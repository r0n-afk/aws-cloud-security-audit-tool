"""OpenAI-compatible AI client (any endpoint). OFF by default. HTTPS-only (local Ollama exception)."""
import json

import requests

from ai import rate_limit as rl

AI_TIMEOUT = 30


class AIError(Exception):
    pass


def ai_enabled():
    from app.modules.settings.services import get_setting
    return str(get_setting('ai_enabled', 'false')).lower() == 'true'


def _settings():
    from app.modules.settings.services import get_setting
    return {
        'base_url': (get_setting('ai_base_url', 'https://api.openai.com/v1') or '').rstrip('/'),
        'api_key': get_setting('ai_api_key', '') or '',
        'model': get_setting('ai_model', 'gpt-4o-mini') or 'gpt-4o-mini',
    }


def _validate_base_url(base_url):
    if not base_url.startswith('https://'):
        if base_url.startswith('http://127.0.0.1') or base_url.startswith('http://localhost'):
            return
        raise AIError('AI base URL must be HTTPS (local Ollama http://127.0.0.1 is allowed).')


def ai_chat(system_prompt, user_prompt, max_tokens=700):
    if not ai_enabled():
        raise AIError('AI integration is disabled in Settings.')
    cfg = _settings()
    _validate_base_url(cfg['base_url'])
    if not cfg['api_key'] and 'localhost' not in cfg['base_url'] and '127.0.0.1' not in cfg['base_url']:
        raise AIError('AI API key is not configured.')

    rl.check_rate_limit()
    rl.begin_request()
    try:
        payload = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt},
            ],
            'max_tokens': max_tokens,
            'temperature': 0.2,
        }
        headers = {'Content-Type': 'application/json'}
        if cfg['api_key']:
            headers['Authorization'] = f"Bearer {cfg['api_key']}"
        url = f"{cfg['base_url']}/chat/completions"
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=AI_TIMEOUT)
        except requests.RequestException as exc:
            raise AIError(f'AI request failed: {exc.__class__.__name__}') from exc
        if resp.status_code == 429:
            raise rl.RateLimitError('Upstream AI provider rate limit hit.', 10)
        if resp.status_code >= 400:
            raise AIError(f'AI provider returned HTTP {resp.status_code}.')
        try:
            data = resp.json()
            content = data['choices'][0]['message']['content']
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIError('Unexpected AI provider response.') from exc
        rl.register_call()
        return content
    finally:
        rl.end_request()


def summarize_assessment(assessment, findings_sample):
    system = (
        'You are a security report editor. Write a concise executive summary '
        '(4-6 sentences, plain English, no marketing filler, no emoji) for an AWS audit. '
        'Facts only from the data provided.'
    )
    lines = [
        f"Assessment: {assessment.name}",
        f"Score: {assessment.security_score}/100",
        f"Total findings: {assessment.total_findings} "
        f"(C:{assessment.critical_count} H:{assessment.high_count} "
        f"M:{assessment.medium_count} L:{assessment.low_count} I:{assessment.informational_count})",
        'Top findings:',
    ]
    for f in findings_sample[:10]:
        lines.append(f"- [{f.severity}] {f.title} ({f.category})")
    return ai_chat(system, '\n'.join(lines), max_tokens=400)


def remediation_advice(finding):
    system = (
        'You are a cloud security engineer. Give a step-by-step remediation plan '
        '(numbered steps, specific to AWS, max 6 steps) for the finding. Plain text only, no emoji.'
    )
    user = (
        f"Title: {finding.title}\nSeverity: {finding.severity}\n"
        f"Category: {finding.category}\nDescription: {finding.description}\n"
        f"Existing recommendation: {finding.recommendation or 'none'}"
    )
    return ai_chat(system, user, max_tokens=500)


def prioritize_findings(findings):
    system = (
        'You are a security lead. Re-rank these findings into a fix order. '
        'Return ONLY a JSON array of finding titles in priority order, max 15 items.'
    )
    lines = [f"[{f.severity}] {f.title} — {f.category}" for f in findings[:40]]
    return ai_chat(system, '\n'.join(lines), max_tokens=600)


def answer_question(question, findings_context):
    system = (
        'You are an auditor assistant answering questions about a security assessment. '
        'Answer only from the provided findings context. If not present, say the data does not include it. '
        'Plain text, no emoji, max 150 words.'
    )
    user = f'Findings context:\n{findings_context}\n\nQuestion: {question}'
    return ai_chat(system, user, max_tokens=400)
