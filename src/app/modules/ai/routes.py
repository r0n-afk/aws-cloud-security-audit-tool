from flask import jsonify, request

from app.modules.ai import ai_bp
from app.modules.findings.services import get_finding, get_findings
from app.models.assessment import Assessment


def _ai_unavailable(message, status=400):
    return jsonify({'success': False, 'error': message}), status


@ai_bp.route('/remediation/<int:finding_id>', methods=['POST'])
def remediation(finding_id):
    try:
        from ai.client import AIError, ai_enabled, remediation_advice
        from ai.rate_limit import RateLimitError
    except Exception as exc:
        return _ai_unavailable(f'AI module unavailable: {exc}', 503)
    if not ai_enabled():
        return _ai_unavailable('AI integration is disabled in Settings.', 403)
    finding = get_finding(finding_id)
    try:
        advice = remediation_advice(finding)
    except RateLimitError as exc:
        return _ai_unavailable(str(exc), 429)
    except AIError as exc:
        return _ai_unavailable(str(exc), 502)
    return jsonify({'success': True, 'advice': advice})


@ai_bp.route('/prioritize/<int:assessment_id>', methods=['POST'])
def prioritize(assessment_id):
    try:
        from ai.client import AIError, ai_enabled, prioritize_findings
        from ai.rate_limit import RateLimitError
        from analyzer import prioritize
    except Exception as exc:
        return _ai_unavailable(f'AI module unavailable: {exc}', 503)
    if not ai_enabled():
        return _ai_unavailable('AI integration is disabled in Settings.', 403)
    assessment = Assessment.query.get_or_404(assessment_id)
    findings = assessment.findings
    if not findings:
        return _ai_unavailable('No findings to prioritize.', 404)
    severity_rank = prioritize(
        [{'severity': f.severity, 'title': f.title, 'id': f.id} for f in findings],
        top_n=15,
    )
    try:
        order = prioritize_findings(findings)
    except RateLimitError as exc:
        return _ai_unavailable(str(exc), 429)
    except AIError as exc:
        return _ai_unavailable(str(exc), 502)
    return jsonify({
        'success': True,
        'ai_order': order,
        'severity_order': [f['title'] for f in severity_rank],
    })


@ai_bp.route('/qna', methods=['POST'])
def qna():
    try:
        from ai.client import AIError, ai_enabled, answer_question
        from ai.rate_limit import RateLimitError
    except Exception as exc:
        return _ai_unavailable(f'AI module unavailable: {exc}', 503)
    if not ai_enabled():
        return _ai_unavailable('AI integration is disabled in Settings.', 403)
    data = request.get_json(silent=True) or {}
    question = (data.get('question') or '').strip()
    if not question or len(question) > 500:
        return _ai_unavailable('Question required (max 500 chars).')
    pagination = get_findings(page=1, per_page=50)
    lines = [
        f'[{f.severity}] {f.title} — {f.category} — {f.description[:120]}'
        for f in pagination.items
    ]
    context = '\n'.join(lines) or 'No findings stored.'
    try:
        answer = answer_question(question, context)
    except RateLimitError as exc:
        return _ai_unavailable(str(exc), 429)
    except AIError as exc:
        return _ai_unavailable(str(exc), 502)
    return jsonify({'success': True, 'answer': answer})
