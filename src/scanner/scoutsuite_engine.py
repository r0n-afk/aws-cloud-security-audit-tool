"""ScoutSuite engine — runs the ScoutSuite CLI and normalizes its rules results."""
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile


def is_available():
    return shutil.which('scoutsuite') is not None or shutil.which('scout') is not None


def _bin():
    return shutil.which('scoutsuite') or shutil.which('scout')


def _normalize_severity(level):
    if level is None:
        return 'medium'
    v = str(level).strip().lower()
    aliases = {
        'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
        'informational': 'informational', 'info': 'informational',
        'danger': 'critical', 'warning': 'medium', '2': 'high', '1': 'medium', '0': 'low',
    }
    return aliases.get(v, 'medium')


_CATEGORY_HINTS = {
    'iam': 'Identity & Access Management', 'identity': 'Identity & Access Management',
    's3': 'Data Protection', 'ec2': 'Network Security', 'vpc': 'Network Security',
    'network': 'Network Security', 'cloudtrail': 'Logging & Monitoring',
    'logging': 'Logging & Monitoring', 'monitoring': 'Logging & Monitoring',
    'kms': 'Data Protection',
}


def _category_for(text):
    t = str(text).lower()
    for key, cat in _CATEGORY_HINTS.items():
        if key in t:
            return cat
    return 'Compliance & Governance'


def _item(engine_rule_id, payload):
    if not isinstance(payload, dict):
        return None
    level = payload.get('level') or payload.get('severity') or payload.get('Level')
    title = payload.get('title') or payload.get('rule') or payload.get('name') or engine_rule_id
    description = payload.get('description') or payload.get('rationale') or payload.get('message') or ''
    remediation = payload.get('remediation') or payload.get('fix') or payload.get('recommendation') or ''
    flagged = payload.get('flagged_items') or payload.get('items') or []
    resources = []
    if isinstance(flagged, list):
        for entry in flagged[:20]:
            if isinstance(entry, dict):
                resources.append(str(entry.get('id') or entry.get('arn') or entry.get('name') or ''))
            else:
                resources.append(str(entry))
    resource = ', '.join(r for r in resources if r)[:300] if resources else f'scoutsuite::{engine_rule_id}'
    return {
        'engine': 'scoutsuite',
        'control_id': str(engine_rule_id),
        'severity': _normalize_severity(level),
        'category': _category_for(f'{engine_rule_id} {title} {description}'),
        'title': str(title),
        'description': str(description or 'Detected by ScoutSuite.'),
        'recommendation': str(remediation or 'Review the ScoutSuite rule documentation.'),
        'resource': resource,
    }


def _extract_from_js(text):
    m = re.search(r'=\s*(\{.*\})\s*;?\s*$', text, re.DOTALL)
    if not m:
        m = re.search(r'(\{.*\})', text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def _walk_rules(obj, out, path=''):
    if isinstance(obj, dict):
        if 'level' in obj and ('description' in obj or 'flagged_items' in obj or 'title' in obj):
            out.append((path or obj.get('rule', 'rule'), obj))
            return
        for k, v in obj.items():
            _walk_rules(v, out, f'{path}/{k}' if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_rules(v, out, f'{path}[{i}]')


def parse_output(root):
    findings = []
    seen = set()
    files = []
    for pattern in ('**/*.json', '**/*.js'):
        files.extend(glob.glob(os.path.join(root, pattern), recursive=True))
    for path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
        except OSError:
            continue
        data = None
        if path.endswith('.json'):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = _extract_from_js(text)
        else:
            data = _extract_from_js(text)
        if data is None:
            continue
        matches = []
        _walk_rules(data, matches)
        for rule_id, payload in matches:
            item = _item(rule_id, payload)
            if not item:
                continue
            key = (item['control_id'], item['resource'])
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings


def run(timeout=1800):
    binary = _bin()
    if not binary:
        raise FileNotFoundError('scoutsuite executable not found on PATH')
    out_dir = tempfile.mkdtemp(prefix='scoutsuite_out_')
    cmd = [binary, 'scan', 'aws', '--report-dir', out_dir]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        shell=False, cwd=out_dir,
    )
    findings = parse_output(out_dir)
    if not findings and proc.returncode not in (0, 1, 2):
        combined = ((proc.stderr or '') + (proc.stdout or '')).lower()
        if 'not found' in combined or 'commandnotfound' in combined.replace(' ', ''):
            raise FileNotFoundError('scoutsuite failed to start')
    return findings
