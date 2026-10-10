"""Prowler engine — runs the Prowler CLI and normalizes JSON output."""
import glob
import json
import os
import shutil
import subprocess
import tempfile


def is_available():
    return shutil.which('prowler') is not None


def _normalize_severity(value):
    if not value:
        return 'medium'
    v = str(value).strip().lower()
    if v in ('critical', 'high', 'medium', 'low', 'informational'):
        return v
    if v in ('flash', 'danger'):
        return 'critical'
    if v in ('warning', 'warn'):
        return 'medium'
    if v in ('notice', 'info'):
        return 'informational'
    return 'medium'


def _from_prowler_record(rec):
    status = str(rec.get('Status') or rec.get('status') or '').upper()
    if status and status not in ('FAIL', 'ERROR', 'WARNING', 'WAIVED', 'FAIL MEDIUM', 'FAIL LOW', 'FAIL HIGH', 'FAIL CRITICAL'):
        if status == 'PASS' or status == 'MANUAL':
            return None
    severity = rec.get('Severity') or rec.get('severity')
    if not severity:
        check_id = str(rec.get('CheckID') or rec.get('check_id') or '')
        for level in ('critical', 'high', 'medium', 'low'):
            if level in check_id.lower():
                severity = level
                break
    title = (rec.get('CheckTitle') or rec.get('check_title') or
             rec.get('Title') or rec.get('CheckID') or rec.get('check_id') or 'Finding')
    risk = rec.get('Risk') or rec.get('risk') or rec.get('Description') or ''
    remediation = rec.get('Remediation') or rec.get('remediation') or {}
    if isinstance(remediation, dict):
        rec_text = remediation.get('Recommendation') or remediation.get('recommendation') or ''
    else:
        rec_text = str(remediation)
    service = rec.get('ServiceName') or rec.get('service_name') or 'AWS'
    category_map = {
        'iam': 'Identity & Access Management', 'identity': 'Identity & Access Management',
        's3': 'Data Protection', 'ec2': 'Network Security', 'ec': 'Network Security',
        'vpc': 'Network Security', 'network': 'Network Security',
        'cloudtrail': 'Logging & Monitoring', 'guardduty': 'Logging & Monitoring',
        'logging': 'Logging & Monitoring', 'monitoring': 'Logging & Monitoring',
        'kms': 'Data Protection', 'encryption': 'Data Protection',
    }
    category = 'Compliance & Governance'
    svc_lower = str(service).lower()
    for key, cat in category_map.items():
        if key in svc_lower:
            category = cat
            break
    return {
        'engine': 'prowler',
        'control_id': str(rec.get('CheckID') or rec.get('check_id') or title),
        'severity': _normalize_severity(severity),
        'category': category,
        'title': str(title),
        'description': str(risk or 'Detected by Prowler.'),
        'recommendation': str(rec_text or 'Review the Prowler check remediation guidance.'),
        'resource': str(rec.get('ResourceArn') or rec.get('resource_arn') or rec.get('ResourceId') or service),
    }


def _iter_json_files(root):
    pattern = os.path.join(root, '**', '*.json')
    for path in glob.glob(pattern, recursive=True):
        yield path


def parse_output(raw_dir):
    findings = []
    seen = set()
    for path in _iter_json_files(raw_dir):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
        records = []
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            for key in ('findings', 'Checks', 'checks', 'Results', 'results'):
                if isinstance(data.get(key), list):
                    records = data[key]
                    break
            if not records and any(k in data for k in ('CheckID', 'check_id', 'Status')):
                records = [data]
        for rec in records:
            if not isinstance(rec, dict):
                continue
            item = _from_prowler_record(rec)
            if not item:
                continue
            key = (item['control_id'], item['resource'])
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings


def run(timeout=1800):
    if not is_available():
        raise FileNotFoundError('prowler executable not found on PATH')
    out_dir = tempfile.mkdtemp(prefix='prowler_out_')
    cmd = ['prowler', 'aws', '-M', 'json', '-o', out_dir]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        shell=False, env=None, cwd=out_dir,
    )
    if proc.returncode not in (0, 1, 2, 3, 4, 5):
        combined = (proc.stderr or '') + (proc.stdout or '')
        if 'not found' in combined.lower():
            raise FileNotFoundError('prowler failed to start')
    findings = parse_output(out_dir)
    return findings
