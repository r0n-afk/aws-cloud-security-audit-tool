import os
import re
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, 'src'))


def _rm(path, retries=5):
    if not os.path.exists(path):
        return
    for i in range(retries):
        try:
            os.remove(path)
            return
        except PermissionError:
            time.sleep(0.4 * (i + 1))
    print('warn: could not remove', path, '(will reset via schema)')


# fresh runtime state
_rm(os.path.join(BASE, 'instance', 'csa_tool.db'))
_rm(os.path.join(BASE, 'instance', 'secret_key'))
reports_dir = os.path.join(BASE, 'instance', 'reports')
if os.path.isdir(reports_dir):
    for fn in os.listdir(reports_dir):
        _rm(os.path.join(reports_dir, fn))

from app import create_app

app = create_app()
c = app.test_client()


def csrf(html):
    m = re.search(rb'name="csrf_token" value="([^"]+)"', html) or re.search(
        rb'csrf-token" content="([^"]+)"', html
    )
    return m.group(1).decode() if m else ''


r = c.get('/auth/setup')
assert r.status_code == 200, r.status_code
token = csrf(r.data)
assert token, 'no csrf on setup'
r = c.post(
    '/auth/setup',
    data={'username': 'tester', 'password': 'secret123', 'confirm': 'secret123', 'csrf_token': token},
)
print('setup POST', r.status_code, r.headers.get('Location'))

r = c.get('/auth/login')
token = csrf(r.data)
r = c.post(
    '/auth/login',
    data={'username': 'tester', 'password': 'secret123', 'csrf_token': token},
)
print('login POST', r.status_code, r.headers.get('Location'))
assert r.headers.get('Location') in ('/', None) or r.status_code == 200

r = c.get('/')
print('dashboard', r.status_code)
assert r.status_code == 200

from unittest import mock


def _fake_run_scan(timeout=1800):
    raw = [
        {'engine': 'prowler', 'control_id': 'iam-root-mfa', 'severity': 'critical',
         'category': 'Identity and Access Management', 'title': 'Root account MFA disabled',
         'description': 'Root account has no MFA.', 'recommendation': 'Enable MFA.',
         'resource': 'arn:aws:iam::123456789012:root'},
        {'engine': 'scoutsuite', 'control_id': 's3-bucket-logging', 'severity': 'medium',
         'category': 'Storage', 'title': 'S3 bucket logging disabled',
         'description': 'Logging not enabled.', 'recommendation': 'Enable logging.',
         'resource': 'arn:aws:s3:::bucket'},
    ]
    return {
        'findings': raw, 'engines': ['prowler', 'scoutsuite'], 'raw_count': len(raw),
        'mode': 'aws', 'aws_account_id': '123456789012',
        'aws_arn': 'arn:aws:iam::123456789012:root', 'errors': [],
    }


r = c.get('/assessment/new')
token = csrf(r.data)
with mock.patch('scanner.orchestrator.run_scan', _fake_run_scan):
    r = c.post(
        '/assessment/create',
        data={'name': 'Smoke Test', 'description': 'e2e', 'csrf_token': token},
    )
print('create scan', r.status_code, r.headers.get('Location'))

with app.app_context():
    from app.models.assessment import Assessment
    from app.models.finding import Finding

    a = Assessment.query.order_by(Assessment.id.desc()).first()
    print(
        'assessment:', a.id, a.status, 'score', a.security_score,
        'total', a.total_findings, 'raw', a.raw_count,
        'deduped', a.deduped_count, 'engines', a.engines_used,
    )
    assert a.status == 'completed', a.status
    assert a.total_findings > 0
    aid = a.id

    from app.modules.reports.services import generate_report

    rep, note = generate_report(aid, 'html')
    print('report html:', rep.id if rep else None, rep.report_type if rep else None, note)
    assert rep and rep.report_type == 'html'
    rep2, note2 = generate_report(aid, 'json')
    print('report json:', rep2.id if rep2 else None, note2)
    assert rep2 and rep2.report_type == 'json'
    fid = Finding.query.first().id

for path in ['/findings/', '/assessment/%d' % aid, '/reports/', '/history/', '/remediation/', '/comparison/', '/settings/']:
    r = c.get(path)
    print(path, r.status_code)
    assert r.status_code == 200, (path, r.status_code)

r = c.get('/findings/%d' % fid)
print('finding detail', r.status_code)
assert r.status_code == 200

r = c.post(
    '/ai/remediation/%d' % fid,
    headers={'X-CSRFToken': csrf(c.get('/findings/%d' % fid).data)},
)
print('ai disabled', r.status_code, r.get_json())
assert r.status_code == 403, r.status_code

# wrong password fails
r = c.get('/auth/logout')  # GET logout not allowed? check
print('logout GET', r.status_code)

from scanner.aws_checks import has_credentials
from scanner.orchestrator import CredentialsError, run_scan

print('has_credentials probe:', has_credentials())
if not has_credentials():
    try:
        run_scan()
        raise SystemExit('ERROR: expected CredentialsError')
    except CredentialsError as e:
        print('CredentialsError OK:', str(e)[:70])

# analyzer dedupe proof
from analyzer import analyze

raw = [
    {'engine': 'prowler', 'control_id': 'check1', 'severity': 'low', 'category': 'Network Security',
     'title': 'Open Port', 'description': 'a', 'recommendation': 'r', 'resource': 'arn:x'},
    {'engine': 'scoutsuite', 'control_id': 'check1', 'severity': 'high', 'category': 'Network Security',
     'title': 'Open Port', 'description': 'longer description here', 'recommendation': 'r2', 'resource': 'arn:x'},
]
result = analyze(raw)
assert result['deduped_count'] == 1, result
assert result['findings'][0]['severity'] == 'high'
assert set(result['findings'][0]['engines']) == {'prowler', 'scoutsuite'}
assert result['redundancy_removed'] == 1
print('analyzer dedupe OK', result['counts'], 'score', result['score'])

print('SMOKE DONE — ALL ASSERTIONS PASSED')
