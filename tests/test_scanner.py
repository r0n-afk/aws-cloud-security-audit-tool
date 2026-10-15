import json
import os

from scanner.prowler_engine import parse_output as parse_prowler
from scanner.scoutsuite_engine import parse_output as parse_scout
from scanner.orchestrator import CredentialsError, run_scan


def test_prowler_fixture_parse(tmp_path):
    payload = [
        {
            'CheckID': 'iam_root_mfa_enabled',
            'CheckTitle': 'Root MFA',
            'Status': 'FAIL',
            'Severity': 'critical',
            'ServiceName': 'iam',
            'ResourceArn': 'arn:aws:iam::1:root',
            'Risk': 'Root without MFA',
            'Remediation': {'Recommendation': 'Enable MFA'},
        },
        {
            'CheckID': 's3_bucket_logging',
            'CheckTitle': 'Bucket logging',
            'Status': 'PASS',
            'Severity': 'low',
            'ServiceName': 's3',
            'ResourceArn': 'arn:aws:s3:::b',
        },
    ]
    path = tmp_path / 'prowler.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    findings = parse_prowler(str(tmp_path))
    assert len(findings) == 1  # PASS filtered out
    assert findings[0]['engine'] == 'prowler'
    assert findings[0]['severity'] == 'critical'
    assert findings[0]['resource'] == 'arn:aws:iam::1:root'


def test_scoutsuite_fixture_parse(tmp_path):
    payload = {
        'rules': {
            'iam.no-root-mfa': {
                'level': 'danger',
                'title': 'Root MFA disabled',
                'description': 'Root has no MFA',
                'remediation': 'Enable MFA',
                'flagged_items': ['123456789012'],
            }
        }
    }
    path = tmp_path / 'results.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    findings = parse_scout(str(tmp_path))
    assert len(findings) == 1
    assert findings[0]['engine'] == 'scoutsuite'
    assert findings[0]['severity'] == 'critical'


def test_aws_mode_without_credentials_raises(monkeypatch):
    import scanner.aws_checks as aws

    monkeypatch.setattr(aws, 'has_credentials', lambda region=None: False)
    monkeypatch.setattr('scanner.orchestrator.aws_checks.has_credentials', lambda region=None: False)
    try:
        run_scan()
        raise AssertionError('expected CredentialsError')
    except CredentialsError as exc:
        assert 'credentials' in str(exc).lower()


def test_identity_returns_empty_tuple_on_error(monkeypatch):
    import boto3

    from scanner import aws_checks

    def _boom(*args, **kwargs):
        raise RuntimeError('sts down')

    monkeypatch.setattr(boto3.Session, 'client', _boom)
    assert aws_checks.identity() == ('', '')
