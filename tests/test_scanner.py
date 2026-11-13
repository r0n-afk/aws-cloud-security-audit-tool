import json
import os
from unittest.mock import MagicMock

from scanner.orchestrator import CredentialsError, run_scan
from scanner.prowler_engine import parse_output as parse_prowler
from scanner.scoutsuite_engine import parse_output as parse_scout


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


def test_boto3_ebs_default_encryption_finding(monkeypatch):
    from scanner import aws_checks

    class _Creds:
        access_key = 'AKIAEXAMPLE'

        def get_frozen_credentials(self):
            return self

    class _Session:
        region_name = 'us-east-1'

        def get_credentials(self):
            return _Creds()

    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {'SecurityGroups': []}
    ec2.describe_volumes.return_value = {'Volumes': []}
    ec2.get_ebs_encryption_by_default.return_value = {'EbsEncryptionByDefault': False}
    ec2.describe_instances.return_value = {'Reservations': []}
    ec2.describe_snapshots.return_value = {'Snapshots': []}
    ec2.describe_vpcs.return_value = {'Vpcs': []}
    ec2.describe_flow_logs.return_value = {'FlowLogs': []}

    monkeypatch.setattr(aws_checks, '_session', lambda region=None: _Session())
    monkeypatch.setattr(
        aws_checks, '_client',
        lambda session, service, region=None: ec2 if service == 'ec2' else None)

    findings = aws_checks.run_boto3_checks()
    ids = {f['control_id'] for f in findings}
    assert 'ebs-default-encryption-disabled' in ids


def test_boto3_public_policy_finding(monkeypatch):
    from scanner import aws_checks

    class _Creds:
        access_key = 'AKIAEXAMPLE'

        def get_frozen_credentials(self):
            return self

    class _Session:
        region_name = 'us-east-1'

        def get_credentials(self):
            return _Creds()

    s3 = MagicMock()
    s3.list_buckets.return_value = {'Buckets': [{'Name': 'public-bucket'}]}
    s3.get_bucket_acl.return_value = {'Grants': []}
    s3.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {}}
    s3.get_bucket_policy_status.return_value = {'PolicyStatus': {'IsPublic': True}}
    s3.get_bucket_versioning.return_value = {'Status': 'Enabled'}
    s3.get_bucket_logging.return_value = {'LoggingEnabled': True}
    s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
        }
    }

    monkeypatch.setattr(aws_checks, '_session', lambda region=None: _Session())
    monkeypatch.setattr(
        aws_checks, '_client',
        lambda session, service, region=None: s3 if service == 's3' else None)

    findings = aws_checks.run_boto3_checks()
    ids = {f['control_id'] for f in findings}
    assert 's3-public-policy' in ids
