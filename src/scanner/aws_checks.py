"""Custom boto3-based security checks (fallback when Prowler/ScoutSuite absent)."""

SEVERITY_MAP = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium',
    'low': 'low', 'informational': 'informational',
}


def _finding(engine, control_id, severity, category, title, description, recommendation, resource='account'):
    return {
        'engine': engine,
        'control_id': control_id,
        'severity': severity,
        'category': category,
        'title': title,
        'description': description,
        'recommendation': recommendation,
        'resource': resource,
    }


def _client(session, service, region=None):
    try:
        return session.client(service, region_name=region) if region else session.client(service)
    except Exception:
        return None


def _session(region=None):
    import boto3
    if region:
        return boto3.Session(region_name=region)
    return boto3.Session()


def run_boto3_checks(region=None):
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

    try:
        session = _session(region)
        creds = session.get_credentials()
        if creds is None:
            raise NoCredentialsError()
        frozen = creds.get_frozen_credentials()
        if not frozen.access_key:
            raise NoCredentialsError()
    except (NoCredentialsError, PartialCredentialsError):
        raise
    except Exception as exc:
        raise NoCredentialsError(str(exc))

    findings = []
    engine = 'boto3'
    r = region or session.region_name

    iam = _client(session, 'iam')
    if iam:
        try:
            summary = iam.get_account_summary()
            if summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0) == 0:
                findings.append(_finding(
                    engine, 'iam-root-mfa', 'critical', 'Identity & Access Management',
                    'Root Account MFA Not Enabled',
                    'The AWS root account does not have MFA enabled.',
                    'Enable hardware or virtual MFA on the root account immediately.',
                    'aws::root'))
            if summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0) > 0:
                findings.append(_finding(
                    engine, 'iam-root-access-key', 'critical', 'Identity & Access Management',
                    'Root Account Has Active Access Keys',
                    'The root account has access keys present.',
                    'Delete root account access keys; use IAM roles for privileged operations.',
                    'aws::root'))
        except ClientError:
            pass
        try:
            policy = iam.get_account_password_policy()
            pw = policy.get('PasswordPolicy', {})
            if not pw.get('MinimumPasswordLength', 0) >= 12 or not pw.get('RequireUppercaseCharacters', False):
                findings.append(_finding(
                    engine, 'iam-password-policy', 'medium', 'Identity & Access Management',
                    'Password Policy Not Enforced',
                    'Account password policy does not meet complexity recommendations (min 12 chars, mixed case).',
                    'Enforce a strong account password policy.',
                    'aws::password-policy'))
        except iam.exceptions.NoSuchEntityException:
            findings.append(_finding(
                engine, 'iam-password-policy-missing', 'high', 'Identity & Access Management',
                'Password Policy Not Configured',
                'No account password policy is configured.',
                'Configure a strong account password policy.',
                'aws::password-policy'))
        except ClientError:
            pass
        try:
            users = iam.list_users().get('Users', [])
            for user in users:
                name = user['UserName']
                mfas = iam.list_mfa_devices(UserName=name).get('MFADevices', [])
                if not mfas and user.get('PasswordLastUsed'):
                    findings.append(_finding(
                        engine, 'iam-user-mfa', 'high', 'Identity & Access Management',
                        f'IAM User Without MFA: {name}',
                        f'IAM user {name} has a console password but no MFA device.',
                        'Require MFA for all IAM users with console access.',
                        f'aws::iam-user/{name}'))
                key_meta = iam.list_access_keys(UserName=name).get('AccessKeyMetadata', [])
                from datetime import datetime, timezone
                for key in key_meta:
                    created = key.get('CreateDate')
                    if created:
                        age_days = (datetime.now(timezone.utc) - created).days
                        if age_days > 90:
                            key_id = key.get('AccessKeyId', '?')
                            findings.append(_finding(
                                engine, 'iam-stale-access-key', 'medium', 'Identity & Access Management',
                                f'Stale Access Key on {name}',
                                f'Access key {key_id} is {age_days} days old.',
                                'Rotate access keys at least every 90 days.',
                                f'aws::iam-user/{name}'))
                    if key.get('Status') == 'Active':
                        try:
                            lu = iam.get_access_key_last_used(AccessKeyId=key.get('AccessKeyId'))['AccessKeyLastUsed']
                            if lu.get('LastUsedDate') is None:
                                findings.append(_finding(
                                    engine, 'iam-unused-access-key', 'medium', 'Identity & Access Management',
                                    f'Unused Access Key on {name}',
                                    f'Access key {key.get("AccessKeyId", "?")} has never been used.',
                                    'Delete unused access keys.',
                                    f'aws::iam-user/{name}'))
                        except ClientError:
                            pass
        except ClientError:
            pass

    s3 = _client(session, 's3')
    if s3:
        try:
            buckets = s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bname = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=bname)
                    public = any(
                        g.get('Type') == 'Group' and g.get('URI', '').endswith('AllUsers')
                        for g in acl.get('Grants', [])
                    )
                    if public:
                        findings.append(_finding(
                            engine, 's3-public-acl', 'critical', 'Data Protection',
                            f'Public S3 Bucket: {bname}',
                            f'Bucket {bname} grants access to AllUsers (public).',
                            'Block public access and remove public ACL grants.',
                            f'aws::s3/{bname}'))
                except ClientError:
                    pass
                try:
                    s3.get_bucket_encryption(Bucket=bname)
                except ClientError:
                    findings.append(_finding(
                        engine, 's3-no-encryption', 'high', 'Data Protection',
                        f'Unencrypted S3 Bucket: {bname}',
                        f'Bucket {bname} has no default encryption configuration.',
                        'Enable default SSE-S3 or SSE-KMS encryption on the bucket.',
                        f'aws::s3/{bname}'))
                try:
                    ver = s3.get_bucket_versioning(Bucket=bname)
                    if ver.get('Status') != 'Enabled':
                        findings.append(_finding(
                            engine, 's3-versioning-disabled', 'medium', 'Data Protection',
                            f'S3 Versioning Disabled: {bname}',
                            f'Bucket {bname} does not have versioning enabled.',
                            'Enable versioning on the bucket.',
                            f'aws::s3/{bname}'))
                except ClientError:
                    pass
                try:
                    logging_cfg = s3.get_bucket_logging(Bucket=bname)
                    if not logging_cfg.get('LoggingEnabled'):
                        findings.append(_finding(
                            engine, 's3-access-logging-disabled', 'medium', 'Logging & Monitoring',
                            f'S3 Access Logging Disabled: {bname}',
                            f'Bucket {bname} does not have server access logging enabled.',
                            'Enable S3 server access logging on the bucket.',
                            f'aws::s3/{bname}'))
                except ClientError:
                    pass
                try:
                    pab = s3.get_public_access_block(Bucket=bname)
                    cfg = pab.get('PublicAccessBlockConfiguration', {})
                    if not all(cfg.get(k) for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')):
                        findings.append(_finding(
                            engine, 's3-public-access-block', 'high', 'Data Protection',
                            f'S3 Public Access Block Incomplete: {bname}',
                            f'Bucket {bname} does not fully block public access.',
                            'Enable all four S3 Block Public Access settings.',
                            f'aws::s3/{bname}'))
                except ClientError:
                    findings.append(_finding(
                        engine, 's3-no-public-access-block', 'medium', 'Data Protection',
                        f'S3 Public Access Block Not Configured: {bname}',
                        f'Bucket {bname} has no public access block configuration.',
                        'Configure S3 Block Public Access on the bucket.',
                        f'aws::s3/{bname}'))
        except ClientError:
            pass

    ec2 = _client(session, 'ec2', r)
    if ec2:
        try:
            sgs = ec2.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                for perm in sg.get('IpPermissions', []):
                    ranges = [x.get('CidrIp') for x in perm.get('IpRanges', [])]
                    if '0.0.0.0/0' in ranges:
                        port = perm.get('FromPort')
                        if port in (22, 3389) or (port is None and perm.get('IpProtocol') == '-1'):
                            sg_id = sg.get('GroupId', '?')
                            sg_name = sg.get('GroupName', sg_id)
                            port_txt = str(port) if port is not None else 'all'
                            findings.append(_finding(
                                engine, 'sg-open-admin', 'high', 'Network Security',
                                f'Security Group Open to 0.0.0.0/0: {sg_id}',
                                f'Security group {sg_name} allows inbound 0.0.0.0/0 on port {port_txt}.',
                                'Restrict security group rules to known IP ranges.',
                                f'aws::sg/{sg_id}'))
                            break
        except ClientError:
            pass
        try:
            vols = ec2.describe_volumes().get('Volumes', [])
            for vol in vols:
                if not vol.get('Encrypted', False):
                    vol_id = vol.get('VolumeId', '?')
                    findings.append(_finding(
                        engine, 'ebs-unencrypted', 'high', 'Data Protection',
                        f'Unencrypted EBS Volume: {vol_id}',
                        f'EBS volume {vol_id} is not encrypted.',
                        'Enable encryption at rest for all EBS volumes.',
                        f'aws::ebs/{vol_id}'))
        except ClientError:
            pass
        try:
            for res in ec2.describe_instances().get('Reservations', []):
                for inst in res.get('Instances', []):
                    md = inst.get('MetadataOptions', {})
                    if md.get('HttpTokens') != 'required':
                        iid = inst.get('InstanceId', '?')
                        findings.append(_finding(
                            engine, 'ec2-imdsv2-not-required', 'medium', 'Compute Security',
                            f'IMDSv2 Not Required: {iid}',
                            f'EC2 instance {iid} does not require IMDSv2.',
                            'Set HttpTokens to required for IMDSv2.',
                            f'aws::ec2/{iid}'))
        except ClientError:
            pass
        try:
            for snap in ec2.describe_snapshots(OwnerIds=['self']).get('Snapshots', []):
                if not snap.get('Encrypted', False):
                    sid = snap.get('SnapshotId', '?')
                    findings.append(_finding(
                        engine, 'ebs-snapshot-unencrypted', 'medium', 'Data Protection',
                        f'Unencrypted EBS Snapshot: {sid}',
                        f'EBS snapshot {sid} is not encrypted.',
                        'Encrypt EBS snapshots.',
                        f'aws::ebs-snapshot/{sid}'))
        except ClientError:
            pass
        try:
            vpcs = ec2.describe_vpcs().get('Vpcs', [])
            flow_logs = ec2.describe_flow_logs().get('FlowLogs', [])
            vpc_ids_with_logs = {fl.get('ResourceId') for fl in flow_logs}
            for vpc in vpcs:
                vid = vpc.get('VpcId')
                if vid not in vpc_ids_with_logs:
                    findings.append(_finding(
                        engine, 'vpc-flow-logs-disabled', 'medium', 'Logging & Monitoring',
                        f'VPC Flow Logs Disabled: {vid}',
                        f'VPC {vid} has no flow logs enabled.',
                        'Enable VPC flow logs for network monitoring.',
                        f'aws::vpc/{vid}'))
        except ClientError:
            pass

    ct = _client(session, 'cloudtrail', r)
    if ct:
        try:
            trails = ct.describe_trails().get('trailList', [])
            if not trails:
                findings.append(_finding(
                    engine, 'cloudtrail-missing', 'critical', 'Logging & Monitoring',
                    'CloudTrail Not Enabled',
                    'No CloudTrail trails exist in this region.',
                    'Enable multi-region CloudTrail with log file validation.',
                    'aws::cloudtrail'))
            else:
                multi = any(t.get('IsMultiRegionTrail') for t in trails)
                if not multi:
                    findings.append(_finding(
                        engine, 'cloudtrail-not-multi-region', 'medium', 'Logging & Monitoring',
                        'CloudTrail Not Multi-Region',
                        'CloudTrail exists but is not enabled for all regions.',
                        'Convert the trail to a multi-region trail.',
                        'aws::cloudtrail'))
                for t in trails:
                    if not t.get('LogFileValidationEnabled'):
                        findings.append(_finding(
                            engine, 'cloudtrail-log-validation', 'medium', 'Logging & Monitoring',
                            'CloudTrail Log Validation Disabled',
                            f'Trail {t.get("Name")} does not have log file validation.',
                            'Enable log file validation on the trail.',
                            f'aws::cloudtrail/{t.get("Name")}'))
        except ClientError:
            pass

    gd = _client(session, 'guardduty', r)
    if gd:
        try:
            detectors = gd.list_detectors().get('DetectorIds', [])
            if not detectors:
                findings.append(_finding(
                    engine, 'guardduty-disabled', 'high', 'Logging & Monitoring',
                    'GuardDuty Not Enabled',
                    'Amazon GuardDuty has no active detector.',
                    'Enable GuardDuty for continuous threat monitoring.',
                    'aws::guardduty'))
        except ClientError:
            pass

    rds = _client(session, 'rds', r)
    if rds:
        try:
            for dbi in rds.describe_db_instances().get('DBInstances', []):
                did = dbi.get('DBInstanceIdentifier', '?')
                if not dbi.get('StorageEncrypted', False):
                    findings.append(_finding(
                        engine, 'rds-unencrypted', 'high', 'Data Protection',
                        f'Unencrypted RDS Instance: {did}',
                        f'RDS instance {did} is not encrypted at rest.',
                        'Enable storage encryption for RDS.',
                        f'aws::rds/{did}'))
                if dbi.get('PubliclyAccessible'):
                    findings.append(_finding(
                        engine, 'rds-public', 'high', 'Network Security',
                        f'Publicly Accessible RDS: {did}',
                        f'RDS instance {did} is publicly accessible.',
                        'Disable public accessibility for RDS.',
                        f'aws::rds/{did}'))
        except ClientError:
            pass

    kms = _client(session, 'kms', r)
    if kms:
        try:
            for k in kms.list_keys().get('Keys', []):
                kid = k.get('KeyId', '?')
                try:
                    rot = kms.get_key_rotation_status(KeyId=kid)
                    if not rot.get('KeyRotationEnabled', False):
                        findings.append(_finding(
                            engine, 'kms-rotation-disabled', 'medium', 'Data Protection',
                            f'KMS Key Rotation Disabled: {kid}',
                            f'KMS key {kid} does not have automatic rotation enabled.',
                            'Enable automatic key rotation.',
                            f'aws::kms/{kid}'))
                except ClientError:
                    pass
        except ClientError:
            pass

    logs = _client(session, 'logs', r)
    if logs:
        try:
            for g in logs.describe_log_groups().get('logGroups', []):
                if g.get('retentionInDays') is None:
                    gname = g.get('logGroupName', '?')
                    findings.append(_finding(
                        engine, 'cloudwatch-no-retention', 'low', 'Logging & Monitoring',
                        f'CloudWatch Log Group No Retention: {gname}',
                        f'Log group {gname} has no retention policy.',
                        'Set a retention policy on the log group.',
                        f'aws::logs/{gname}'))
        except ClientError:
            pass

    sm = _client(session, 'secretsmanager', r)
    if sm:
        try:
            for sec in sm.list_secrets().get('SecretList', []):
                if not sec.get('RotationEnabled', False):
                    sname = sec.get('Name', '?')
                    findings.append(_finding(
                        engine, 'secretsmanager-rotation-disabled', 'medium', 'Data Protection',
                        f'Secrets Manager Rotation Disabled: {sname}',
                        f'Secret {sname} does not have rotation enabled.',
                        'Enable automatic rotation for the secret.',
                        f'aws::secretsmanager/{sname}'))
        except ClientError:
            pass

    lam = _client(session, 'lambda', r)
    if lam:
        try:
            for fn in lam.list_functions().get('Functions', []):
                fname = fn.get('FunctionName', '?')
                try:
                    policy = lam.get_policy(FunctionName=fname)
                    import json as _json
                    doc = _json.loads(policy.get('Policy', '{}'))
                    for stmt in doc.get('Statement', []):
                        if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                            findings.append(_finding(
                                engine, 'lambda-public-policy', 'high', 'Compute Security',
                                f'Lambda Function Publicly Invocable: {fname}',
                                f'Lambda function {fname} has a public resource policy.',
                                'Restrict the function resource policy.',
                                f'aws::lambda/{fname}'))
                except lam.exceptions.ResourceNotFoundException:
                    pass
                except ClientError:
                    pass
        except ClientError:
            pass

    if not findings:
        findings.append(_finding(
            engine, 'boto3-no-issues', 'informational', 'General',
            'No Issues Detected by Fallback Checks',
            'Custom boto3 checks completed without detecting issues in the covered services.',
            'Run Prowler or ScoutSuite for broader coverage.',
            'aws::account'))
    return findings


def identity(region=None):
    """Best-effort STS GetCallerIdentity for scan attribution. Never raises, never blocks a scan."""
    try:
        session = _session(region)
        ident = session.client('sts').get_caller_identity()
        return ident.get('Account') or '', ident.get('Arn') or ''
    except Exception:
        return '', ''


def has_credentials(region=None):
    try:
        session = _session(region)
        creds = session.get_credentials()
        if creds is None:
            return False
        return bool(creds.get_frozen_credentials().access_key)
    except Exception:
        return False


def connection_status(region=None):
    """Detect local AWS credentials/region without contacting AWS."""
    status = {
        'credentials_found': False,
        'region': None,
        'error': None,
    }
    try:
        session = _session(region)
        creds = session.get_credentials()
        if creds is not None:
            frozen = creds.get_frozen_credentials()
            status['credentials_found'] = bool(frozen and frozen.access_key)
        status['region'] = session.region_name
    except Exception as exc:
        status['error'] = str(exc)[:300]
    return status


def test_connection(region=None):
    """STS GetCallerIdentity — identity only, not a scan. Never stores keys."""
    if not has_credentials(region):
        return {
            'ok': False,
            'error': 'No AWS credentials found. Run `aws configure` or set '
                     'AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, then retry.',
        }
    try:
        session = _session(region)
        ident = session.client('sts').get_caller_identity()
        return {
            'ok': True,
            'account': ident.get('Account') or '',
            'arn': ident.get('Arn') or '',
            'user_id': ident.get('UserId') or '',
            'region': session.region_name,
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc)[:500]}


def list_regions():
    """Return list of enabled AWS regions (best-effort)."""
    try:
        session = _session()
        ec2 = session.client('ec2', region_name=session.region_name or 'us-east-1')
        return [r['RegionName'] for r in ec2.describe_regions().get('Regions', [])]
    except Exception:
        return [session.region_name or 'us-east-1']