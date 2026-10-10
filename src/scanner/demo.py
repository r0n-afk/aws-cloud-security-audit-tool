import random

SECURITY_CHECKS = [
    {
        'category': 'Identity & Access Management',
        'checks': [
            {'title': 'Root Account MFA Not Enabled', 'severity': 'critical', 'description': 'Root account does not have multi-factor authentication enabled, allowing potential unauthorized access to the entire cloud environment.', 'recommendation': 'Enable MFA on root account immediately.'},
            {'title': 'Overly Permissive IAM Policies', 'severity': 'high', 'description': 'IAM policies with wildcard permissions were detected, granting excessive access to resources.', 'recommendation': 'Apply principle of least privilege to all IAM policies.'},
            {'title': 'Inactive User Accounts', 'severity': 'medium', 'description': 'User accounts that have not been active for over 90 days were found.', 'recommendation': 'Review and deactivate or remove inactive accounts.'},
            {'title': 'Password Policy Not Enforced', 'severity': 'medium', 'description': 'Account password policy does not meet recommended complexity requirements.', 'recommendation': 'Enforce strong password policies.'},
            {'title': 'Access Keys Not Rotated', 'severity': 'low', 'description': 'Access keys older than 90 days were detected.', 'recommendation': 'Implement regular access key rotation.'},
        ]
    },
    {
        'category': 'Network Security',
        'checks': [
            {'title': 'Public S3 Bucket Detected', 'severity': 'critical', 'description': 'An S3 bucket with public read access was detected, potentially exposing sensitive data.', 'recommendation': 'Restrict S3 bucket access and enable encryption.'},
            {'title': 'Security Group Open to 0.0.0.0/0', 'severity': 'high', 'description': 'A security group allows inbound traffic from all IP addresses on sensitive ports.', 'recommendation': 'Restrict security group rules to specific IP ranges.'},
            {'title': 'Unencrypted Data Transfer', 'severity': 'medium', 'description': 'Data transfers detected without TLS/SSL encryption.', 'recommendation': 'Enforce HTTPS and enable TLS for all data transfers.'},
            {'title': 'DNS Logging Not Enabled', 'severity': 'low', 'description': 'DNS query logging is not enabled for the VPC.', 'recommendation': 'Enable DNS logging for security monitoring.'},
            {'title': 'Network ACLs Review Needed', 'severity': 'informational', 'description': 'Network ACL configurations should be reviewed for compliance.', 'recommendation': 'Review and update network ACL rules.'},
        ]
    },
    {
        'category': 'Data Protection',
        'checks': [
            {'title': 'Unencrypted EBS Volume', 'severity': 'high', 'description': 'EBS volumes without encryption were detected, risking data exposure.', 'recommendation': 'Enable encryption for all EBS volumes.'},
            {'title': 'S3 Bucket Logging Disabled', 'severity': 'medium', 'description': 'Access logging is not enabled for S3 buckets.', 'recommendation': 'Enable S3 access logging for audit trails.'},
            {'title': 'No Key Rotation Policy', 'severity': 'medium', 'description': 'KMS keys do not have automatic rotation enabled.', 'recommendation': 'Enable automatic key rotation for KMS keys.'},
            {'title': 'Backup Not Configured', 'severity': 'low', 'description': 'Automated backups are not configured for critical resources.', 'recommendation': 'Configure automated backup schedules.'},
            {'title': 'Data Classification Missing', 'severity': 'informational', 'description': 'Data classification tags are not applied to stored objects.', 'recommendation': 'Implement data classification policies.'},
        ]
    },
    {
        'category': 'Logging & Monitoring',
        'checks': [
            {'title': 'CloudTrail Not Enabled', 'severity': 'critical', 'description': 'AWS CloudTrail is not enabled, preventing audit logging of API calls.', 'recommendation': 'Enable CloudTrail in all regions.'},
            {'title': 'GuardDuty Not Enabled', 'severity': 'high', 'description': 'Amazon GuardDuty threat detection is not enabled.', 'recommendation': 'Enable GuardDuty for threat monitoring.'},
            {'title': 'Log Retention Too Short', 'severity': 'medium', 'description': 'CloudWatch log retention is set below recommended 90 days.', 'recommendation': 'Increase log retention period.'},
            {'title': 'Alerts Not Configured', 'severity': 'low', 'description': 'No CloudWatch alarms configured for critical events.', 'recommendation': 'Set up alerts for security-relevant events.'},
            {'title': 'VPC Flow Logs Review', 'severity': 'informational', 'description': 'VPC flow logs should be reviewed for completeness.', 'recommendation': 'Review and enable VPC flow logs.'},
        ]
    },
    {
        'category': 'Compliance & Governance',
        'checks': [
            {'title': 'Untagged Resources', 'severity': 'medium', 'description': 'Cloud resources without required tagging were detected.', 'recommendation': 'Apply mandatory tags to all resources.'},
            {'title': 'Outdated AMIs', 'severity': 'medium', 'description': 'EC2 instances running outdated Amazon Machine Images.', 'recommendation': 'Update AMIs to latest patched versions.'},
            {'title': 'No Config Rules', 'severity': 'low', 'description': 'AWS Config rules are not configured for compliance monitoring.', 'recommendation': 'Implement AWS Config rules.'},
            {'title': 'Service Control Policies Review', 'severity': 'low', 'description': 'SCP policies should be reviewed for effectiveness.', 'recommendation': 'Review and update SCP policies.'},
            {'title': 'Compliance Documentation', 'severity': 'informational', 'description': 'Compliance documentation should be updated.', 'recommendation': 'Maintain up-to-date compliance documentation.'},
        ]
    }
]


def run_demo(probability=0.6, rng=None):
    rand = rng.random if rng is not None else random.random
    findings = []
    for check_group in SECURITY_CHECKS:
        category = check_group['category']
        for check in check_group['checks']:
            if rand() < probability:
                findings.append({
                    'engine': 'demo',
                    'control_id': f"demo-{check['title'].lower().replace(' ', '-')}",
                    'severity': check['severity'],
                    'category': category,
                    'title': check['title'],
                    'description': check['description'],
                    'recommendation': check['recommendation'],
                    'resource': 'demo/account',
                })
    if not findings:
        findings.append({
            'engine': 'demo',
            'control_id': 'demo-no-critical-issues',
            'severity': 'informational',
            'category': 'General',
            'title': 'No Critical Issues Found',
            'description': 'The scan completed without detecting critical security issues.',
            'recommendation': 'Continue regular security assessments.',
            'resource': 'demo/account',
        })
    return findings
