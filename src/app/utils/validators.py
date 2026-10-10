import re


VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
VALID_STATUSES = ['open', 'in_progress', 'resolved', 'verified']
VALID_ASSESSMENT_STATUSES = ['pending', 'running', 'completed', 'failed']
VALID_REPORT_TYPES = ['pdf', 'html', 'json']


def validate_assessment_name(name):
    if not name or not name.strip():
        return False
    if len(name.strip()) > 200:
        return False
    return True


def validate_severity(severity):
    return severity in VALID_SEVERITIES


def validate_status(status):
    return status in VALID_STATUSES


def validate_assessment_status(status):
    return status in VALID_ASSESSMENT_STATUSES


def validate_report_type(report_type):
    return report_type in VALID_REPORT_TYPES


def sanitize_input(input_str):
    if input_str is None:
        return ''
    input_str = re.sub(r'<[^>]+>', '', str(input_str))
    input_str = input_str.strip()
    return input_str[:1000]
