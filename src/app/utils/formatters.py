SEVERITY_COLORS = {
    'critical': 'danger',
    'high': 'warning',
    'medium': 'info',
    'low': 'primary',
    'informational': 'secondary'
}

STATUS_COLORS = {
    'open': 'danger',
    'in_progress': 'warning',
    'resolved': 'success',
    'verified': 'info'
}

ASSESSMENT_STATUS_COLORS = {
    'pending': 'secondary',
    'running': 'info',
    'completed': 'success',
    'failed': 'danger'
}


def severity_badge_color(severity):
    return SEVERITY_COLORS.get(severity, 'secondary')


def status_badge_color(status):
    return STATUS_COLORS.get(status, 'secondary')


def assessment_status_badge(status):
    return ASSESSMENT_STATUS_COLORS.get(status, 'secondary')


def score_color(score):
    if score is None:
        return 'secondary'
    if score >= 80:
        return 'success'
    elif score >= 60:
        return 'warning'
    elif score >= 40:
        return 'info'
    else:
        return 'danger'
