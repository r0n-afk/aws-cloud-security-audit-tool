from app.extensions import db
from app.models.finding import Finding
from app.models.assessment import Assessment
from app.utils.helpers import mode_filter
from app.utils.validators import validate_status


def _findings():
    return Finding.query.join(Assessment, Finding.assessment_id == Assessment.id).filter(
        mode_filter(Assessment)
    )


def get_remediation_dashboard():
    open_count = _findings().filter(Finding.remediation_status == 'open').count()
    in_progress_count = _findings().filter(Finding.remediation_status == 'in_progress').count()
    resolved_count = _findings().filter(Finding.remediation_status == 'resolved').count()
    verified_count = _findings().filter(Finding.remediation_status == 'verified').count()
    total = open_count + in_progress_count + resolved_count + verified_count

    findings_by_status = {
        'open': _findings().filter(Finding.remediation_status == 'open').order_by(Finding.created_at.desc()).all(),
        'in_progress': _findings().filter(Finding.remediation_status == 'in_progress').order_by(Finding.created_at.desc()).all(),
        'resolved': _findings().filter(Finding.remediation_status == 'resolved').order_by(Finding.created_at.desc()).all(),
        'verified': _findings().filter(Finding.remediation_status == 'verified').order_by(Finding.created_at.desc()).all(),
    }

    progress = {
        'open': open_count,
        'in_progress': in_progress_count,
        'resolved': resolved_count,
        'verified': verified_count,
        'total': total,
        'progress_pct': ((resolved_count + verified_count) / total * 100) if total > 0 else 0
    }

    return {'findings': findings_by_status, 'progress': progress}


def update_remediation_status(finding_id, new_status):
    if not validate_status(new_status):
        return None
    finding = Finding.query.get(finding_id)
    if not finding:
        return None
    finding.remediation_status = new_status
    if new_status in ['resolved', 'verified']:
        finding.status = 'resolved'
    else:
        finding.status = new_status
    db.session.commit()
    return finding


def get_remediation_progress(assessment_id):
    findings = Finding.query.filter_by(assessment_id=assessment_id).all()
    total = len(findings)
    if total == 0:
        return {'total': 0, 'open': 0, 'in_progress': 0, 'resolved': 0, 'verified': 0, 'progress_pct': 0}

    counts = {
        'open': sum(1 for f in findings if f.remediation_status == 'open'),
        'in_progress': sum(1 for f in findings if f.remediation_status == 'in_progress'),
        'resolved': sum(1 for f in findings if f.remediation_status == 'resolved'),
        'verified': sum(1 for f in findings if f.remediation_status == 'verified'),
    }
    counts['total'] = total
    counts['progress_pct'] = ((counts['resolved'] + counts['verified']) / total * 100)
    return counts
