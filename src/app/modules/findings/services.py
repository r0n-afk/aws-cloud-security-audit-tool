from app.extensions import db
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.utils.validators import validate_severity, validate_status


def _base():
    return Finding.query.join(Assessment, Finding.assessment_id == Assessment.id)


def get_findings(assessment_id=None, severity=None, category=None, status=None, search=None, page=1, per_page=20):
    query = _base()

    if assessment_id:
        query = query.filter(Finding.assessment_id == assessment_id)
    if severity and validate_severity(severity):
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if status and validate_status(status):
        query = query.filter(Finding.remediation_status == status)
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Finding.title.ilike(search_term),
                Finding.description.ilike(search_term)
            )
        )

    query = query.order_by(Finding.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination


def get_finding(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    if not finding.assessment:
        from flask import abort
        abort(404)
    return finding


def update_finding_status(finding_id, new_status):
    if not validate_status(new_status):
        return None
    finding = Finding.query.get(finding_id)
    if not finding:
        return None
    finding.remediation_status = new_status
    finding.status = new_status if new_status in ['open', 'in_progress'] else 'resolved'
    db.session.commit()
    return finding


def get_categories():
    categories = _base().with_entities(Finding.category).distinct().all()
    return [c[0] for c in categories]
