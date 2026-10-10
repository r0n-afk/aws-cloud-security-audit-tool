from app.models.assessment import Assessment
from app.utils.helpers import mode_filter, mode_visible


def get_all_assessments(search=None, page=1, per_page=20):
    query = Assessment.query.filter(mode_filter(Assessment))

    if search:
        search_term = f'%{search}%'
        query = query.filter(Assessment.name.ilike(search_term))

    query = query.order_by(Assessment.created_at.desc())
    return query.paginate(page=page, per_page=per_page, error_out=False)


def get_assessment_detail(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    if not mode_visible(assessment):
        from flask import abort
        abort(404)
    return assessment
