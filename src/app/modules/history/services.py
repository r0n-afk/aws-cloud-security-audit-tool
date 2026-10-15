from app.models.assessment import Assessment


def get_all_assessments(search=None, page=1, per_page=20):
    query = Assessment.query

    if search:
        search_term = f'%{search}%'
        query = query.filter(Assessment.name.ilike(search_term))

    query = query.order_by(Assessment.created_at.desc())
    return query.paginate(page=page, per_page=per_page, error_out=False)


def get_assessment_detail(assessment_id):
    return Assessment.query.get_or_404(assessment_id)
