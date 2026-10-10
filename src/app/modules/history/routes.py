from flask import render_template, request
from app.modules.history import history_bp
from app.modules.history.services import get_all_assessments, get_assessment_detail


@history_bp.route('/')
def index():
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)
    pagination = get_all_assessments(search=search, page=page)
    return render_template('history/index.html', assessments=pagination.items, pagination=pagination, search=search)


@history_bp.route('/<int:id>')
def detail(id):
    assessment = get_assessment_detail(id)
    return render_template('history/detail.html', assessment=assessment)
