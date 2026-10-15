from datetime import datetime

from flask import current_app, render_template, request, redirect, url_for, flash, jsonify
from app.modules.assessment import assessment_bp
from app.modules.assessment.services import create_assessment, get_assessment, run_assessment, get_assessment_status

_rate_window = {'start': None, 'count': 0}


def _scan_rate_limited():
    now = datetime.utcnow()
    window = current_app.config.get('SCAN_RATE_LIMIT_WINDOW', 600)
    limit = current_app.config.get('SCAN_RATE_LIMIT_MAX', 5)
    if _rate_window['start'] is None or (now - _rate_window['start']).total_seconds() > window:
        _rate_window['start'] = now
        _rate_window['count'] = 0
    if _rate_window['count'] >= limit:
        return True
    _rate_window['count'] += 1
    return False


@assessment_bp.route('/new')
def new():
    return render_template('assessment/new.html')


@assessment_bp.route('/create', methods=['POST'])
def create():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()

    if _scan_rate_limited():
        flash('Too many assessments started. Wait a few minutes and try again.', 'warning')
        return redirect(url_for('assessment.new'))

    assessment = create_assessment(name, description)
    if not assessment:
        flash('Invalid assessment name.', 'danger')
        return redirect(url_for('assessment.new'))

    success = run_assessment(assessment.id)
    if success:
        flash('Assessment completed successfully!', 'success')
    else:
        from app.modules.assessment.services import get_assessment as _get
        err = _get(assessment.id).scan_error or 'Assessment failed. Check AWS credentials or engine installation.'
        flash(err, 'danger')

    return redirect(url_for('assessment.detail', id=assessment.id))


@assessment_bp.route('/<int:id>')
def detail(id):
    assessment = get_assessment(id)
    return render_template('assessment/detail.html', assessment=assessment)


@assessment_bp.route('/<int:id>/status')
def status(id):
    status_data = get_assessment_status(id)
    if not status_data:
        return jsonify({'error': 'Assessment not found'}), 404
    return jsonify(status_data)
