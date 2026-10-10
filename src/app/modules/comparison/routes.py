from flask import render_template, request, redirect, url_for, flash, jsonify
from app.modules.comparison import comparison_bp
from app.modules.comparison.services import compare_assessments, get_comparison_chart_data
from app.models.assessment import Assessment


@comparison_bp.route('/')
def index():
    from app.utils.helpers import mode_filter
    assessments = Assessment.query.filter_by(status='completed').filter(mode_filter(Assessment)).order_by(Assessment.created_at.desc()).all()
    id1 = request.args.get('id1', type=int)
    id2 = request.args.get('id2', type=int)
    comparison = None
    if id1 and id2:
        comparison = compare_assessments(id1, id2)
    return render_template('comparison/index.html', assessments=assessments, comparison=comparison, id1=id1, id2=id2)


@comparison_bp.route('/compare', methods=['POST'])
def compare():
    id1 = request.form.get('assessment1', type=int)
    id2 = request.form.get('assessment2', type=int)

    if not id1 or not id2:
        flash('Please select two assessments to compare.', 'warning')
        return redirect(url_for('comparison.index'))

    if id1 == id2:
        flash('Please select two different assessments.', 'warning')
        return redirect(url_for('comparison.index'))

    return redirect(url_for('comparison.index', id1=id1, id2=id2))


@comparison_bp.route('/api/<int:id1>/<int:id2>')
def api_compare(id1, id2):
    data = get_comparison_chart_data(id1, id2)
    if not data:
        return jsonify({'error': 'Assessments not found'}), 404
    return jsonify(data)
