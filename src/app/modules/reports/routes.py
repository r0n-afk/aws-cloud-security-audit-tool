from flask import render_template, request, redirect, url_for, flash, send_file
from app.modules.reports import reports_bp
from app.modules.reports.services import generate_report, get_report, get_reports, download_report
from app.modules.assessment.services import get_assessment
from app.models.assessment import Assessment


@reports_bp.route('/')
def index():
    assessment_id = request.args.get('assessment_id', type=int)
    reports = get_reports(assessment_id=assessment_id)
    if assessment_id:
        assessments_list = [get_assessment(assessment_id)]
    else:
        assessments_list = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template(
        'reports/index.html',
        reports=reports,
        assessments=assessments_list,
        selected_assessment=assessment_id,
    )


@reports_bp.route('/generate', methods=['POST'])
def generate():
    assessment_id = request.form.get('assessment_id', type=int)
    report_type = request.form.get('report_type', 'html')

    if not assessment_id:
        flash('Please select an assessment.', 'warning')
        return redirect(url_for('reports.index'))

    report, note = generate_report(assessment_id, report_type)
    if report:
        msg = f'{report.report_type.upper()} report generated successfully!'
        if note:
            msg += f' ({note})'
        flash(msg, 'success')
    else:
        flash(note or 'Report generation failed.', 'danger')

    return redirect(url_for('reports.index'))


@reports_bp.route('/<int:id>/download')
def download(id):
    report = download_report(id)
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('reports.index'))

    mimetype = {
        'pdf': 'application/pdf',
        'html': 'text/html',
        'json': 'application/json',
    }.get(report.report_type, 'application/octet-stream')

    return send_file(report.report_path, mimetype=mimetype, as_attachment=True)


@reports_bp.route('/<int:id>/preview')
def preview(id):
    report = get_report(id)
    if report.report_type == 'html':
        return send_file(report.report_path, mimetype='text/html')
    flash('Preview only available for HTML reports.', 'info')
    return redirect(url_for('reports.index'))
