import json
import os
from datetime import datetime

from flask import current_app
from app.extensions import db
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.report import Report
from app.models.audit import log_event
from app.utils.helpers import generate_unique_filename
from reports.render import build_report_data, render_html, render_pdf

_SEVERITY_SORT = db.case(
    (Finding.severity == 'critical', 0),
    (Finding.severity == 'high', 1),
    (Finding.severity == 'medium', 2),
    (Finding.severity == 'low', 3),
    else_=4,
)


def _ai_summary(assessment, findings):
    try:
        from ai.client import ai_enabled, summarize_assessment
        if not ai_enabled():
            return ''
        return summarize_assessment(assessment, findings[:10]) or ''
    except Exception:
        return ''


def generate_report(assessment_id, report_type):
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return None, 'Assessment not found.'
    if report_type not in ('html', 'json', 'pdf'):
        return None, 'Invalid report type.'

    findings = Finding.query.filter_by(assessment_id=assessment_id).order_by(_SEVERITY_SORT).all()

    meta = {
        'engines': assessment.engines_used or 'n/a',
        'raw_count': assessment.raw_count or len(findings),
        'deduped_count': assessment.deduped_count or len(findings),
        'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
    }
    meta['redundancy_removed'] = max(0, meta['raw_count'] - meta['deduped_count'])

    ai_summary = _ai_summary(assessment, findings)
    data = build_report_data(assessment, findings, meta, ai_summary=ai_summary)

    note = None
    effective_type = report_type

    if report_type == 'json':
        content = json.dumps(data, indent=2, default=str)
        filename = generate_unique_filename('json')
    else:
        html = render_html(data)
        if report_type == 'pdf':
            pdf_bytes, note = render_pdf(html)
            if pdf_bytes is None:
                effective_type = 'html'
                content = html
                filename = generate_unique_filename('html')
            else:
                content = pdf_bytes
                filename = generate_unique_filename('pdf')
        else:
            content = html
            filename = generate_unique_filename('html')

    reports_folder = current_app.config.get(
        'REPORTS_FOLDER', os.path.join(current_app.instance_path, 'reports')
    )
    os.makedirs(reports_folder, exist_ok=True)
    filepath = os.path.join(reports_folder, filename)

    if isinstance(content, bytes):
        with open(filepath, 'wb') as f:
            f.write(content)
    else:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    report = Report(
        assessment_id=assessment_id,
        report_type=effective_type,
        report_path=filepath,
        generated_date=datetime.utcnow(),
    )
    db.session.add(report)
    db.session.commit()
    log_event('report', f'{effective_type} report for assessment #{assessment_id}')
    if report_type == 'pdf' and effective_type == 'html' and note:
        log_event('report_pdf_fallback', note)
    return report, note


def get_report(report_id):
    return Report.query.get_or_404(report_id)


def get_reports(assessment_id=None):
    query = Report.query
    if assessment_id:
        query = query.filter_by(assessment_id=assessment_id)
    return query.order_by(Report.generated_date.desc()).all()


def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not os.path.exists(report.report_path):
        return None
    reports_folder = os.path.abspath(current_app.config.get('REPORTS_FOLDER', ''))
    resolved = os.path.abspath(report.report_path)
    if reports_folder and not resolved.startswith(reports_folder + os.sep) and resolved != reports_folder:
        return None
    return report
