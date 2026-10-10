from datetime import datetime

from app.extensions import db
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.audit import log_event
from app.utils.validators import validate_assessment_name


def create_assessment(name, description=''):
    if not validate_assessment_name(name):
        return None

    assessment = Assessment(
        name=name.strip(),
        description=description.strip() if description else '',
        assessment_date=datetime.utcnow(),
        status='pending'
    )
    db.session.add(assessment)
    db.session.commit()
    return assessment


def get_assessment(assessment_id):
    from app.utils.helpers import mode_visible
    assessment = Assessment.query.get_or_404(assessment_id)
    if not mode_visible(assessment):
        from flask import abort
        abort(404)
    return assessment


def run_assessment(assessment_id):
    from flask import current_app
    from app.modules.settings.services import get_setting
    from scanner.orchestrator import CredentialsError, EngineUnavailableError, run_scan
    from analyzer import analyze

    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return False

    assessment.status = 'running'
    db.session.commit()

    mode = get_setting('scanner_mode', 'aws')
    timeout = current_app.config.get('SCAN_TIMEOUT_SECONDS', 1800)

    try:
        scan_result = run_scan(mode=mode, timeout=timeout)
        analysis = analyze(scan_result['findings'])

        for item in analysis['findings']:
            db.session.add(Finding(
                assessment_id=assessment.id,
                severity=item['severity'],
                category=item['category'],
                title=item['title'][:300],
                description=item['description'],
                recommendation=item['recommendation'],
                resource=str(item.get('resource', ''))[:500],
                control_id=str(item.get('control_id', ''))[:200],
                engines=','.join(item.get('engines', []))[:200],
                status='open',
                remediation_status='open',
            ))

        counts = analysis['counts']
        assessment.completion_date = datetime.utcnow()
        assessment.status = 'completed'
        assessment.engines_used = ','.join(scan_result.get('engines', []))[:200]
        assessment.aws_account_id = str(scan_result.get('aws_account_id', ''))[:20]
        assessment.aws_arn = str(scan_result.get('aws_arn', ''))[:200]
        assessment.raw_count = analysis['raw_count']
        assessment.deduped_count = analysis['deduped_count']
        assessment.total_findings = analysis['deduped_count']
        assessment.critical_count = counts['critical']
        assessment.high_count = counts['high']
        assessment.medium_count = counts['medium']
        assessment.low_count = counts['low']
        assessment.informational_count = counts['informational']
        assessment.security_score = analysis['score']
        assessment.scan_error = '; '.join(scan_result.get('errors', []))[:1000] or None
        db.session.commit()
        log_event(
            'scan',
            f'Assessment #{assessment.id}: '
            f'{analysis["raw_count"]}->{analysis["deduped_count"]}',
        )
        return True

    except (CredentialsError, EngineUnavailableError) as exc:
        assessment.status = 'failed'
        assessment.scan_error = str(exc)[:1000]
        db.session.commit()
        log_event('scan_fail', f'Assessment #{assessment.id}: {exc}')
        return False
    except Exception as exc:
        assessment.status = 'failed'
        assessment.scan_error = str(exc)[:1000]
        db.session.commit()
        log_event('scan_fail', f'Assessment #{assessment.id}: {exc.__class__.__name__}')
        return False


def get_assessment_status(assessment_id):
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return None
    return {
        'id': assessment.id,
        'status': assessment.status,
        'score': assessment.security_score,
        'total_findings': assessment.total_findings,
        'engines': assessment.engines_used,
        'error': assessment.scan_error,
    }
