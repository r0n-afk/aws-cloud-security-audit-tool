from app.models.assessment import Assessment
from app.models.finding import Finding


def _assessments():
    return Assessment.query


def _findings():
    return Finding.query.join(Assessment, Finding.assessment_id == Assessment.id)


def get_dashboard_stats():
    latest_assessment = _assessments().order_by(Assessment.created_at.desc()).first()
    total_assessments = _assessments().count()
    total_findings = _findings().count()
    critical_count = _findings().filter(Finding.severity == 'critical').count()
    high_count = _findings().filter(Finding.severity == 'high').count()

    return {
        'latest_assessment': latest_assessment,
        'total_assessments': total_assessments,
        'total_findings': total_findings,
        'critical_count': critical_count,
        'high_count': high_count,
        'security_score': latest_assessment.security_score if latest_assessment else 0.0,
        'last_assessment_date': latest_assessment.assessment_date if latest_assessment else None
    }


def get_chart_data():
    assessments = _assessments().order_by(Assessment.assessment_date.asc()).all()

    severity_counts = {
        'critical': _findings().filter(Finding.severity == 'critical').count(),
        'high': _findings().filter(Finding.severity == 'high').count(),
        'medium': _findings().filter(Finding.severity == 'medium').count(),
        'low': _findings().filter(Finding.severity == 'low').count(),
        'informational': _findings().filter(Finding.severity == 'informational').count(),
    }

    category_counts = {}
    findings = _findings().all()
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    score_trend = {
        'dates': [a.assessment_date.strftime('%Y-%m-%d') for a in assessments],
        'scores': [a.security_score for a in assessments]
    }

    remediation_counts = {
        'open': _findings().filter(Finding.remediation_status == 'open').count(),
        'in_progress': _findings().filter(Finding.remediation_status == 'in_progress').count(),
        'resolved': _findings().filter(Finding.remediation_status == 'resolved').count(),
        'verified': _findings().filter(Finding.remediation_status == 'verified').count(),
    }

    return {
        'severity_distribution': severity_counts,
        'category_distribution': category_counts,
        'score_trend': score_trend,
        'remediation_status': remediation_counts
    }


def get_recent_activity():
    assessments = _assessments().order_by(Assessment.created_at.desc()).limit(5).all()
    activities = []
    for a in assessments:
        activities.append({
            'type': 'assessment',
            'message': f'Assessment "{a.name}" completed',
            'date': a.created_at,
            'status': a.status,
            'score': a.security_score
        })
    return activities
