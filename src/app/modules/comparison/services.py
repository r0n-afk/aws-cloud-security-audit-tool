from app.models.assessment import Assessment
from app.models.finding import Finding


def compare_assessments(id1, id2):
    a1 = Assessment.query.get(id1)
    a2 = Assessment.query.get(id2)

    if not a1 or not a2:
        return None

    f1 = Finding.query.filter_by(assessment_id=id1).all()
    f2 = Finding.query.filter_by(assessment_id=id2).all()

    score_diff = a2.security_score - a1.security_score

    sev1 = _count_by_severity(f1)
    sev2 = _count_by_severity(f2)

    severity_diff = {}
    for sev in ['critical', 'high', 'medium', 'low', 'informational']:
        severity_diff[sev] = sev2.get(sev, 0) - sev1.get(sev, 0)

    return {
        'assessment1': a1,
        'assessment2': a2,
        'score_diff': score_diff,
        'findings_diff': a2.total_findings - a1.total_findings,
        'severity_counts1': sev1,
        'severity_counts2': sev2,
        'severity_diff': severity_diff,
        'improved': score_diff > 0
    }


def get_comparison_chart_data(id1, id2):
    a1 = Assessment.query.get(id1)
    a2 = Assessment.query.get(id2)
    if not a1 or not a2:
        return None

    f1 = Finding.query.filter_by(assessment_id=id1).all()
    f2 = Finding.query.filter_by(assessment_id=id2).all()

    return {
        'labels': ['Score', 'Critical', 'High', 'Medium', 'Low', 'Info'],
        'assessment1': [a1.security_score, a1.critical_count, a1.high_count, a1.medium_count, a1.low_count, a1.informational_count],
        'assessment2': [a2.security_score, a2.critical_count, a2.high_count, a2.medium_count, a2.low_count, a2.informational_count],
        'names': [a1.name, a2.name]
    }


def _count_by_severity(findings):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
