"""Analyzer: normalize → unify severity → dedupe (redundancy check) → categorize → score."""
SEVERITY_ORDER = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']

SEVERITY_WEIGHTS = {
    'critical': 25,
    'high': 15,
    'medium': 8,
    'low': 3,
    'informational': 1,
}


def normalize_severity(value):
    if not value:
        return 'medium'
    v = str(value).strip().lower()
    if v in SEVERITY_ORDER:
        return v
    aliases = {
        'flash': 'critical', 'danger': 'critical', 'crit': 'critical',
        'warning': 'medium', 'warn': 'medium', 'notice': 'informational',
        'info': 'informational', 'information': 'informational',
    }
    return aliases.get(v, 'medium')


def max_severity(a, b):
    a = normalize_severity(a)
    b = normalize_severity(b)
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def _norm_text(value):
    import re
    text = str(value or '').lower()
    text = re.sub(r'[^a-z0-9]+', ' ', text)
    return ' '.join(text.split())


def dedupe_key(finding):
    resource = _norm_text(finding.get('resource'))
    control = _norm_text(finding.get('control_id'))
    title = _norm_text(finding.get('title'))
    base = control or title
    if resource:
        return (base, resource)
    return (base, title)


def dedupe(raw_findings):
    merged = {}
    order = []
    for item in raw_findings:
        key = dedupe_key(item)
        engine = item.get('engine', 'unknown')
        if key not in merged:
            entry = {
                'control_id': item.get('control_id') or item.get('title', ''),
                'severity': normalize_severity(item.get('severity')),
                'category': item.get('category') or 'General',
                'title': item.get('title', 'Finding'),
                'description': item.get('description', ''),
                'recommendation': item.get('recommendation', ''),
                'resource': item.get('resource', ''),
                'engines': [engine],
            }
            merged[key] = entry
            order.append(key)
        else:
            entry = merged[key]
            if engine not in entry['engines']:
                entry['engines'].append(engine)
            entry['severity'] = max_severity(entry['severity'], item.get('severity'))
            if len(str(item.get('description', ''))) > len(entry['description']):
                entry['description'] = item.get('description', entry['description'])
            if not entry['recommendation'] and item.get('recommendation'):
                entry['recommendation'] = item.get('recommendation')
    return [merged[k] for k in order]


def calculate_score(findings):
    score = 100.0
    counts = count_by_severity(findings)
    for sev, weight in SEVERITY_WEIGHTS.items():
        score -= counts.get(sev, 0) * weight
    return max(0.0, score)


def count_by_severity(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = normalize_severity(f.get('severity'))
        counts[sev] += 1
    return counts


def analyze(raw_findings):
    deduped = dedupe(raw_findings)
    counts = count_by_severity(deduped)
    return {
        'findings': deduped,
        'raw_count': len(raw_findings),
        'deduped_count': len(deduped),
        'redundancy_removed': max(0, len(raw_findings) - len(deduped)),
        'counts': counts,
        'score': calculate_score(deduped),
    }


def prioritize(findings, top_n=None):
    ranked = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER[normalize_severity(f.get('severity') if isinstance(f, dict) else getattr(f, 'severity', 'medium'))],
        reverse=True,
    )
    if top_n:
        return ranked[:top_n]
    return ranked
