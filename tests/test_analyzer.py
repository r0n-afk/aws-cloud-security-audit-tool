from analyzer import analyze, calculate_score, dedupe, max_severity, normalize_severity, prioritize


def test_normalize_severity_aliases():
    assert normalize_severity('CRITICAL') == 'critical'
    assert normalize_severity('danger') == 'critical'
    assert normalize_severity('bogus') == 'medium'
    assert normalize_severity(None) == 'medium'


def test_max_severity_picks_higher():
    assert max_severity('low', 'high') == 'high'
    assert max_severity('critical', 'medium') == 'critical'


def test_dedupe_merges_engines_and_severity():
    raw = [
        {'engine': 'prowler', 'control_id': 'c1', 'severity': 'low', 'category': 'Network Security',
         'title': 'Open Port', 'description': 'short', 'recommendation': 'fix', 'resource': 'arn:1'},
        {'engine': 'scoutsuite', 'control_id': 'c1', 'severity': 'high', 'category': 'Network Security',
         'title': 'Open Port', 'description': 'much longer description text', 'recommendation': 'fix now',
         'resource': 'arn:1'},
    ]
    out = dedupe(raw)
    assert len(out) == 1
    assert out[0]['severity'] == 'high'
    assert set(out[0]['engines']) == {'prowler', 'scoutsuite'}
    assert out[0]['description'] == 'much longer description text'


def test_analyze_counts_and_redundancy_metric():
    raw = [
        {'engine': 'prowler', 'control_id': 'c1', 'severity': 'critical', 'category': 'Data Protection',
         'title': 'Public bucket', 'description': 'd', 'recommendation': 'r', 'resource': 'b1'},
        {'engine': 'scoutsuite', 'control_id': 'c1', 'severity': 'critical', 'category': 'Data Protection',
         'title': 'Public bucket', 'description': 'd', 'recommendation': 'r', 'resource': 'b1'},
        {'engine': 'boto3', 'control_id': 'c2', 'severity': 'low', 'category': 'Logging & Monitoring',
         'title': 'No trail', 'description': 'd', 'recommendation': 'r', 'resource': 't1'},
    ]
    result = analyze(raw)
    assert result['raw_count'] == 3
    assert result['deduped_count'] == 2
    assert result['redundancy_removed'] == 1
    assert result['counts']['critical'] == 1
    assert result['counts']['low'] == 1
    assert result['score'] == calculate_score(result['findings'])


def test_score_bounds():
    assert calculate_score([]) == 100.0
    heavy = [{'severity': 'critical'} for _ in range(10)]
    assert calculate_score(heavy) == 0.0


def test_prioritize_orders_by_severity():
    items = [
        {'severity': 'low', 'title': 'a'},
        {'severity': 'critical', 'title': 'b'},
        {'severity': 'medium', 'title': 'c'},
    ]
    ranked = prioritize(items)
    assert [r['title'] for r in ranked] == ['b', 'c', 'a']
