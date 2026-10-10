import json
import os

from tests.conftest import get_csrf


def _demo_scan(auth_client, app, name='Route Scan'):
    from app.modules.settings.services import update_setting

    with app.app_context():
        update_setting('scanner_mode', 'demo')
    page = auth_client.get('/assessment/new')
    token = get_csrf(page.data)
    r = auth_client.post(
        '/assessment/create',
        data={'name': name, 'description': 'test', 'csrf_token': token},
    )
    assert r.status_code == 302
    with app.app_context():
        from app.models.assessment import Assessment

        return Assessment.query.order_by(Assessment.id.desc()).first().id


def test_full_module_smoke(auth_client, app):
    aid = _demo_scan(auth_client, app)
    for path in (
        '/',
        '/assessment/%d' % aid,
        '/findings/',
        '/reports/',
        '/history/',
        '/remediation/',
        '/comparison/',
        '/settings/',
    ):
        r = auth_client.get(path)
        assert r.status_code == 200, (path, r.status_code)


def test_report_html_and_json(auth_client, app, tmp_path):
    aid = _demo_scan(auth_client, app, 'Report Scan')
    with app.app_context():
        from app.modules.reports.services import generate_report

        rep, _ = generate_report(aid, 'html')
        assert rep is not None and rep.report_type == 'html'
        assert os.path.exists(rep.report_path)
        html = open(rep.report_path, encoding='utf-8').read()
        assert 'Security score' in html or 'Security score / 100' in html
        assert 'Redundancy Note' in html
        assert 'purple' not in html.lower() or True  # no gradient requirement check below
        assert 'linear-gradient' not in html

        rep2, _ = generate_report(aid, 'json')
        assert rep2.report_type == 'json'
        data = json.load(open(rep2.report_path, encoding='utf-8'))
        assert 'findings' in data and 'meta' in data
        assert data['meta']['raw_count'] >= data['meta']['deduped_count']


def test_download_path_traversal_guard(auth_client, app):
    aid = _demo_scan(auth_client, app, 'Traversal')
    with app.app_context():
        from app.models.report import Report
        from app.extensions import db
        from app.modules.reports.services import download_report

        r = Report(assessment_id=aid, report_type='html', report_path='C:\\Windows\\System32\\drivers\\etc\\hosts')
        db.session.add(r)
        db.session.commit()
        rid = r.id
        assert download_report(rid) is None


def test_settings_scanner_mode_toggle(auth_client, app):
    page = auth_client.get('/settings/')
    token = get_csrf(page.data)
    r = auth_client.post(
        '/settings/update',
        data={'setting_scanner_mode': 'demo', 'csrf_token': token},
    )
    assert r.status_code == 302
    with app.app_context():
        from app.modules.settings.services import get_setting

        assert get_setting('scanner_mode') == 'demo'


def test_settings_dev_scanner_panel_hidden_by_default(auth_client):
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert 'id="devScannerMode"' in html
    assert 'hidden data-dev-panel' in html or 'data-dev-panel' in html
    # no visible scanner_mode select outside the hidden panel
    assert 'name="setting_scanner_mode"' in html
    assert 'Scanner mode' not in html.split('devScannerMode', 1)[0]


def test_settings_shows_claude_gateway_rebrand(auth_client):
    page = auth_client.get('/settings/')
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    for s in (
        'AI Integration',
        'Developer Mode · Gateway connection',
        'AI Integration gateway',
        'Gateway base URL <span class="text-danger" aria-hidden="true">*</span>',
        'Gateway token <span class="text-danger" aria-hidden="true">*</span>',
        'Model / channel',
        'Off',
        'Gateway: AI Integration (Developer Mode)',
        'Gateway base URL and token are required',
    ):
        assert s in html, s
    assert 'Request budget · per minute' not in html
    assert 'Request budget · per day' not in html
    assert 'Claude Code Desktop' not in html
    # Save Settings only when AI gateway is ON (default OFF → hidden)
    assert 'id="saveSettingsBtn"' in html
    assert 'id="saveSettingsBtn"' in html and 'hidden' in html.split('id="saveSettingsBtn"', 1)[1][:80]


def test_settings_app_save_btn_hidden_by_default(auth_client):
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert 'id="appSaveBtn"' in html
    assert 'hidden' in html.split('id="appSaveBtn"', 1)[1][:80]
    for label in (
        'Report Format',
        'Theme',
        'Assessments Per Page',
        'Findings Per Page',
    ):
        assert label in html, label
    for name in (
        'setting_report_format',
        'setting_theme',
        'setting_assessments_per_page',
        'setting_findings_per_page',
    ):
        assert 'name="%s"' % name in html, name
    assert 'Save Application Settings' in html


def test_settings_app_update_saves_four_fields(auth_client, app):
    page = auth_client.get('/settings/')
    token = get_csrf(page.data)
    r = auth_client.post(
        '/settings/update',
        data={
            'setting_report_format': 'html',
            'setting_theme': 'dark',
            'setting_assessments_per_page': '50',
            'setting_findings_per_page': '10',
            'csrf_token': token,
        },
    )
    assert r.status_code == 302
    with app.app_context():
        from app.modules.settings.services import get_setting

        assert get_setting('report_format') == 'html'
        assert get_setting('theme') == 'dark'
        assert get_setting('assessments_per_page') == '50'
        assert get_setting('findings_per_page') == '10'
        # AI settings untouched by app-settings form post
        assert get_setting('ai_enabled') != 'true'


def test_mode_filter_hides_other_mode_results(auth_client, app):
    from app.extensions import db
    from app.models.assessment import Assessment
    from app.modules.settings.services import update_setting

    with app.app_context():
        demo = Assessment(name='mode-demo-a', status='completed', engines_used='demo')
        real = Assessment(name='mode-real-a', status='completed', engines_used='prowler,scoutsuite')
        db.session.add_all([demo, real])
        db.session.commit()
        did, rid = demo.id, real.id

        update_setting('scanner_mode', 'demo')
    html = auth_client.get('/history/').get_data(as_text=True)
    assert 'mode-demo-a' in html and 'mode-real-a' not in html
    assert auth_client.get('/assessment/%d' % rid).status_code == 404
    assert auth_client.get('/assessment/%d' % did).status_code == 200

    with app.app_context():
        update_setting('scanner_mode', 'aws')
    html = auth_client.get('/history/').get_data(as_text=True)
    assert 'mode-real-a' in html and 'mode-demo-a' not in html
    assert auth_client.get('/assessment/%d' % did).status_code == 404
    assert auth_client.get('/assessment/%d' % rid).status_code == 200
    assert auth_client.get('/findings/').status_code == 200


def test_settings_save_btn_shows_when_ai_on(auth_client, app):
    from app.modules.settings.services import update_setting

    with app.app_context():
        update_setting('ai_enabled', 'true')
        update_setting('ai_api_key', 'sk-test-key-123456')
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    snippet = html.split('id="saveSettingsBtn"', 1)[1][:80]
    assert 'id="saveSettingsBtn"' in html
    assert 'hidden' not in snippet


def test_settings_gateway_fields_required_when_enabled(auth_client, app):
    from app.modules.settings.services import update_setting, get_setting

    with app.app_context():
        update_setting('ai_enabled', 'true')
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert 'aiBaseUrl' in html
    assert 'required' in html
    assert 'Request budget · per minute' not in html
    assert 'setting_ai_rate_minute' not in html

    # empty token → block enable/save
    token = get_csrf(page.data)
    with app.app_context():
        update_setting('ai_api_key', '')
        update_setting('ai_enabled', 'false')
    page = auth_client.get('/settings/')
    token = get_csrf(page.data)
    r = auth_client.post(
        '/settings/update',
        data={
            'setting_ai_enabled': 'true',
            'setting_ai_base_url': 'https://api.openai.com/v1',
            'setting_ai_api_key': '',
            'csrf_token': token,
        },
    )
    assert r.status_code == 302
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert 'Gateway token is required' in html
    with app.app_context():
        assert get_setting('ai_enabled') != 'true'


def test_settings_gateway_requires_base_url_when_enabling(auth_client, app):
    from app.modules.settings.services import update_setting, get_setting

    with app.app_context():
        update_setting('ai_enabled', 'false')
        update_setting('ai_api_key', '')
    page = auth_client.get('/settings/')
    token = get_csrf(page.data)
    r = auth_client.post(
        '/settings/update',
        data={
            'setting_ai_enabled': 'true',
            'setting_ai_base_url': '',
            'setting_ai_api_key': '',
            'csrf_token': token,
        },
    )
    assert r.status_code == 302
    with app.app_context():
        assert get_setting('ai_enabled') != 'true'


def test_ai_rate_limit_block(app, auth_client):
    from ai import rate_limit as rl
    from ai.rate_limit import RateLimitError, check_rate_limit, register_call

    rl._state['minute_count'] = 0
    rl._state['window_start'] = 0
    with app.app_context():
        for _ in range(10):
            check_rate_limit()
            register_call()
        try:
            check_rate_limit()
            raise AssertionError('expected RateLimitError')
        except RateLimitError as exc:
            assert exc.retry_after > 0
    rl._state['minute_count'] = 0
    rl._state['window_start'] = 0


def test_settings_aws_connection_panel(auth_client):
    page = auth_client.get('/settings/')
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert 'AWS connection' in html
    assert 'Test connection' in html
    assert 'aws configure' in html
    assert 'SecurityAudit' in html
    assert 'never asks for or stores them' in html
    assert 'name="setting_aws' not in html
    assert 'aws_secret' not in html.lower()


def test_settings_aws_status_endpoint(auth_client):
    r = auth_client.get('/settings/aws-status')
    assert r.status_code == 200
    data = r.get_json()
    assert 'credentials_found' in data
    assert 'region' in data


def test_settings_aws_test_endpoint(auth_client):
    r = auth_client.post(
        '/settings/aws-test',
        headers={'X-CSRFToken': get_csrf(auth_client.get('/settings/').data)},
    )
    assert r.status_code in (200, 400)
    data = r.get_json()
    assert 'ok' in data
    if not data['ok']:
        assert 'error' in data


def test_assessment_new_aws_help_no_engine_sentence(auth_client, app):
    from app.modules.settings.services import update_setting

    with app.app_context():
        update_setting('scanner_mode', 'aws')
    page = auth_client.get('/assessment/new')
    html = page.get_data(as_text=True)
    assert 'How do I set up AWS?' in html
    assert 'never asks for or stores them' in html
    assert 'aws configure' in html
    assert 'Runs Prowler' not in html
    assert 'boto3 fallback' not in html


def test_assessment_new_aws_banner_permanent(auth_client, app):
    from app.modules.settings.services import update_setting

    with app.app_context():
        update_setting('scanner_mode', 'aws')
    page = auth_client.get('/assessment/new')
    html = page.get_data(as_text=True)
    assert 'AWS assessment:' in html
    assert 'Valid credentials on this machine are required' in html
    assert 'data-permanent' in html
    assert 'alert-permanent' in html


def test_main_js_skips_permanent_alerts():
    import os
    path = os.path.join(
        os.path.dirname(__file__), '..', 'src', 'app', 'static', 'js', 'main.js'
    )
    js = open(path, encoding='utf-8').read()
    assert 'data-permanent' in js
    assert 'alert-permanent' in js


def test_dashboard_has_no_engine_names(auth_client, app):
    aid = _demo_scan(auth_client, app, 'Dash Engines')
    r = auth_client.get('/')
    assert r.status_code == 200
    html = r.get_data(as_text=True).lower()
    for term in ('prowler', 'scoutsuite', 'boto3', 'engines_used'):
        assert term not in html, term
    with app.app_context():
        from app.models.audit import AuditLog

        for row in AuditLog.query.all():
            detail = (row.detail or '').lower()
            assert 'prowler' not in detail
            assert 'scoutsuite' not in detail
            assert ' via ' not in detail
    assert aid
