from tests.conftest import get_csrf


def test_first_run_setup_forces_login_wall(client):
    r = client.get('/')
    assert r.status_code == 302
    assert '/auth/setup' in r.headers['Location']


def test_setup_login_logout_cycle(client):
    r = client.get('/auth/setup')
    token = get_csrf(r.data)
    r = client.post(
        '/auth/setup',
        data={'username': 'alice', 'password': 'password1', 'confirm': 'password1', 'csrf_token': token},
    )
    assert r.status_code == 302

    r = client.get('/auth/login')
    token = get_csrf(r.data)
    r = client.post(
        '/auth/login',
        data={'username': 'alice', 'password': 'wrongpass', 'csrf_token': token},
    )
    assert 'Invalid' in r.get_data(as_text=True)

    r = client.get('/auth/login')
    token = get_csrf(r.data)
    r = client.post(
        '/auth/login',
        data={'username': 'alice', 'password': 'password1', 'csrf_token': token},
    )
    assert r.status_code == 302

    r = client.get('/')
    assert r.status_code == 200

    r = client.post('/auth/logout', data={'csrf_token': get_csrf(r.data)})
    assert r.status_code == 302
    r = client.get('/')
    assert '/auth/login' in r.headers['Location']


def test_setup_rejects_short_password(client):
    r = client.get('/auth/setup')
    token = get_csrf(r.data)
    r = client.post(
        '/auth/setup',
        data={'username': 'bob', 'password': 'short', 'confirm': 'short', 'csrf_token': token},
    )
    assert r.status_code == 200
    assert 'at least 8' in r.get_data(as_text=True)


def test_protected_routes_require_auth(client):
    for path in ('/', '/findings/', '/reports/', '/settings/'):
        r = client.get(path)
        assert r.status_code == 302


def test_ai_endpoint_requires_auth_and_enabled(app, client):
    # no user yet → only /auth/setup is reachable (login redirects there)
    token = get_csrf(client.get('/auth/setup').data)
    r = client.post('/ai/qna', json={'question': 'hi'}, headers={'X-CSRFToken': token})
    assert r.status_code == 302  # not logged in


def test_ai_disabled_returns_403(auth_client, app):
    from app.models.finding import Finding
    from app.extensions import db

    with app.app_context():
        from app.models.assessment import Assessment
        from datetime import datetime

        a = Assessment(name='t', assessment_date=datetime.utcnow(), status='completed')
        db.session.add(a)
        db.session.commit()
        f = Finding(
            assessment_id=a.id, severity='high', category='Network Security',
            title='Open port', description='d', recommendation='r',
        )
        db.session.add(f)
        db.session.commit()
        fid = f.id

    page = auth_client.get('/findings/%d' % fid)
    token = get_csrf(page.data)
    r = auth_client.post('/ai/remediation/%d' % fid, headers={'X-CSRFToken': token})
    assert r.status_code == 403
    assert r.get_json()['success'] is False
