import os
import re
import sys
import tempfile

import pytest

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC = os.path.join(BASE, 'src')
if SRC not in sys.path:
    sys.path.insert(0, SRC)


@pytest.fixture()
def app():
    from app import create_app
    from app.extensions import db as _db
    from config import config as config_map

    tmp = tempfile.mkdtemp(prefix='csat_test_')
    cfg = config_map['development']
    old_uri = cfg.SQLALCHEMY_DATABASE_URI
    old_reports = cfg.REPORTS_FOLDER
    cfg.SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(tmp, 'test.db')
    cfg.REPORTS_FOLDER = os.path.join(tmp, 'reports')

    try:
        application = create_app('development')
        application.config['TESTING'] = True
        application.config['LOGIN_FAIL_DELAY'] = 0

        with application.app_context():
            _db.session.remove()
            _db.drop_all()
            _db.create_all()
            from app.modules.settings.services import init_default_settings

            init_default_settings()
        yield application
    finally:
        try:
            with application.app_context():
                _db.session.remove()
                _db.drop_all()
        except Exception:
            pass
        cfg.SQLALCHEMY_DATABASE_URI = old_uri
        cfg.REPORTS_FOLDER = old_reports


@pytest.fixture(autouse=True)
def _reset_scan_rate_limit():
    """Module-global counter in assessment/routes must not leak across tests."""
    from app.modules.assessment import routes as _ar

    _ar._rate_window['start'] = None
    _ar._rate_window['count'] = 0
    yield


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(app, client):
    r = client.get('/auth/setup')
    token = _csrf(r.data)
    client.post(
        '/auth/setup',
        data={'username': 'tester', 'password': 'secret123', 'confirm': 'secret123', 'csrf_token': token},
    )
    r = client.get('/auth/login')
    token = _csrf(r.data)
    client.post(
        '/auth/login',
        data={'username': 'tester', 'password': 'secret123', 'csrf_token': token},
    )
    return client


def _csrf(html):
    m = re.search(rb'name="csrf_token" value="([^"]+)"', html) or re.search(
        rb'csrf-token" content="([^"]+)"', html
    )
    return m.group(1).decode() if m else ''


get_csrf = _csrf
