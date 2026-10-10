import os
import secrets

basedir = os.path.abspath(os.path.dirname(__file__))


def _load_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    secret_file = os.path.join(basedir, 'instance', 'secret_key')
    os.makedirs(os.path.dirname(secret_file), exist_ok=True)
    if os.path.exists(secret_file):
        with open(secret_file, 'r') as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(secret_file, 'w') as f:
        f.write(key)
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass
    return key


class Config:
    SECRET_KEY = _load_secret_key()
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'csa_tool.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REPORTS_FOLDER = os.path.join(basedir, 'instance', 'reports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = None
    SCAN_TIMEOUT_SECONDS = int(os.environ.get('SCAN_TIMEOUT_SECONDS', '1800'))
    SCAN_RATE_LIMIT_WINDOW = 600
    SCAN_RATE_LIMIT_MAX = 5
    LOGIN_FAIL_DELAY = 0.3


class DevelopmentConfig(Config):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    # Never cache static assets in local dev — browser refresh must show edits.
    SEND_FILE_MAX_AGE_DEFAULT = 0
    ASSETS_CACHE = 0


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
