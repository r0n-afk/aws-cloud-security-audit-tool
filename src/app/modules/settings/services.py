from app.models.setting import Setting
from app.extensions import db


DEFAULT_SETTINGS = {
    'report_format': {'value': 'pdf', 'description': 'Default report format (pdf, html, json)'},
    'theme': {'value': 'light', 'description': 'UI theme'},
    'assessments_per_page': {'value': '20', 'description': 'Assessments per page'},
    'findings_per_page': {'value': '20', 'description': 'Findings per page'},
    'ai_enabled': {'value': 'false', 'description': 'AI Integration gateway (Developer Mode; default off)'},
    'ai_base_url': {'value': 'https://api.openai.com/v1', 'description': 'Gateway base URL — OpenAI-compatible, HTTPS required (loopback allowed)'},
    'ai_api_key': {'value': '', 'description': 'Gateway token (stored locally, never committed)'},
    'ai_model': {'value': 'gpt-4o-mini', 'description': 'Model / channel id used by the gateway'},
    'ai_daily_count': {'value': '0', 'description': 'Internal: AI calls used today (UTC)'},
    'ai_daily_day': {'value': '', 'description': 'Internal: current AI rate-limit day'},
}

SENSITIVE_KEYS = {'ai_api_key'}


def init_default_settings():
    for key, data in DEFAULT_SETTINGS.items():
        existing = Setting.query.filter_by(key=key).first()
        if not existing:
            setting = Setting(key=key, value=data['value'], description=data['description'])
            db.session.add(setting)
        elif existing.description != data['description']:
            existing.description = data['description']
    db.session.commit()


def get_setting(key, default=None):
    setting = Setting.query.filter_by(key=key).first()
    return setting.value if setting else default


def update_setting(key, value):
    setting = Setting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = Setting(key=key, value=value)
        db.session.add(setting)
    db.session.commit()
    return setting


def get_all_settings():
    settings = Setting.query.all()
    result = {}
    for s in settings:
        value = s.value
        if s.key in SENSITIVE_KEYS and value:
            value = '****' + value[-4:] if len(value) > 8 else '****'
        result[s.key] = {'value': value, 'description': s.description, 'sensitive': s.key in SENSITIVE_KEYS}
    return result
