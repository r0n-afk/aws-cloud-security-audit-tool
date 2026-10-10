import uuid
import re
from datetime import datetime


def format_date(date_obj, fmt='%Y-%m-%d %H:%M'):
    if date_obj is None:
        return 'N/A'
    return date_obj.strftime(fmt)


def format_score(score):
    if score is None:
        return '0.0'
    return f'{score:.1f}'


def format_percentage(value):
    if value is None:
        return '0%'
    return f'{value:.1f}%'


def generate_unique_filename(extension):
    unique_id = uuid.uuid4().hex[:12]
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return f'report_{timestamp}_{unique_id}.{extension}'


def safe_filename(filename):
    filename = re.sub(r'[^\w\s\-.]', '', filename)
    filename = re.sub(r'\s+', '_', filename)
    return filename[:200]


def _demo_mode():
    from app.modules.settings.services import get_setting
    return get_setting('scanner_mode', 'aws') == 'demo'


def mode_filter(model):
    """SQL condition: only assessments of the active scanner mode (aws vs demo)."""
    if _demo_mode():
        return model.engines_used == 'demo'
    # ponytail: failed rows with engines_used='' count as aws; add a dedicated column if that matters
    return model.engines_used != 'demo'


def mode_visible(assessment):
    return (assessment.engines_used == 'demo') == _demo_mode()
