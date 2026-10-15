"""Server-side AI usage rate limits: 10/min, 100/day, persisted daily counter."""
import time
from datetime import datetime, timezone


DEFAULT_LIMIT_MINUTE = 10
DEFAULT_LIMIT_DAY = 100

_state = {'window_start': 0.0, 'minute_count': 0, 'in_flight': 0}


class RateLimitError(Exception):
    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = retry_after


def _get_int_setting(key, default):
    try:
        from app.modules.settings.services import get_setting
        value = get_setting(key, str(default))
        return int(value)
    except (TypeError, ValueError):
        return default


def _day_key():
    return datetime.now(timezone.utc).strftime('%Y%m%d')


def _daily_count():
    from app.modules.settings.services import get_setting
    stored_day = get_setting('ai_daily_day', '')
    if stored_day != _day_key():
        return 0
    try:
        return int(get_setting('ai_daily_count', '0'))
    except (TypeError, ValueError):
        return 0


def _persist_daily(count):
    from app.modules.settings.services import update_setting
    update_setting('ai_daily_count', str(count))
    update_setting('ai_daily_day', _day_key())


def check_rate_limit():
    limit_min = _get_int_setting('ai_rate_minute', DEFAULT_LIMIT_MINUTE)
    limit_day = _get_int_setting('ai_rate_day', DEFAULT_LIMIT_DAY)

    now = time.time()
    if now - _state['window_start'] >= 60.0:
        _state['window_start'] = now
        _state['minute_count'] = 0

    if _state['minute_count'] >= limit_min:
        retry = int(60 - (now - _state['window_start'])) + 1
        raise RateLimitError(f'AI minute limit reached ({limit_min}/min). Try again in {retry}s.', retry)

    if _daily_count() >= limit_day:
        raise RateLimitError(f'AI daily limit reached ({limit_day}/day). Resets tomorrow (UTC).', 3600)

    if _state['in_flight'] >= 1:
        raise RateLimitError('Another AI request is in progress. Try again shortly.', 2)


def register_call():
    now = time.time()
    if now - _state['window_start'] >= 60.0:
        _state['window_start'] = now
        _state['minute_count'] = 0
    _state['minute_count'] += 1
    _persist_daily(_daily_count() + 1)


def begin_request():
    if _state['in_flight'] >= 1:
        raise RateLimitError('Another AI request is in progress.', 2)
    _state['in_flight'] += 1


def end_request():
    _state['in_flight'] = max(0, _state['in_flight'] - 1)
