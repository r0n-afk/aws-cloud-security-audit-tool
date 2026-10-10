from flask import render_template, request, redirect, url_for, flash, jsonify
from app.modules.settings import settings_bp
from app.modules.settings.services import get_all_settings, update_setting, get_setting, SENSITIVE_KEYS


@settings_bp.route('/')
def index():
    settings = get_all_settings()
    from scanner.aws_checks import connection_status
    aws = connection_status()
    return render_template('settings/index.html', settings=settings, aws=aws)


@settings_bp.route('/aws-status')
def aws_status():
    from scanner.aws_checks import connection_status
    return jsonify(connection_status())


@settings_bp.route('/aws-test', methods=['POST'])
def aws_test():
    from scanner.aws_checks import test_connection
    result = test_connection()
    return jsonify(result), (200 if result.get('ok') else 400)


@settings_bp.route('/update', methods=['POST'])
def update():
    seen = set()
    updates = {}
    ai_enabled_next = None

    for key in request.form:
        if not key.startswith('setting_'):
            continue
        setting_key = key.replace('setting_', '')
        if setting_key in seen:
            continue
        seen.add(setting_key)
        if setting_key == 'ai_enabled':
            values = request.form.getlist(key)
            ai_enabled_next = 'true' if 'true' in values else 'false'
            updates['ai_enabled'] = ai_enabled_next
            continue
        value = request.form.get(key, '')
        if setting_key in SENSITIVE_KEYS:
            if value.startswith('****') and len(value) <= 8:
                continue
            if value.strip() == '':
                updates[setting_key] = ''
                continue
        if setting_key == 'scanner_mode' and value not in ('aws', 'demo'):
            continue
        updates[setting_key] = value

    if ai_enabled_next == 'true':
        base = (updates.get('ai_base_url') if 'ai_base_url' in updates else get_setting('ai_base_url', '')) or ''
        base = base.strip()
        if 'ai_api_key' in updates:
            token = (updates.get('ai_api_key') or '').strip()
            if token.startswith('****') and len(token) <= 8:
                token = (get_setting('ai_api_key', '') or '').strip()
        else:
            token = (get_setting('ai_api_key', '') or '').strip()
        if not base:
            flash('Gateway base URL is required to enable AI Integration.', 'danger')
            return redirect(url_for('settings.index'))
        if not token:
            flash('Gateway token is required to enable AI Integration.', 'danger')
            return redirect(url_for('settings.index'))

    for setting_key, value in updates.items():
        update_setting(setting_key, value)
    flash('Settings updated successfully!', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/update-theme', methods=['POST'])
def update_theme():
    data = request.get_json()
    theme = data.get('theme', 'light')
    if theme in ['light', 'dark']:
        update_setting('theme', theme)
        return jsonify({'success': True, 'theme': theme})
    return jsonify({'error': 'Invalid theme'}), 400
