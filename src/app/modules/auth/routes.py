import time

from flask import current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from app.extensions import db
from app.models.audit import log_event
from app.models.user import User
from app.modules.auth import auth_bp
from app.utils.validators import sanitize_input

_fail_window = {'start': 0.0, 'count': 0}


def _too_many_fails():
    now = time.time()
    if now - _fail_window['start'] > 60:
        _fail_window['start'] = now
        _fail_window['count'] = 0
    return _fail_window['count'] >= 10


def _record_fail():
    now = time.time()
    if now - _fail_window['start'] > 60:
        _fail_window['start'] = now
        _fail_window['count'] = 0
    _fail_window['count'] += 1


@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if User.query.first() is not None:
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '') or ''
        confirm = request.form.get('confirm', '') or ''
        if len(username) < 3 or len(username) > 80:
            flash('Username must be 3–80 characters.', 'danger')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            log_event('setup', f'Local account created: {username}')
            flash('Account created. Please sign in.', 'success')
            return redirect(url_for('auth.login'))
    return render_template('auth/setup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if User.query.first() is None:
        return redirect(url_for('auth.setup'))
    if session.get('user_id'):
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        if _too_many_fails():
            flash('Too many failed attempts. Wait a minute and try again.', 'warning')
            return render_template('auth/login.html'), 429
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '') or ''
        user = User.query.filter_by(username=username).first()
        delay = current_app.config.get('LOGIN_FAIL_DELAY', 0.3)
        if user is None or not user.check_password(password):
            _record_fail()
            time.sleep(delay)
            log_event('login_fail', f'Failed login for {username}')
            flash('Invalid username or password.', 'danger')
        else:
            session.clear()
            session['user_id'] = user.id
            session.permanent = True
            from datetime import datetime
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_event('login', f'Login: {username}')
            return redirect(url_for('dashboard.index'))
    return render_template('auth/login.html')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    session.clear()
    log_event('logout', f'Logout user_id={uid}')
    flash('Signed out.', 'success')
    return redirect(url_for('auth.login'))
