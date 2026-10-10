from flask import Flask
import os
import sys

_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if _src not in sys.path:
    sys.path.insert(0, _src)

from config import config
from app.extensions import db, csrf


def ensure_identity_columns(engine):
    """Add scan-identity columns to pre-existing SQLite DBs (idempotent)."""
    from sqlalchemy import inspect, text
    cols = {c['name'] for c in inspect(engine).get_columns('assessments')}
    with engine.begin() as conn:
        if 'aws_account_id' not in cols:
            conn.execute(text('ALTER TABLE assessments ADD COLUMN aws_account_id VARCHAR(20)'))
        if 'aws_arn' not in cols:
            conn.execute(text('ALTER TABLE assessments ADD COLUMN aws_arn VARCHAR(200)'))


def create_app(config_name='default'):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config[config_name])

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config.get('REPORTS_FOLDER', os.path.join(app.instance_path, 'reports')), exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        from app import models as _models  # noqa: F401  register tables

        from app.modules.auth import auth_bp
        from app.modules.dashboard import dashboard_bp
        from app.modules.assessment import assessment_bp
        from app.modules.findings import findings_bp
        from app.modules.reports import reports_bp
        from app.modules.comparison import comparison_bp
        from app.modules.history import history_bp
        from app.modules.remediation import remediation_bp
        from app.modules.settings import settings_bp
        from app.modules.ai import ai_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp, url_prefix='/')
        app.register_blueprint(assessment_bp, url_prefix='/assessment')
        app.register_blueprint(findings_bp, url_prefix='/findings')
        app.register_blueprint(reports_bp, url_prefix='/reports')
        app.register_blueprint(comparison_bp, url_prefix='/comparison')
        app.register_blueprint(history_bp, url_prefix='/history')
        app.register_blueprint(remediation_bp, url_prefix='/remediation')
        app.register_blueprint(settings_bp, url_prefix='/settings')
        app.register_blueprint(ai_bp, url_prefix='/ai')

        from app.utils.helpers import format_date, format_score, format_percentage
        from app.utils.formatters import severity_badge_color, status_badge_color, assessment_status_badge, score_color
        from flask_wtf.csrf import generate_csrf
        app.jinja_env.globals.update(
            format_date=format_date,
            format_score=format_score,
            format_percentage=format_percentage,
            severity_badge_color=severity_badge_color,
            status_badge_color=status_badge_color,
            assessment_status_badge=assessment_status_badge,
            score_color=score_color,
            csrf_token=generate_csrf,
        )

        register_error_handlers(app)

        @app.route('/favicon.ico')
        def favicon():
            from flask import Response
            return Response(status=204)

        @app.context_processor
        def inject_globals():
            from app.modules.settings.services import get_setting
            from app.models.user import User
            from flask import session
            try:
                ai_on = str(get_setting('ai_enabled', 'false')).lower() == 'true'
                scanner_mode = get_setting('scanner_mode', 'aws')
            except Exception:
                ai_on = False
                scanner_mode = 'aws'
            user = None
            if session.get('user_id'):
                user = db.session.get(User, session.get('user_id'))
            return dict(theme=get_setting('theme', 'light'), ai_on=ai_on,
                        scanner_mode=scanner_mode, current_user=user)

        @app.before_request
        def _enforce_local_auth():
            from flask import request, session, redirect, url_for
            from app.models.user import User
            endpoint = request.endpoint or ''
            if endpoint == 'static' or endpoint.startswith('auth.'):
                return None
            has_user = User.query.first() is not None
            if not has_user:
                if endpoint == 'auth.setup':
                    return None
                return redirect(url_for('auth.setup'))
            if not session.get('user_id'):
                if endpoint == 'auth.login':
                    return None
                return redirect(url_for('auth.login'))
            return None

        db.create_all()
        ensure_identity_columns(db.engine)

        from app.modules.settings.services import init_default_settings
        init_default_settings()

        if app.debug:
            from flask import request as _req

            @app.after_request
            def _dev_no_cache(response):
                # Browser F5 must always show latest templates/CSS/JS.
                if response.headers.get('Content-Type', '').startswith('text/html'):
                    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                    response.headers['Pragma'] = 'no-cache'
                    response.headers['Expires'] = '0'
                elif _req.endpoint == 'static':
                    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                    response.headers['Pragma'] = 'no-cache'
                return response

    return app


def register_error_handlers(app):
    from flask import render_template

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('errors/404.html', message=str(e)), 429
