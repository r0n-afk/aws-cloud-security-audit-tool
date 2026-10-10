from flask import Blueprint

settings_bp = Blueprint('settings', __name__)

from app.modules.settings import routes
