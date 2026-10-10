from flask import Blueprint

comparison_bp = Blueprint('comparison', __name__)

from app.modules.comparison import routes
