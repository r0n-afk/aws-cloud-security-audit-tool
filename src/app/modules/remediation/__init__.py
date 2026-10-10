from flask import Blueprint

remediation_bp = Blueprint('remediation', __name__)

from app.modules.remediation import routes
