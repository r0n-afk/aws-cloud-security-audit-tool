from flask import Blueprint

findings_bp = Blueprint('findings', __name__)

from app.modules.findings import routes
