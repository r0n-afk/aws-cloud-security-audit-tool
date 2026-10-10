from flask import render_template, request, jsonify
from app.modules.remediation import remediation_bp
from app.modules.remediation.services import get_remediation_dashboard, update_remediation_status, get_remediation_progress


@remediation_bp.route('/')
def index():
    data = get_remediation_dashboard()
    return render_template('remediation/index.html', findings=data['findings'], progress=data['progress'])


@remediation_bp.route('/<int:id>/status', methods=['PUT'])
def update_status(id):
    data = request.get_json()
    new_status = data.get('status')
    finding = update_remediation_status(id, new_status)
    if not finding:
        return jsonify({'error': 'Invalid finding or status'}), 400
    return jsonify({'success': True, 'status': finding.remediation_status})


@remediation_bp.route('/progress/<int:assessment_id>')
def progress(assessment_id):
    data = get_remediation_progress(assessment_id)
    return jsonify(data)
