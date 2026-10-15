from flask import render_template, request, jsonify
from app.modules.findings import findings_bp
from app.modules.findings.services import get_findings, get_finding, update_finding_status, get_categories


@findings_bp.route('/')
def index():
    assessment_id = request.args.get('assessment_id', type=int)
    severity = request.args.get('severity')
    category = request.args.get('category')
    status = request.args.get('status')
    search = request.args.get('search')
    page = request.args.get('page', 1, type=int)

    pagination = get_findings(
        assessment_id=assessment_id,
        severity=severity,
        category=category,
        status=status,
        search=search,
        page=page
    )
    categories = get_categories()
    return render_template('findings/index.html',
                           findings=pagination.items,
                           pagination=pagination,
                           categories=categories,
                           filters={'severity': severity, 'category': category, 'status': status, 'search': search, 'assessment_id': assessment_id})


@findings_bp.route('/<int:id>')
def detail(id):
    finding = get_finding(id)
    return render_template('findings/detail.html', finding=finding)


@findings_bp.route('/<int:id>/status', methods=['PUT'])
def update_status(id):
    data = request.get_json()
    new_status = data.get('status')
    finding = update_finding_status(id, new_status)
    if not finding:
        return jsonify({'error': 'Invalid finding or status'}), 400
    return jsonify({'success': True, 'status': finding.remediation_status})


@findings_bp.route('/assessment/<int:assessment_id>')
def by_assessment(assessment_id):
    page = request.args.get('page', 1, type=int)
    pagination = get_findings(assessment_id=assessment_id, page=page)
    categories = get_categories()
    return render_template('findings/index.html',
                           findings=pagination.items,
                           pagination=pagination,
                           categories=categories,
                           filters={'assessment_id': assessment_id})
