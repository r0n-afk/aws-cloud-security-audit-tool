import json
from flask import render_template, jsonify
from app.modules.dashboard import dashboard_bp
from app.modules.dashboard.services import get_dashboard_stats, get_chart_data, get_recent_activity


@dashboard_bp.route('/')
def index():
    stats = get_dashboard_stats()
    activities = get_recent_activity()
    return render_template('dashboard/index.html', stats=stats, activities=activities)


@dashboard_bp.route('/api/dashboard/stats')
def api_stats():
    stats = get_dashboard_stats()
    return jsonify({
        'security_score': stats['security_score'],
        'total_findings': stats['total_findings'],
        'critical_count': stats['critical_count'],
        'total_assessments': stats['total_assessments']
    })


@dashboard_bp.route('/api/dashboard/charts')
def api_charts():
    data = get_chart_data()
    return jsonify(data)
