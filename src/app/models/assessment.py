from datetime import datetime
from app.extensions import db


class Assessment(db.Model):
    __tablename__ = 'assessments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    assessment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completion_date = db.Column(db.DateTime)
    security_score = db.Column(db.Float, default=0.0)
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    informational_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), nullable=False, default='pending')
    engines_used = db.Column(db.String(200), default='')
    aws_account_id = db.Column(db.String(20), default='')
    aws_arn = db.Column(db.String(200), default='')
    raw_count = db.Column(db.Integer, default=0)
    deduped_count = db.Column(db.Integer, default=0)
    scan_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    findings = db.relationship('Finding', backref='assessment', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='assessment', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Assessment {self.name}>'
