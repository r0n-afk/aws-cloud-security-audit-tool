from datetime import datetime
from app.extensions import db


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default='open')
    remediation_status = db.Column(db.String(20), nullable=False, default='open')
    resource = db.Column(db.String(500), default='')
    control_id = db.Column(db.String(200), default='')
    engines = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_findings_assessment', 'assessment_id'),
        db.Index('idx_findings_severity', 'severity'),
        db.Index('idx_findings_status', 'status'),
        db.Index('idx_findings_remediation', 'remediation_status'),
    )

    def __repr__(self):
        return f'<Finding {self.title}>'
