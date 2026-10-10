from datetime import datetime
from app.extensions import db


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    report_type = db.Column(db.String(10), nullable=False)
    report_path = db.Column(db.String(500), nullable=False)
    generated_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_reports_assessment', 'assessment_id'),
    )

    def __repr__(self):
        return f'<Report {self.report_type} for Assessment {self.assessment_id}>'
