from datetime import datetime

from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<AuditLog {self.event}>'


def log_event(event, detail=''):
    try:
        db.session.add(AuditLog(event=event, detail=str(detail)[:1000]))
        db.session.commit()
    except Exception:
        db.session.rollback()
