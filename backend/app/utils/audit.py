from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def record_audit_event(
    db: Session,
    actor_id: str | None,
    action: str,
    resource: str | None = None,
    details: dict | None = None,
    ip_hash: str | None = None,
) -> None:
    """
    Writes one audit entry. Never pass secrets, tokens, or passwords into
    `details` — this table is append-only and readable by admins.
    """
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource=resource,
        details=details or {},
        ip_hash=ip_hash,
    )
    db.add(entry)
    db.commit()
