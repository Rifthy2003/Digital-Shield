from fastapi import Request
from sqlalchemy.orm import Session

from app.core.client_ip import resolve_client_ip
from app.core.security import hash_ip
from app.models.audit_log import AuditLog


def record_audit_event(
    db: Session,
    actor_id: str | None,
    action: str,
    resource: str | None = None,
    details: dict | None = None,
    ip_hash: str | None = None,
    request: Request | None = None,
) -> None:
    """
    Writes one audit entry. Never pass secrets, tokens, or passwords into
    `details` — this table is append-only and readable by admins.
    """
    if ip_hash is None and request is not None:
        ip_hash = hash_ip(resolve_client_ip(request))

    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource=resource,
        details=details or {},
        ip_hash=ip_hash,
    )
    db.add(entry)
    db.commit()
