"""add_mfa_pending_expires_at

Revision ID: e1a9c3d47b2f
Revises: d2f5a8c91e4b
Create Date: 2026-11-26 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e1a9c3d47b2f"
down_revision: Union[str, None] = "d2f5a8c91e4b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_user_cols = {col["name"] for col in inspector.get_columns("users")}
    if "mfa_pending_expires_at" not in existing_user_cols:
        with op.batch_alter_table("users") as batch_op:
            batch_op.add_column(sa.Column("mfa_pending_expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_user_cols = {col["name"] for col in inspector.get_columns("users")}
    if "mfa_pending_expires_at" in existing_user_cols:
        with op.batch_alter_table("users") as batch_op:
            batch_op.drop_column("mfa_pending_expires_at")
