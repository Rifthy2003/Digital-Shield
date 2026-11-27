"""add_oauth_state_platform

Revision ID: f3b7d2a84c1e
Revises: e1a9c3d47b2f
Create Date: 2026-11-26 23:42:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f3b7d2a84c1e"
down_revision: Union[str, None] = "e1a9c3d47b2f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {col["name"] for col in inspector.get_columns("oauth_states")}
    if "platform" not in existing_cols:
        with op.batch_alter_table("oauth_states") as batch_op:
            batch_op.add_column(
                sa.Column("platform", sa.String(length=16), nullable=False, server_default="web")
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {col["name"] for col in inspector.get_columns("oauth_states")}
    if "platform" in existing_cols:
        with op.batch_alter_table("oauth_states") as batch_op:
            batch_op.drop_column("platform")
