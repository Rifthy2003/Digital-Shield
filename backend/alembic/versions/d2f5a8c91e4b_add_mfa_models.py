"""add_mfa_models

Revision ID: d2f5a8c91e4b
Revises: c4d8e1f29a0b
Create Date: 2026-11-26 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d2f5a8c91e4b"
down_revision: Union[str, None] = "c4d8e1f29a0b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_user_cols = {col["name"] for col in inspector.get_columns("users")}
    existing_tables = set(inspector.get_table_names())

    cols_to_add: list[sa.Column] = []
    if "mfa_pending_secret_encrypted" not in existing_user_cols:
        cols_to_add.append(sa.Column("mfa_pending_secret_encrypted", sa.String(length=255), nullable=True))
    if "mfa_last_totp_step" not in existing_user_cols:
        cols_to_add.append(sa.Column("mfa_last_totp_step", sa.Integer(), nullable=True))

    if cols_to_add:
        with op.batch_alter_table("users") as batch_op:
            for col in cols_to_add:
                batch_op.add_column(col)

    if "mfa_recovery_codes" not in existing_tables:
        op.create_table(
            "mfa_recovery_codes",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("code_hash", sa.String(length=64), nullable=False),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"], unique=False)
        op.create_index("ix_mfa_recovery_codes_code_hash", "mfa_recovery_codes", ["code_hash"], unique=True)

    if "mfa_challenges" not in existing_tables:
        op.create_table(
            "mfa_challenges",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("challenge_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_mfa_challenges_user_id", "mfa_challenges", ["user_id"], unique=False)
        op.create_index("ix_mfa_challenges_challenge_hash", "mfa_challenges", ["challenge_hash"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())
    existing_user_cols = {col["name"] for col in inspector.get_columns("users")}

    if "mfa_challenges" in existing_tables:
        op.drop_index("ix_mfa_challenges_challenge_hash", table_name="mfa_challenges")
        op.drop_index("ix_mfa_challenges_user_id", table_name="mfa_challenges")
        op.drop_table("mfa_challenges")

    if "mfa_recovery_codes" in existing_tables:
        op.drop_index("ix_mfa_recovery_codes_code_hash", table_name="mfa_recovery_codes")
        op.drop_index("ix_mfa_recovery_codes_user_id", table_name="mfa_recovery_codes")
        op.drop_table("mfa_recovery_codes")

    cols_to_drop = [
        name for name in ("mfa_last_totp_step", "mfa_pending_secret_encrypted") if name in existing_user_cols
    ]
    if cols_to_drop:
        with op.batch_alter_table("users") as batch_op:
            for col_name in cols_to_drop:
                batch_op.drop_column(col_name)
