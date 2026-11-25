"""add_oauth_models

Revision ID: a7c3e9d14b2f
Revises: f18487bc8773
Create Date: 2026-11-25 15:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7c3e9d14b2f"
down_revision: Union[str, None] = "f18487bc8773"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=True),
        sa.Column("code_verifier_encrypted", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("used", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_oauth_states_user_id"), "oauth_states", ["user_id"], unique=False)
    op.create_index(op.f("ix_oauth_states_state_hash"), "oauth_states", ["state_hash"], unique=True)
    op.create_index(op.f("ix_oauth_states_expires_at"), "oauth_states", ["expires_at"], unique=False)

    op.create_table(
        "connected_accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("provider_email", sa.String(length=255), nullable=True),
        sa.Column("provider_email_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("avatar_url", sa.String(length=512), nullable=True),
        sa.Column("scopes", sa.String(length=512), server_default="", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "provider_user_id", name="uq_connected_accounts_provider_user"),
        sa.UniqueConstraint("user_id", "provider", "provider_user_id", name="uq_connected_accounts_user_provider_user"),
    )
    op.create_index(op.f("ix_connected_accounts_user_id"), "connected_accounts", ["user_id"], unique=False)
    op.create_index(op.f("ix_connected_accounts_provider"), "connected_accounts", ["provider"], unique=False)
    op.create_index(op.f("ix_connected_accounts_status"), "connected_accounts", ["status"], unique=False)
    op.create_index("ix_connected_accounts_user_provider", "connected_accounts", ["user_id", "provider"], unique=False)

    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("connected_account_id", sa.String(length=36), nullable=False),
        sa.Column("access_token_encrypted", sa.Text(), nullable=False),
        sa.Column("refresh_token_encrypted", sa.Text(), nullable=True),
        sa.Column("encryption_key_id", sa.String(length=64), nullable=False),
        sa.Column("token_type", sa.String(length=32), server_default="Bearer", nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["connected_account_id"], ["connected_accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_oauth_tokens_connected_account_id"), "oauth_tokens", ["connected_account_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_oauth_tokens_connected_account_id"), table_name="oauth_tokens")
    op.drop_table("oauth_tokens")

    op.drop_index("ix_connected_accounts_user_provider", table_name="connected_accounts")
    op.drop_index(op.f("ix_connected_accounts_status"), table_name="connected_accounts")
    op.drop_index(op.f("ix_connected_accounts_provider"), table_name="connected_accounts")
    op.drop_index(op.f("ix_connected_accounts_user_id"), table_name="connected_accounts")
    op.drop_table("connected_accounts")

    op.drop_index(op.f("ix_oauth_states_expires_at"), table_name="oauth_states")
    op.drop_index(op.f("ix_oauth_states_state_hash"), table_name="oauth_states")
    op.drop_index(op.f("ix_oauth_states_user_id"), table_name="oauth_states")
    op.drop_table("oauth_states")
