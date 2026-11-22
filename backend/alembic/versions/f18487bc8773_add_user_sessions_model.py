"""add_user_sessions_model

Revision ID: f18487bc8773
Revises: 44575c92a1a9
Create Date: 2026-11-22 11:36:15.301833

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f18487bc8773'
down_revision: Union[str, None] = '44575c92a1a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create user_sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('device_name', sa.String(length=128), nullable=False),
        sa.Column('client_type', sa.String(length=32), server_default='web', nullable=False),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_active_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_sessions_is_active'), 'user_sessions', ['is_active'], unique=False)
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)

    # 2. Add session_id to refresh_tokens (nullable to preserve existing legacy refresh tokens)
    op.add_column('refresh_tokens', sa.Column('session_id', sa.String(length=36), nullable=True))
    op.create_index(op.f('ix_refresh_tokens_session_id'), 'refresh_tokens', ['session_id'], unique=False)
    op.create_foreign_key(
        'fk_refresh_tokens_session_id',
        'refresh_tokens',
        'user_sessions',
        ['session_id'],
        ['id'],
        ondelete='CASCADE'
    )


def downgrade() -> None:
    # 1. Remove foreign key, index, and column from refresh_tokens
    op.drop_constraint('fk_refresh_tokens_session_id', 'refresh_tokens', type_='foreignkey')
    op.drop_index(op.f('ix_refresh_tokens_session_id'), table_name='refresh_tokens')
    op.drop_column('refresh_tokens', 'session_id')

    # 2. Drop user_sessions indexes and table
    op.drop_index(op.f('ix_user_sessions_expires_at'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_is_active'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_table('user_sessions')
