"""add_org_slug_active_fields

Revision ID: c4d8e1f29a0b
Revises: b9e4f2a18c3d
Create Date: 2026-11-26 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4d8e1f29a0b"
down_revision: Union[str, None] = "b9e4f2a18c3d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("slug", sa.String(length=128), nullable=True))
    op.add_column("organizations", sa.Column("created_by", sa.String(length=36), nullable=True))
    op.add_column(
        "organizations",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.execute("UPDATE organizations SET slug = id WHERE slug IS NULL")

    with op.batch_alter_table("organizations") as batch_op:
        batch_op.alter_column("slug", existing_type=sa.String(length=128), nullable=False)
        batch_op.alter_column("primary_domain", existing_type=sa.String(length=255), nullable=True)
        batch_op.create_foreign_key(
            "fk_organizations_created_by",
            "users",
            ["created_by"],
            ["id"],
            ondelete="SET NULL",
        )

    op.create_index(op.f("ix_organizations_slug"), "organizations", ["slug"], unique=True)
    op.create_index(op.f("ix_organizations_created_by"), "organizations", ["created_by"], unique=False)
    op.create_index(op.f("ix_organizations_is_active"), "organizations", ["is_active"], unique=False)

    op.add_column(
        "organization_memberships",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column(
        "organization_memberships",
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(
        op.f("ix_organization_memberships_is_active"),
        "organization_memberships",
        ["is_active"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_organization_memberships_is_active"), table_name="organization_memberships")
    op.drop_column("organization_memberships", "updated_at")
    op.drop_column("organization_memberships", "is_active")

    op.drop_index(op.f("ix_organizations_is_active"), table_name="organizations")
    op.drop_index(op.f("ix_organizations_created_by"), table_name="organizations")
    op.drop_index(op.f("ix_organizations_slug"), table_name="organizations")
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_constraint("fk_organizations_created_by", type_="foreignkey")
        batch_op.drop_column("is_active")
        batch_op.drop_column("created_by")
        batch_op.drop_column("slug")
