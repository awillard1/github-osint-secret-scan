from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260909_0003"
down_revision = "20260909_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("username", sa.String(length=255), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=True),
            sa.Column("display_name", sa.String(length=255), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_users_username", "users", ["username"], unique=True)
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    if "user_tenant_memberships" not in tables:
        op.create_table(
            "user_tenant_memberships",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("tenant_key", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="reader"),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_id", "tenant_key", name="uq_user_tenant_membership"),
        )
        op.create_index("ix_user_tenant_memberships_user_id", "user_tenant_memberships", ["user_id"])
        op.create_index("ix_user_tenant_memberships_tenant_key", "user_tenant_memberships", ["tenant_key"])

    if "user_sessions" not in tables:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("session_name", sa.String(length=255), nullable=True),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="reader"),
            sa.Column("tenant_scopes_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
        op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "user_sessions" in tables:
        op.drop_index("ix_user_sessions_token_hash", table_name="user_sessions")
        op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
        op.drop_table("user_sessions")
    if "user_tenant_memberships" in tables:
        op.drop_index("ix_user_tenant_memberships_tenant_key", table_name="user_tenant_memberships")
        op.drop_index("ix_user_tenant_memberships_user_id", table_name="user_tenant_memberships")
        op.drop_table("user_tenant_memberships")
    if "users" in tables:
        op.drop_index("ix_users_email", table_name="users")
        op.drop_index("ix_users_username", table_name="users")
        op.drop_table("users")
