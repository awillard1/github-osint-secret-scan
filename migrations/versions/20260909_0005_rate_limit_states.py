from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260909_0005"
down_revision = "20260909_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "rate_limit_states" not in tables:
        op.create_table(
            "rate_limit_states",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scope", sa.String(length=255), nullable=False),
            sa.Column("backend", sa.String(length=32), nullable=False, server_default="db"),
            sa.Column("requests_per_minute", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("min_interval_seconds", sa.Float(), nullable=False, server_default="0"),
            sa.Column("window_seconds", sa.Float(), nullable=False, server_default="0"),
            sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_request_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_allowed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_rate_limit_states_scope", "rate_limit_states", ["scope"], unique=True)
        op.create_index("ix_rate_limit_states_backend", "rate_limit_states", ["backend"])
        op.create_index("ix_rate_limit_states_next_allowed_at", "rate_limit_states", ["next_allowed_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "rate_limit_states" in tables:
        op.drop_index("ix_rate_limit_states_next_allowed_at", table_name="rate_limit_states")
        op.drop_index("ix_rate_limit_states_backend", table_name="rate_limit_states")
        op.drop_index("ix_rate_limit_states_scope", table_name="rate_limit_states")
        op.drop_table("rate_limit_states")
