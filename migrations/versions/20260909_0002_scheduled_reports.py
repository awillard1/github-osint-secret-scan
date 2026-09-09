from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260909_0002"
down_revision = "20260909_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scheduled_reports" in inspector.get_table_names():
        return
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_type", sa.String(length=64), nullable=False, server_default="global"),
        sa.Column("target_value", sa.String(length=255), nullable=True),
        sa.Column("output_format", sa.String(length=32), nullable=False, server_default="json"),
        sa.Column("cadence", sa.String(length=32), nullable=False, server_default="daily"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("output_path", sa.String(length=1024), nullable=True),
        sa.Column("webhook_url", sa.String(length=1024), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scheduled_reports_target_type", "scheduled_reports", ["target_type"])
    op.create_index("ix_scheduled_reports_target_value", "scheduled_reports", ["target_value"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scheduled_reports" not in inspector.get_table_names():
        return
    op.drop_index("ix_scheduled_reports_target_value", table_name="scheduled_reports")
    op.drop_index("ix_scheduled_reports_target_type", table_name="scheduled_reports")
    op.drop_table("scheduled_reports")
