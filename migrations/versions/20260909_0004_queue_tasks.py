from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260909_0004"
down_revision = "20260909_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "queue_tasks" not in tables:
        op.create_table(
            "queue_tasks",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scheduled_scan_id", sa.Integer(), sa.ForeignKey("scheduled_scans.id"), nullable=False),
            sa.Column("backend", sa.String(length=32), nullable=False, server_default="db"),
            sa.Column("queue_name", sa.String(length=255), nullable=False, server_default="orgscan:db"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("lease_owner", sa.String(length=255), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("result_scan_job_id", sa.Integer(), nullable=True),
            sa.Column("result_tool_run_id", sa.Integer(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_queue_tasks_scheduled_scan_id", "queue_tasks", ["scheduled_scan_id"])
        op.create_index("ix_queue_tasks_backend", "queue_tasks", ["backend"])
        op.create_index("ix_queue_tasks_status", "queue_tasks", ["status"])
        op.create_index("ix_queue_tasks_available_at", "queue_tasks", ["available_at"])
        op.create_index("ix_queue_tasks_lease_owner", "queue_tasks", ["lease_owner"])
        op.create_index("ix_queue_tasks_lease_expires_at", "queue_tasks", ["lease_expires_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "queue_tasks" in tables:
        op.drop_index("ix_queue_tasks_lease_expires_at", table_name="queue_tasks")
        op.drop_index("ix_queue_tasks_lease_owner", table_name="queue_tasks")
        op.drop_index("ix_queue_tasks_available_at", table_name="queue_tasks")
        op.drop_index("ix_queue_tasks_status", table_name="queue_tasks")
        op.drop_index("ix_queue_tasks_backend", table_name="queue_tasks")
        op.drop_index("ix_queue_tasks_scheduled_scan_id", table_name="queue_tasks")
        op.drop_table("queue_tasks")
