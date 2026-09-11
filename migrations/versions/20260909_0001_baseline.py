from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from orgscan.models import Base

revision = "20260909_0001"
down_revision = None
branch_labels = None
depends_on = None


def _add_column_if_missing(table_name: str, column: sa.Column[object]) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {entry["name"] for entry in inspector.get_columns(table_name)}
    if column.name not in existing_columns:
        op.add_column(table_name, column)


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    for table_name, column in (
        ("organizations", sa.Column("tenant_key", sa.String(length=255), nullable=True)),
        ("repositories", sa.Column("mirror_path", sa.String(length=1024), nullable=True)),
        ("repositories", sa.Column("last_mirrored_at", sa.DateTime(timezone=True), nullable=True)),
        ("scan_jobs", sa.Column("target_ref", sa.String(length=255), nullable=True)),
        ("scan_jobs", sa.Column("scope_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))),
        ("findings", sa.Column("triage_owner", sa.String(length=255), nullable=True)),
        ("findings", sa.Column("triage_notes", sa.Text(), nullable=True)),
        ("findings", sa.Column("remediation_due_date", sa.Date(), nullable=True)),
        ("evidence", sa.Column("ref_name", sa.String(length=255), nullable=True)),
        ("relationships", sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))),
        ("tool_runs", sa.Column("artifact_type", sa.String(length=64), nullable=True)),
        ("tool_runs", sa.Column("artifact_path", sa.String(length=1024), nullable=True)),
    ):
        _add_column_if_missing(table_name, column)

    bind.execute(sa.text("UPDATE scan_jobs SET scope_json = '{}' WHERE scope_json IS NULL"))
    bind.execute(sa.text("UPDATE relationships SET metadata_json = '{}' WHERE metadata_json IS NULL"))


def downgrade() -> None:
    pass
