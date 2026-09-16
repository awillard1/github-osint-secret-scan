"""Explicit lifecycle and retained transition history."""
from alembic import op
import sqlalchemy as sa

revision = "20260911_0007"
down_revision = "20260911_0006"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("findings")}
    legacy = "lifecycle_state" not in columns
    additions = [
        sa.Column("lifecycle_state", sa.String(32), nullable=False, server_default="NEW"),
        sa.Column("remediated_at", sa.DateTime(timezone=True)),
        sa.Column("regressed_at", sa.DateTime(timezone=True)),
        sa.Column("regression_count", sa.Integer(), nullable=False, server_default="0"),
    ]
    for column in additions:
        if column.name not in columns:
            op.add_column("findings", column)
    if "ix_findings_lifecycle_state" not in {i["name"] for i in sa.inspect(bind).get_indexes("findings")}:
        op.create_index("ix_findings_lifecycle_state", "findings", ["lifecycle_state"])
    if "finding_history" not in sa.inspect(bind).get_table_names():
        op.create_table("finding_history",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
            sa.Column("from_state", sa.String(32)), sa.Column("to_state", sa.String(32), nullable=False),
            sa.Column("actor", sa.String(255), nullable=False), sa.Column("reason", sa.Text()),
            sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id")),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("metadata_json", sa.JSON(), nullable=False))
        op.create_index("ix_finding_history_finding_id", "finding_history", ["finding_id"])
    if legacy:
        findings = sa.Table("findings", sa.MetaData(), autoload_with=bind)
        history = sa.Table("finding_history", sa.MetaData(), autoload_with=bind)
        mapping = {"resolved": "REMEDIATED", "triaged": "REVIEWING", "suppressed": "SUPPRESSED", "accepted_risk": "ACCEPTED_RISK"}
        for row in bind.execute(sa.select(findings)).mappings():
            state = mapping.get(row["status"], "NEW")
            when = row["updated_at"] or row["last_seen_at"]
            bind.execute(findings.update().where(findings.c.id == row["id"]).values(
                lifecycle_state=state, remediated_at=when if state == "REMEDIATED" else None))
            bind.execute(history.insert().values(finding_id=row["id"], to_state=state, actor="migration",
                reason="Legacy status mapped; timestamp inferred from stored update time", occurred_at=when,
                metadata_json={"legacy_status": row["status"], "timestamp_inferred": True}))


def downgrade():
    op.drop_table("finding_history")
    op.drop_index("ix_findings_lifecycle_state", table_name="findings")
    with op.batch_alter_table("findings") as batch:
        for name in ("lifecycle_state", "remediated_at", "regressed_at", "regression_count"):
            batch.drop_column(name)
