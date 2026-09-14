"""Preserve scanner provenance and deduplicate new scanner observations."""
from alembic import op
import sqlalchemy as sa

revision = "20260911_0006"
down_revision = "20260909_0005"
branch_labels = None
depends_on = None


def upgrade():
    # The initial migration creates current model metadata on fresh databases.
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("evidence")}
    if "metadata_json" not in columns:
        op.add_column("evidence", sa.Column(
            "metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"),
        ))
    if "observation_fingerprint" not in columns:
        op.add_column("evidence", sa.Column("observation_fingerprint", sa.String(64), nullable=True))
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("evidence")}
    if "ix_evidence_observation_fingerprint" not in indexes:
        op.create_index("ix_evidence_observation_fingerprint", "evidence", ["observation_fingerprint"], unique=True)


def downgrade():
    op.drop_index("ix_evidence_observation_fingerprint", table_name="evidence")
    with op.batch_alter_table("evidence") as batch:
        batch.drop_column("observation_fingerprint")
        batch.drop_column("metadata_json")
