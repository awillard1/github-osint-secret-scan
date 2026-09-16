"""Forward repair of escaped/copied credential assignments (irreversible)."""
from alembic import op
import sqlalchemy as sa
from orgscan.migration_snapshots.phase22_redaction import redact

revision = '20260914_0011'
down_revision = '20260914_0010'
branch_labels = depends_on = None

TABLES = ('organizations', 'repositories', 'domains', 'accounts', 'findings', 'evidence',
          'domain_exposures', 'identity_correlations', 'relationships', 'finding_history',
          'scan_jobs', 'tool_runs', 'risk_scores', 'suppressions', 'scheduled_reports', 'queue_tasks')


def upgrade():
    bind = op.get_bind()
    # Keyset batches bound migration buffering; no values are logged. Authentication
    # tables and operational webhook credentials are intentionally not evidence.
    for name in TABLES:
        table = sa.Table(name, sa.MetaData(), autoload_with=bind)
        last_id = 0
        while True:
            rows = bind.execute(sa.select(table).where(table.c.id > last_id).order_by(table.c.id).limit(250)).mappings().all()
            if not rows:
                break
            for row in rows:
                values = {key: val for key, val in row.items() if isinstance(val, (str, dict, list)) and key != 'webhook_url'}
                cleaned = redact(values, preserve_root_keys=True)
                changed = {key: val for key, val in cleaned.items() if val != values[key]}
                if changed:
                    bind.execute(table.update().where(table.c.id == row['id']).values(**changed))
            last_id = rows[-1]['id']


def downgrade():
    # Relationships/schema are unchanged; removed credentials cannot be restored.
    pass
