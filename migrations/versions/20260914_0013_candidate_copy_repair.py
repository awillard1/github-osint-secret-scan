"""Keyless repair of copied Phase 23 secrets; protected ciphertext stays intact."""
from alembic import op
import sqlalchemy as sa
from orgscan.migration_snapshots.phase24_repair import repair_values

revision = '20260914_0013'
down_revision = '20260914_0012'
branch_labels = depends_on = None


def upgrade():
    bind = op.get_bind()
    metadata = sa.MetaData()
    protected = sa.Table('secret_evidence', metadata, autoload_with=bind)
    finding = sa.Table('findings', metadata, autoload_with=bind)
    ids = sa.select(protected.c.finding_id)
    for name in ('findings', 'evidence', 'finding_history', 'risk_scores', 'suppressions', 'domain_exposures', 'relationships'):
        table = sa.Table(name, metadata, autoload_with=bind, extend_existing=True)
        if name == 'findings':
            affected = table.c.id.in_(ids)
        elif name == 'domain_exposures':
            affected = sa.exists(sa.select(finding.c.id).where(
                finding.c.id.in_(ids), finding.c.domain_id == table.c.domain_id,
                finding.c.normalized_hash == table.c.normalized_hash))
        elif name == 'relationships':
            finding_ids = sa.select(sa.cast(protected.c.finding_id, sa.String))
            affected = sa.or_(sa.and_(table.c.from_entity_type == 'finding', table.c.from_entity_id.in_(finding_ids)),
                              sa.and_(table.c.to_entity_type == 'finding', table.c.to_entity_id.in_(finding_ids)))
        else:
            affected = table.c.finding_id.in_(ids)
        last_id = 0
        while True:
            rows = bind.execute(sa.select(table).where(affected, table.c.id > last_id).order_by(table.c.id).limit(100)).mappings().all()
            if not rows:
                break
            for row in rows:
                changed = repair_values(row)
                if changed:
                    bind.execute(table.update().where(table.c.id == row['id']).values(**changed))
            last_id = rows[-1]['id']


def downgrade():
    # Irreversible ordinary-text repair; protected values and schema are unchanged.
    pass
