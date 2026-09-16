"""Separate global DNS identity from stable private domain associations.

No private row or referencing ID is merged, moved or deleted. Ambiguous normalized
associations stop before DDL for explicit operator reconciliation on a backup.
"""
import re
from alembic import op
import sqlalchemy as sa

revision = '20260916_0016'
down_revision = '20260915_0015'
branch_labels = depends_on = None


def normalized(value):
    try:
        name = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, AttributeError):
        raise RuntimeError('Domain migration requires identity reconciliation') from None
    if not name or len(name) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in name.split('.')):
        raise RuntimeError('Domain migration requires identity reconciliation')
    return name


def upgrade():
    bind = op.get_bind()
    # Frozen schema inputs; do not import application models or normalization.
    domains = sa.table('domains', sa.column('id', sa.Integer()), sa.column('name', sa.String()), sa.column('organization_id', sa.Integer()))
    orgs = sa.table('organizations', sa.column('id', sa.Integer()), sa.column('tenant_key', sa.String()))
    seen = set()
    # Preflight before schema mutation. Only IDs appear in conflict diagnostics.
    for row in bind.execute(sa.select(domains.c.id, domains.c.name, domains.c.organization_id, orgs.c.tenant_key).select_from(domains.outerjoin(orgs, domains.c.organization_id == orgs.c.id))).mappings():
        if len(seen) >= 1000000:
            raise RuntimeError('Domain migration preflight limit reached; explicit partitioned migration review required')
        key = (row['tenant_key'], normalized(row['name']))
        if key in seen:
            raise RuntimeError('Domain migration needs explicit duplicate-association reconciliation; row ID '+str(row['id']))
        seen.add(key)
    op.create_table('domain_identities', sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('normalized_name', sa.String(255), nullable=False, unique=True))
    op.add_column('domains', sa.Column('identity_id', sa.Integer(), nullable=True))
    op.add_column('domains', sa.Column('tenant_key', sa.String(255), nullable=True))
    identities = sa.table('domain_identities', sa.column('id', sa.Integer()), sa.column('normalized_name', sa.String()))
    updated = sa.table('domains', sa.column('id', sa.Integer()), sa.column('identity_id', sa.Integer()), sa.column('tenant_key', sa.String()), sa.column('name', sa.String()))
    op.drop_index('ix_domains_name', table_name='domains')
    names = {}
    for row in bind.execute(sa.select(domains.c.id, domains.c.name, orgs.c.tenant_key).select_from(domains.outerjoin(orgs, domains.c.organization_id == orgs.c.id))).mappings():
        name = normalized(row['name'])
        if name not in names:
            bind.execute(identities.insert().values(normalized_name=name))
            names[name] = bind.scalar(sa.select(identities.c.id).where(identities.c.normalized_name == name))
        bind.execute(updated.update().where(updated.c.id == row['id']).values(identity_id=names[name], tenant_key=row['tenant_key'], name=name))
    with op.batch_alter_table('domains') as batch:
        batch.alter_column('identity_id', existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key('fk_domains_identity', 'domain_identities', ['identity_id'], ['id'])
        batch.create_unique_constraint('uq_domain_tenant_identity', ['tenant_key', 'identity_id'])
    op.create_index('ix_domains_name', 'domains', ['name'])
    op.create_index('ix_domains_tenant_key', 'domains', ['tenant_key'])
    op.create_index('uq_domain_legacy_identity', 'domains', ['identity_id'], unique=True,
                    sqlite_where=sa.text('tenant_key IS NULL'), postgresql_where=sa.text('tenant_key IS NULL'))


def downgrade():
    raise RuntimeError('Domain identity downgrade would collapse tenant ownership; restore a verified backup instead')
