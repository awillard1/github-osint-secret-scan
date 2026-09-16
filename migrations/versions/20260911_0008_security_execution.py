"""Durable queue execution identities and legacy evidence sanitization."""
import uuid
from datetime import UTC, datetime
from alembic import op
import sqlalchemy as sa

revision = '20260911_0008'
down_revision = '20260911_0007'
branch_labels = depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'queue_execution_key' not in {c['name'] for c in inspector.get_columns('scheduled_scans')}:
        op.add_column('scheduled_scans', sa.Column('queue_execution_key',sa.String(64),nullable=True))
    if 'execution_key' not in {c['name'] for c in inspector.get_columns('queue_tasks')}:
        op.add_column('queue_tasks',sa.Column('execution_key',sa.String(64),nullable=True))
        op.create_index('ix_queue_tasks_execution_key','queue_tasks',['execution_key'],unique=True)
    tasks = sa.Table('queue_tasks',sa.MetaData(),autoload_with=bind)
    schedules = sa.Table('scheduled_scans',sa.MetaData(),autoload_with=bind)
    active = {}
    for row in bind.execute(sa.select(tasks).order_by(tasks.c.id)).mappings():
        key = row['execution_key'] or uuid.uuid4().hex
        bind.execute(tasks.update().where(tasks.c.id==row['id']).values(execution_key=key))
        if row['status'] in {'queued','running'}:
            if row['scheduled_scan_id'] in active:
                bind.execute(tasks.update().where(tasks.c.id==row['id']).values(
                    status='failed',last_error='Duplicate legacy execution quarantined during upgrade'))
            else:
                active[row['scheduled_scan_id']] = key
    for row in bind.execute(sa.select(schedules)).mappings():
        metadata = row['metadata_json'] or {}
        key = active.get(row['id'])
        if not key and metadata.get('queue_backend') == 'rq' and metadata.get('queue_status') in {'queued','running'}:
            # Existing Redis messages retain their job ID; do not publish a new identity.
            key = metadata.get('queue_job_id') or uuid.uuid4().hex
            now = datetime.now(UTC)
            bind.execute(tasks.insert().values(scheduled_scan_id=row['id'],backend='rq',
                queue_name=metadata.get('queue_name') or 'orgscan:scans',execution_key=key,
                status=metadata['queue_status'],attempt_count=0,max_attempts=3,available_at=now,
                metadata_json={'published':True},created_at=now,updated_at=now))
        if key:
            bind.execute(schedules.update().where(schedules.c.id==row['id']).values(queue_execution_key=key))
    # Historical source bodies and diagnostics were never required for canonical identity.
    from orgscan.migration_snapshots.phase17_redaction import redact
    for table_name in ('findings','evidence','domain_exposures','identity_correlations','relationships','finding_history','tool_runs','scan_jobs'):
        table = sa.Table(table_name,sa.MetaData(),autoload_with=bind)
        fields = set(table.c.keys()) & {'title','description','raw_payload','metadata_json','snippet',
            'extracted_indicator','source_url','triage_notes','reason','evidence_summary','remediation_hint',
            'stdout_log','stderr_log','error_message'}
        for row in bind.execute(sa.select(table)).mappings():
            values = redact({name:row[name] for name in fields})
            for name in ('stdout_log','stderr_log','error_message'):
                if values.get(name):
                    values[name] = 'Legacy diagnostic omitted during security upgrade'
            if values:
                bind.execute(table.update().where(table.c.id==row['id']).values(**values))


def downgrade():
    op.drop_index('ix_queue_tasks_execution_key',table_name='queue_tasks')
    with op.batch_alter_table('queue_tasks') as batch:
        batch.drop_column('execution_key')
    with op.batch_alter_table('scheduled_scans') as batch:
        batch.drop_column('queue_execution_key')
    # Redaction is intentionally irreversible.
