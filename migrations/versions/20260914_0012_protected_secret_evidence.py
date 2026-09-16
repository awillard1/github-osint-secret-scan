"""Dedicated encrypted secret evidence and audited reveal; prior data is not recovered."""
from alembic import op
import sqlalchemy as sa
revision = '20260914_0012'
down_revision = '20260914_0011'
branch_labels = depends_on = None


def upgrade():
    op.create_table('secret_evidence',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('evidence_id', sa.Integer(), sa.ForeignKey('evidence.id')),
        sa.Column('tenant_key', sa.String(255), nullable=False),
        sa.Column('secret_type', sa.String(128), nullable=False),
        sa.Column('redacted_display', sa.String(64), nullable=False),
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column('key_id', sa.String(64), nullable=False),
        sa.Column('encrypted_value', sa.LargeBinary(), nullable=False),
        sa.Column('nonce', sa.LargeBinary(), nullable=False),
        sa.Column('source', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('finding_id','fingerprint','key_id',name='uq_secret_finding_fingerprint_key'))
    op.create_index('ix_secret_evidence_finding_id','secret_evidence',['finding_id'])
    op.create_index('ix_secret_evidence_tenant_key','secret_evidence',['tenant_key'])
    op.create_table('secret_reveal_audit',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id')),
        sa.Column('principal', sa.String(255), nullable=False),
        sa.Column('tenant_key', sa.String(255), nullable=False),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('secret_evidence_id', sa.Integer(), sa.ForeignKey('secret_evidence.id'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_secret_reveal_audit_tenant_key','secret_reveal_audit',['tenant_key'])


def downgrade():
    op.drop_table('secret_reveal_audit')
    op.drop_table('secret_evidence')
