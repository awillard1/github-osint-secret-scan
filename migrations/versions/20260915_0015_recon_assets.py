"""Canonical recon assets, additive to the assessment control plane."""
from alembic import op
import sqlalchemy as sa
revision = '20260915_0015'
down_revision = '20260915_0014'
branch_labels = depends_on = None


def upgrade():
    op.create_table('recon_assets',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('organization_id',sa.Integer(),sa.ForeignKey('organizations.id'),nullable=False),
        sa.Column('kind',sa.String(32),nullable=False),
        sa.Column('identity',sa.String(64),nullable=False),
        sa.Column('name',sa.String(2048),nullable=False),
        sa.Column('metadata_json',sa.JSON(),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False),
        sa.UniqueConstraint('organization_id','kind','identity',name='uq_recon_asset_identity'))
    op.create_index('ix_recon_assets_organization_id','recon_assets',['organization_id'])
    op.create_index('ix_recon_assets_kind','recon_assets',['kind'])


def downgrade():
    op.drop_table('recon_assets')
