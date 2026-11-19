"""feeds proactivos: tech_stack_entries, feed_items, feed_runs

Revision ID: a6b8c0d2e4f5
Revises: f5a7b9c1d3e4
Create Date: 2026-11-19 03:00:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md). WP6 de PLAN-FUSION.

* `feed_items`: UN registro por CVE (UNIQUE cve_id), no por fuente: un CVE ya conocido que entra después en KEV se escala.
* `tech_stack_entries`: el stack declarado. Índice único por expresión (vendor y producto sin distinguir mayúsculas; un
  vendor/producto ausente cuenta como cadena vacía).
* `feed_runs`: bitácora de ejecuciones (de ahí sale cuándo corrió por última vez cada fuente: sobrevive a un reinicio).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a6b8c0d2e4f5'
down_revision = 'f5a7b9c1d3e4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'tech_stack_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('vendor', sa.String(length=120), nullable=True),
        sa.Column('product', sa.String(length=120), nullable=True),
        sa.Column('note', sa.String(length=300), nullable=False, server_default=''),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.execute("CREATE UNIQUE INDEX uq_tech_stack_vendor_product ON tech_stack_entries "
               "(lower(coalesce(vendor, '')), lower(coalesce(product, '')))")

    op.create_table(
        'feed_items',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('cve_id', sa.String(length=30), nullable=False, unique=True),
        sa.Column('title', sa.String(length=300), nullable=False, server_default=''),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('sources', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('affected', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('in_kev', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('kev_date_added', sa.Date(), nullable=True),
        sa.Column('known_ransomware', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('epss', sa.Float(), nullable=True),
        sa.Column('priority_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_level', sa.String(length=20), nullable=False, server_default='BAJO'),
        sa.Column('is_relevant', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('matched_entries', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('escalated_at', sa.DateTime(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_feed_items_published_at', 'feed_items', ['published_at'])
    op.create_index('ix_feed_items_risk_level', 'feed_items', ['risk_level'])
    op.create_index('ix_feed_items_is_relevant', 'feed_items', ['is_relevant'])
    op.create_index('ix_feed_items_first_seen_at', 'feed_items', ['first_seen_at'])

    op.create_table(
        'feed_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=10), nullable=False, server_default='running'),
        sa.Column('fetched', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('new_items', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('updated_items', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('relevant_new', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error', sa.String(length=500), nullable=True),
    )
    op.create_index('ix_feed_runs_source', 'feed_runs', ['source'])
    op.create_index('ix_feed_runs_started_at', 'feed_runs', ['started_at'])


def downgrade():
    op.drop_table('feed_runs')
    op.drop_table('feed_items')
    op.execute('DROP INDEX IF EXISTS uq_tech_stack_vendor_product')
    op.drop_table('tech_stack_entries')
