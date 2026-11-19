"""ioc_analyses: columnas de las APIs de CVE (nvd, cisa_kev, epss, exploitdb)

Revision ID: f5a7b9c1d3e4
Revises: e4f6a8b0c2d3
Create Date: 2026-11-19 01:30:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md). WP3 de PLAN-FUSION: los CVE son un tipo de IOC nuevo
('cve', la columna ioc_type es String(20), no hace falta cambiarla) y cada fuente sigue la convención del proyecto:
una columna `<api>_data`. Todas JSONB y nullable: solo se rellenan para IOCs de tipo 'cve'.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'f5a7b9c1d3e4'
down_revision = 'e4f6a8b0c2d3'
branch_labels = None
depends_on = None

COLUMNS = ('nvd_data', 'cisa_kev_data', 'epss_data', 'exploitdb_data')


def upgrade():
    for c in COLUMNS:
        op.add_column('ioc_analyses', sa.Column(c, postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade():
    for c in reversed(COLUMNS):
        op.drop_column('ioc_analyses', c)
