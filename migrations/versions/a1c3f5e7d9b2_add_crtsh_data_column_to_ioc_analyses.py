"""add crtsh_data column to ioc_analyses

Revision ID: a1c3f5e7d9b2
Revises: 36d3e8d1847f
Create Date: 2026-07-21 00:05:00.000000

Migración escrita a mano (NO autogenerate): `flask db migrate` sobre este
proyecto arrastra drift preexistente entre la baseline y la BD real (borra
índices GIN legítimos, baja JSONB a JSON en tablas mitre_*, etc. — ver
CLAUDE.md, "autogenerate no ordena bien..."). Este archivo solo agrega la
columna `crtsh_data` (API crt.sh, Certificate Transparency), sin tocar nada
más de ese drift.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'a1c3f5e7d9b2'
down_revision = '36d3e8d1847f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'ioc_analyses',
        sa.Column('crtsh_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )


def downgrade():
    op.drop_column('ioc_analyses', 'crtsh_data')
