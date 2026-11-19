"""investigation_profiles + ioc_analyses.profile_id

Revision ID: e4f6a8b0c2d3
Revises: d3e5f7a9b1c2
Create Date: 2026-11-18 23:30:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md: el drift de la baseline arrastraría decenas de cambios).

* Tabla `investigation_profiles` (consultas repetibles definidas por el analista; WP2 de PLAN-FUSION).
* `ioc_analyses.from_profile` (bool) + `profile_id` (nullable, ON DELETE SET NULL): marcan los análisis hechos con un
  perfil. La caché los usa para que un análisis NORMAL nunca se sirva desde una ejecución parcial (subconjunto de
  APIs). `from_profile` existe porque profile_id pasa a NULL al borrar el perfil y no debe "convertir" esos
  análisis parciales en completos.
* Los perfiles del sistema NO se siembran aquí: los crea `ensure_system_profiles()` (una sola fuente de verdad, en
  app/services/profile_service.py) tras `upgrade()`.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e4f6a8b0c2d3'
down_revision = 'd3e5f7a9b1c2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'investigation_profiles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('owner_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('ioc_type', sa.String(length=20), nullable=False),
        sa.Column('apis', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('llm_synthesis', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('is_system', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_investigation_profiles_owner_id', 'investigation_profiles', ['owner_id'])
    op.create_index('ix_investigation_profiles_ioc_type', 'investigation_profiles', ['ioc_type'])
    op.execute(
        "CREATE UNIQUE INDEX uq_investigation_profile_owner_name "
        "ON investigation_profiles (coalesce(owner_id, 0), lower(name))"
    )

    op.add_column('ioc_analyses', sa.Column('from_profile', sa.Boolean(), nullable=False,
                                            server_default=sa.false()))
    op.add_column('ioc_analyses', sa.Column('profile_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_ioc_analyses_profile_id', 'ioc_analyses', 'investigation_profiles',
                          ['profile_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_ioc_analyses_profile_id', 'ioc_analyses', ['profile_id'])


def downgrade():
    op.drop_index('ix_ioc_analyses_profile_id', table_name='ioc_analyses')
    op.drop_constraint('fk_ioc_analyses_profile_id', 'ioc_analyses', type_='foreignkey')
    op.drop_column('ioc_analyses', 'profile_id')
    op.drop_column('ioc_analyses', 'from_profile')
    op.execute('DROP INDEX IF EXISTS uq_investigation_profile_owner_name')
    op.drop_index('ix_investigation_profiles_ioc_type', table_name='investigation_profiles')
    op.drop_index('ix_investigation_profiles_owner_id', table_name='investigation_profiles')
    op.drop_table('investigation_profiles')
