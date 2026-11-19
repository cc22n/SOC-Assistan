"""investigation_profiles.owner_id: ON DELETE CASCADE (antes SET NULL)

Revision ID: b7c9d1e3f5a6
Revises: a6b8c0d2e4f5
Create Date: 2026-11-19 18:00:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md). Hallazgo F1 de la auditoría del 2026-11-19, reproducido: con
`SET NULL`, al borrar un usuario sus perfiles pasaban a owner NULL, el mismo "cubo" que los perfiles del sistema en el índice
único (coalesce(owner_id, 0), lower(name)). Dos usuarios con un perfil del mismo nombre hacían fallar el borrado del segundo
con UniqueViolation. Un perfil de usuario ahora se borra CON el usuario; los perfiles del sistema (owner NULL) no se tocan.
Los análisis hechos con el perfil se conservan: ioc_analyses.profile_id sigue siendo ON DELETE SET NULL y `from_profile`
sigue marcándolos como parciales.
"""
from alembic import op

revision = 'b7c9d1e3f5a6'
down_revision = 'a6b8c0d2e4f5'
branch_labels = None
depends_on = None

FK = 'investigation_profiles_owner_id_fkey'


def upgrade():
    op.drop_constraint(FK, 'investigation_profiles', type_='foreignkey')
    op.create_foreign_key(FK, 'investigation_profiles', 'users', ['owner_id'], ['id'], ondelete='CASCADE')


def downgrade():
    op.drop_constraint(FK, 'investigation_profiles', type_='foreignkey')
    op.create_foreign_key(FK, 'investigation_profiles', 'users', ['owner_id'], ['id'], ondelete='SET NULL')
