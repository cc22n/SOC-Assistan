"""ioc_analyses.user_id: ON DELETE SET NULL

Revision ID: d3e5f7a9b1c2
Revises: c2d4e6f8a0b1
Create Date: 2026-11-13 20:10:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md).

`ioc_analyses.user_id` es nullable pero su FK a users.id no tenía ON DELETE, así que
en Postgres no se podía borrar un usuario que hubiera hecho análisis (violación de FK).
El análisis es un registro de inteligencia que debe sobrevivir al analista: pasa a
user_id NULL (huérfano) en vez de bloquear el borrado.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd3e5f7a9b1c2'
down_revision = 'c2d4e6f8a0b1'
branch_labels = None
depends_on = None

FK_NAME = 'ioc_analyses_user_id_fkey'


def upgrade():
    op.drop_constraint(FK_NAME, 'ioc_analyses', type_='foreignkey')
    op.create_foreign_key(FK_NAME, 'ioc_analyses', 'users', ['user_id'], ['id'], ondelete='SET NULL')


def downgrade():
    op.drop_constraint(FK_NAME, 'ioc_analyses', type_='foreignkey')
    op.create_foreign_key(FK_NAME, 'ioc_analyses', 'users', ['user_id'], ['id'])
