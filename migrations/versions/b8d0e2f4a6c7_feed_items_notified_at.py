"""feed_items.notified_at: marca de "ya avisado por Telegram"

Revision ID: b8d0e2f4a6c7
Revises: b7c9d1e3f5a6
Create Date: 2026-11-20 20:00:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md). WP7 de PLAN-FUSION (avisos salientes por Telegram).

`notified_at` NULL = pendiente de avisar. Se rellena SOLO tras un envío correcto (si Telegram falla el CVE sigue pendiente y se
reintenta); un CVE ya conocido que se escala a KEV vuelve a NULL para avisar otra vez. Nullable y sin default: las filas
existentes quedan "pendientes", pero el notificador solo mira lo actualizado en los últimos días (no inunda con el histórico).
"""
from alembic import op
import sqlalchemy as sa

revision = 'b8d0e2f4a6c7'
down_revision = 'b7c9d1e3f5a6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('feed_items', sa.Column('notified_at', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('feed_items', 'notified_at')
