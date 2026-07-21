"""drop tablas y vista huerfanas sin uso en codigo

Revision ID: 36d3e8d1847f
Revises: b9a306dbac54
Create Date: 2026-07-20 23:17:02.256859

chat_conversations, user_preferences y la vista v_active_sessions existian
en soc_agent (dev) sin ningun SQLAlchemy model ni referencia en el codigo
de la app -- confirmado con grep, y las dos tablas estaban vacias (0 filas).
v_active_sessions viene de migrations/add_investigation_sessions.sql (ver
migrations/LEGACY_SQL.md), que se corrio a mano contra dev en algun momento
pero nunca contra test/CI. Usa IF EXISTS/IF NOT EXISTS en ambas direcciones
para ser un no-op seguro en soc_agent_test y CI, que nunca tuvieron estos
objetos.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '36d3e8d1847f'
down_revision = 'b9a306dbac54'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('DROP VIEW IF EXISTS v_active_sessions')
    op.execute('DROP TABLE IF EXISTS chat_conversations')
    op.execute('DROP TABLE IF EXISTS user_preferences')


def downgrade():
    op.create_table('chat_conversations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', postgresql.UUID(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('messages', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('analyses_performed', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('user_preferences',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('preferred_llm', sa.String(), nullable=True),
    sa.Column('preferred_sources', postgresql.ARRAY(sa.String()), nullable=True),
    sa.Column('auto_incident_threshold', sa.Integer(), nullable=True),
    sa.Column('notification_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ui_preferences', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )

    op.execute("""
        CREATE OR REPLACE VIEW v_active_sessions AS
        SELECT s.id, s.uuid, s.user_id, u.username, s.title, s.status,
               s.total_iocs, s.total_messages, s.highest_risk_level,
               s.created_at, s.last_activity_at,
               EXTRACT(EPOCH FROM (NOW() - s.last_activity_at))/3600 AS hours_inactive,
               s.auto_close_hours - EXTRACT(EPOCH FROM (NOW() - s.last_activity_at))/3600 AS hours_until_auto_close
        FROM investigation_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.status = 'active'
    """)
