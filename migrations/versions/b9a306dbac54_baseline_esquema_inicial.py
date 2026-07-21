"""baseline: esquema inicial

Revision ID: b9a306dbac54
Revises:
Create Date: 2026-07-20 22:22:20.313180

Generado con autogenerate contra una BD vacia y reordenado a mano: el
resultado crudo de `flask db migrate` no respeta el orden topologico de las
FK entre tablas (SAWarning: unresolvable cycles between "incidents,
investigation_sessions" hace que Alembic renuncie a ordenar TODO el grafo,
no solo el ciclo). db.create_all() lo tolera porque SQLAlchemy resuelve
ciclos con su propio sorter y aplica las FK problematicas via ALTER
despues; aqui se hace lo mismo explicitamente.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'b9a306dbac54'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Requerido por el indice GIN idx_ioc_value_gin (gin_trgm_ops) de iocs.value,
    # mas abajo. No es parte de la metadata de modelos, autogenerate no lo detecta.
    op.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')

    # ---- Tablas sin dependencias ----
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.UUID(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_users_is_active'), ['is_active'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_role'), ['role'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    op.create_table('iocs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.UUID(), nullable=False),
    sa.Column('value', sa.String(length=500), nullable=False),
    sa.Column('ioc_type', sa.String(length=20), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_analyzed', sa.DateTime(), nullable=True),
    sa.Column('times_analyzed', sa.Integer(), nullable=True),
    sa.Column('is_whitelisted', sa.Boolean(), nullable=True),
    sa.Column('whitelist_reason', sa.Text(), nullable=True),
    sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('meta_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.create_index('idx_ioc_last_analyzed', ['last_analyzed'], unique=False)
        batch_op.create_index('idx_ioc_type_whitelisted', ['ioc_type', 'is_whitelisted'], unique=False)
        batch_op.create_index('idx_ioc_value_gin', ['value'], unique=False, postgresql_using='gin', postgresql_ops={'value': 'gin_trgm_ops'})
        batch_op.create_index('idx_ioc_value_type', ['value', 'ioc_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_first_seen'), ['first_seen'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_is_whitelisted'), ['is_whitelisted'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_last_analyzed'), ['last_analyzed'], unique=False)

    op.create_table('mitre_malware_mappings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('malware_name', sa.String(length=200), nullable=False),
    sa.Column('malware_id', sa.String(length=20), nullable=True),
    sa.Column('technique_ids', sa.JSON(), nullable=True),
    sa.Column('aliases', sa.JSON(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('malware_name', name='unique_malware_name')
    )
    with op.batch_alter_table('mitre_malware_mappings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mitre_malware_mappings_malware_name'), ['malware_name'], unique=False)

    op.create_table('mitre_techniques',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('technique_id', sa.String(length=20), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('tactic', sa.String(length=50), nullable=True),
    sa.Column('tactics', sa.JSON(), nullable=True),
    sa.Column('platform', sa.JSON(), nullable=True),
    sa.Column('is_subtechnique', sa.Boolean(), nullable=True),
    sa.Column('parent_id', sa.String(length=20), nullable=True),
    sa.Column('url', sa.String(length=500), nullable=True),
    sa.Column('data_sources', sa.JSON(), nullable=True),
    sa.Column('detection', sa.Text(), nullable=True),
    sa.Column('deprecated', sa.Boolean(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('mitre_techniques', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mitre_techniques_tactic'), ['tactic'], unique=False)
        batch_op.create_index(batch_op.f('ix_mitre_techniques_technique_id'), ['technique_id'], unique=True)

    op.create_table('mitre_update_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('techniques_count', sa.Integer(), nullable=True),
    sa.Column('malware_count', sa.Integer(), nullable=True),
    sa.Column('source', sa.String(length=100), nullable=True),
    sa.Column('version', sa.String(length=50), nullable=True),
    sa.Column('success', sa.Boolean(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('api_usage',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('api_name', sa.String(length=50), nullable=False),
    sa.Column('date', sa.Date(), nullable=True),
    sa.Column('requests_count', sa.Integer(), nullable=True),
    sa.Column('errors_count', sa.Integer(), nullable=True),
    sa.Column('last_request_at', sa.DateTime(), nullable=True),
    sa.Column('stats', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('api_name', 'date', name='unique_api_date')
    )
    with op.batch_alter_table('api_usage', schema=None) as batch_op:
        batch_op.create_index('idx_api_usage_date', ['date', 'api_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_api_usage_api_name'), ['api_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_api_usage_date'), ['date'], unique=False)

    # ---- incidents: depende de users; session_id/analysis_id se agregan al final ----
    op.create_table('incidents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.UUID(), nullable=False),
    sa.Column('ticket_id', sa.String(length=50), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=10), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('analysis_id', sa.Integer(), nullable=True),
    sa.Column('session_id', sa.Integer(), nullable=True),
    sa.Column('assigned_to', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('timeline', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('related_iocs', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    # NOTA: analysis_id -> ioc_analyses.id y session_id -> investigation_sessions.id
    # se agregan al final de upgrade() via op.create_foreign_key, DESPUES de crear
    # esas dos tablas. Hay una dependencia circular real entre incidents e
    # investigation_sessions (incidents.session_id <-> investigation_sessions.incident_id)
    # que autogenerate no resuelve solo; los modelos no usan
    # ForeignKey(..., use_alter=True), asi que create_all() la tolera con su
    # propio sorter pero un CREATE TABLE con la FK inline fallaria aqui porque
    # las tablas destino todavia no existen en este punto del script.
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index('idx_incident_created', ['created_at'], unique=False)
        batch_op.create_index('idx_incident_status_severity', ['status', 'severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_ticket_id'), ['ticket_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_incidents_updated_at'), ['updated_at'], unique=False)

    # ---- investigation_sessions: depende de incidents y users ----
    op.create_table('investigation_sessions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=200), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('total_iocs', sa.Integer(), nullable=True),
    sa.Column('total_messages', sa.Integer(), nullable=True),
    sa.Column('highest_risk_level', sa.String(length=20), nullable=True),
    sa.Column('compressed_summary', sa.Text(), nullable=True),
    sa.Column('summary_updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('auto_close_hours', sa.Integer(), nullable=True),
    sa.Column('preferred_llm_provider', sa.String(length=20), nullable=True),
    sa.CheckConstraint("status IN ('active', 'paused', 'closed', 'archived')", name='check_session_status'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    with op.batch_alter_table('investigation_sessions', schema=None) as batch_op:
        batch_op.create_index('idx_sessions_last_activity', [sa.literal_column('last_activity_at DESC')], unique=False)
        batch_op.create_index('idx_sessions_user_active', ['user_id', 'status'], unique=False, postgresql_where=sa.text("status = 'active'"))

    # ---- audit_events: depende de users ----
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('username', sa.String(length=80), nullable=True),
    sa.Column('action', sa.String(length=80), nullable=False),
    sa.Column('resource_type', sa.String(length=50), nullable=True),
    sa.Column('resource_id', sa.Integer(), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('user_agent', sa.String(length=300), nullable=True),
    sa.Column('request_id', sa.String(length=36), nullable=True),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index('ix_audit_action_created', ['action', 'created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_user_id'), ['user_id'], unique=False)
        batch_op.create_index('ix_audit_resource', ['resource_type', 'resource_id'], unique=False)
        batch_op.create_index('ix_audit_user_created', ['user_id', 'created_at'], unique=False)

    # ---- ioc_analyses: depende de iocs y users ----
    op.create_table('ioc_analyses',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.UUID(), nullable=False),
    sa.Column('ioc_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('confidence_score', sa.Integer(), nullable=True),
    sa.Column('risk_level', sa.String(length=20), nullable=True),
    sa.Column('recommendation', sa.Text(), nullable=True),
    sa.Column('virustotal_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('abuseipdb_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('shodan_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('otx_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('greynoise_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('urlhaus_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('threatfox_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('malwarebazaar_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('google_safebrowsing_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('securitytrails_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('hybrid_analysis_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('criminal_ip_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('pulsedive_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('urlscan_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('shodan_internetdb_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ip_api_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('censys_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ipinfo_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('ipgeolocation_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('web_search_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('llm_analysis', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('sources_used', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('errors', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('processing_time', sa.Float(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    with op.batch_alter_table('ioc_analyses', schema=None) as batch_op:
        batch_op.create_index('idx_analysis_confidence', ['confidence_score', 'created_at'], unique=False)
        batch_op.create_index('idx_analysis_ioc_created', ['ioc_id', 'created_at'], unique=False)
        batch_op.create_index('idx_analysis_risk_level', ['risk_level', 'created_at'], unique=False)
        batch_op.create_index('idx_mitre_techniques', ['mitre_techniques'], unique=False, postgresql_using='gin')
        batch_op.create_index('idx_virustotal_data', ['virustotal_data'], unique=False, postgresql_using='gin')
        batch_op.create_index(batch_op.f('ix_ioc_analyses_confidence_score'), ['confidence_score'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_analyses_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_analyses_ioc_id'), ['ioc_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_analyses_risk_level'), ['risk_level'], unique=False)

    # ---- pivots: dependen de incidents/investigation_sessions/iocs/ioc_analyses ----
    op.create_table('incident_iocs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=False),
    sa.Column('ioc_id', sa.Integer(), nullable=False),
    sa.Column('analysis_id', sa.Integer(), nullable=True),
    sa.Column('role', sa.String(length=20), nullable=True),
    sa.Column('added_at', sa.DateTime(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_id'], ['ioc_analyses.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('incident_id', 'ioc_id', name='unique_incident_ioc')
    )
    op.create_table('session_iocs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('session_id', sa.Integer(), nullable=False),
    sa.Column('ioc_id', sa.Integer(), nullable=False),
    sa.Column('analysis_id', sa.Integer(), nullable=True),
    sa.Column('role', sa.String(length=20), nullable=True),
    sa.Column('added_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('added_by_message_id', sa.Integer(), nullable=True),
    sa.Column('analyst_notes', sa.Text(), nullable=True),
    sa.Column('related_to_ioc_ids', sa.ARRAY(sa.Integer()), nullable=True),
    sa.Column('relationship_type', sa.String(length=50), nullable=True),
    sa.CheckConstraint("role IN ('primary', 'related', 'context', 'analyzed')", name='check_ioc_role'),
    sa.ForeignKeyConstraint(['analysis_id'], ['ioc_analyses.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['session_id'], ['investigation_sessions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('session_id', 'ioc_id', name='unique_session_ioc')
    )
    with op.batch_alter_table('session_iocs', schema=None) as batch_op:
        batch_op.create_index('idx_session_iocs_ioc', ['ioc_id'], unique=False)
        batch_op.create_index('idx_session_iocs_session', ['session_id'], unique=False)

    op.create_table('session_messages',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('session_id', sa.Integer(), nullable=False),
    sa.Column('analysis_id', sa.Integer(), nullable=True),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('iocs_mentioned', sa.ARRAY(sa.Text()), nullable=True),
    sa.Column('analysis_triggered', sa.Boolean(), nullable=True),
    sa.Column('is_summary', sa.Boolean(), nullable=True),
    sa.Column('tokens_estimated', sa.Integer(), nullable=True),
    sa.Column('llm_provider', sa.String(length=20), nullable=True),
    sa.CheckConstraint("role IN ('user', 'assistant', 'system')", name='check_message_role'),
    sa.ForeignKeyConstraint(['analysis_id'], ['ioc_analyses.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['session_id'], ['investigation_sessions.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('session_messages', schema=None) as batch_op:
        batch_op.create_index('idx_session_messages_session', ['session_id'], unique=False)
        batch_op.create_index('idx_session_messages_session_created', ['session_id', sa.literal_column('created_at DESC')], unique=False)

    # Ver nota en la definicion de incidents mas arriba: estas dos FK se agregan
    # aqui, una vez que investigation_sessions e ioc_analyses ya existen.
    op.create_foreign_key('incidents_session_id_fkey', 'incidents', 'investigation_sessions', ['session_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('incidents_analysis_id_fkey', 'incidents', 'ioc_analyses', ['analysis_id'], ['id'])


def downgrade():
    # Soltar primero las FK diferidas de incidents (ver upgrade()): ioc_analyses
    # e investigation_sessions se borran mas abajo y no pueden tener referencias
    # vivas desde incidents en ese momento.
    op.drop_constraint('incidents_analysis_id_fkey', 'incidents', type_='foreignkey')
    op.drop_constraint('incidents_session_id_fkey', 'incidents', type_='foreignkey')

    with op.batch_alter_table('session_messages', schema=None) as batch_op:
        batch_op.drop_index('idx_session_messages_session_created')
        batch_op.drop_index('idx_session_messages_session')
    op.drop_table('session_messages')

    with op.batch_alter_table('session_iocs', schema=None) as batch_op:
        batch_op.drop_index('idx_session_iocs_session')
        batch_op.drop_index('idx_session_iocs_ioc')
    op.drop_table('session_iocs')

    op.drop_table('incident_iocs')

    with op.batch_alter_table('ioc_analyses', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ioc_analyses_risk_level'))
        batch_op.drop_index(batch_op.f('ix_ioc_analyses_ioc_id'))
        batch_op.drop_index(batch_op.f('ix_ioc_analyses_created_at'))
        batch_op.drop_index(batch_op.f('ix_ioc_analyses_confidence_score'))
        batch_op.drop_index('idx_virustotal_data', postgresql_using='gin')
        batch_op.drop_index('idx_mitre_techniques', postgresql_using='gin')
        batch_op.drop_index('idx_analysis_risk_level')
        batch_op.drop_index('idx_analysis_ioc_created')
        batch_op.drop_index('idx_analysis_confidence')
    op.drop_table('ioc_analyses')

    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_user_created')
        batch_op.drop_index('ix_audit_resource')
        batch_op.drop_index(batch_op.f('ix_audit_events_user_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_created_at'))
        batch_op.drop_index(batch_op.f('ix_audit_events_action'))
        batch_op.drop_index('ix_audit_action_created')
    op.drop_table('audit_events')

    with op.batch_alter_table('investigation_sessions', schema=None) as batch_op:
        batch_op.drop_index('idx_sessions_user_active', postgresql_where=sa.text("status = 'active'"))
        batch_op.drop_index('idx_sessions_last_activity')
    op.drop_table('investigation_sessions')

    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incidents_updated_at'))
        batch_op.drop_index(batch_op.f('ix_incidents_ticket_id'))
        batch_op.drop_index(batch_op.f('ix_incidents_status'))
        batch_op.drop_index(batch_op.f('ix_incidents_severity'))
        batch_op.drop_index(batch_op.f('ix_incidents_created_at'))
        batch_op.drop_index('idx_incident_status_severity')
        batch_op.drop_index('idx_incident_created')
    op.drop_table('incidents')

    with op.batch_alter_table('api_usage', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_usage_date'))
        batch_op.drop_index(batch_op.f('ix_api_usage_api_name'))
        batch_op.drop_index('idx_api_usage_date')
    op.drop_table('api_usage')

    op.drop_table('mitre_update_log')

    with op.batch_alter_table('mitre_techniques', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mitre_techniques_technique_id'))
        batch_op.drop_index(batch_op.f('ix_mitre_techniques_tactic'))
    op.drop_table('mitre_techniques')

    with op.batch_alter_table('mitre_malware_mappings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mitre_malware_mappings_malware_name'))
    op.drop_table('mitre_malware_mappings')

    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_iocs_last_analyzed'))
        batch_op.drop_index(batch_op.f('ix_iocs_is_whitelisted'))
        batch_op.drop_index(batch_op.f('ix_iocs_first_seen'))
        batch_op.drop_index('idx_ioc_value_type')
        batch_op.drop_index('idx_ioc_value_gin', postgresql_using='gin', postgresql_ops={'value': 'gin_trgm_ops'})
        batch_op.drop_index('idx_ioc_type_whitelisted')
        batch_op.drop_index('idx_ioc_last_analyzed')
    op.drop_table('iocs')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))
        batch_op.drop_index(batch_op.f('ix_users_role'))
        batch_op.drop_index(batch_op.f('ix_users_is_active'))
        batch_op.drop_index(batch_op.f('ix_users_email'))
    op.drop_table('users')
