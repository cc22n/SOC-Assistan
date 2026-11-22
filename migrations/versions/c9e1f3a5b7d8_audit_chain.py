"""audit_events: cadena criptografica (HMAC) y trigger de solo agregar (WP1)

Revision ID: c9e1f3a5b7d8
Revises: b8d0e2f4a6c7

Escrita a mano (el autogenerate arrastra el drift de la baseline). Las filas existentes quedan con chain_* NULL:
`flask audit seal-legacy` las sella. El trigger bloquea DELETE y UPDATE salvo (a) user_id -> NULL (lo hace la FK ON DELETE SET NULL
al borrar un usuario) y (b) sellar una fila de legado. No cubre TRUNCATE ni a un propietario de la tabla que lo quite: es defensa
en profundidad, la barrera real es el HMAC.
"""
from alembic import op
import sqlalchemy as sa

revision = 'c9e1f3a5b7d8'
down_revision = 'b8d0e2f4a6c7'
branch_labels = None
depends_on = None

GUARD_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION audit_events_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: DELETE no permitido';
    END IF;
    -- UPDATE: solo se permite (a) que la FK ON DELETE SET NULL ponga user_id a NULL y (b) sellar una fila de legado (chain_* de NULL a valor)
    IF ROW(NEW.id, NEW.username, NEW.action, NEW.resource_type, NEW.resource_id, NEW.details, NEW.ip_address,
           NEW.user_agent, NEW.request_id, NEW.success, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.username, OLD.action, OLD.resource_type, OLD.resource_id, OLD.details, OLD.ip_address,
           OLD.user_agent, OLD.request_id, OLD.success, OLD.created_at) THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: UPDATE no permitido';
    END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id AND NEW.user_id IS NOT NULL THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: user_id solo puede pasar a NULL';
    END IF;
    IF OLD.entry_hash IS NOT NULL
       AND ROW(NEW.chain_pos, NEW.prev_hash, NEW.entry_hash, NEW.key_id, NEW.algo)
           IS DISTINCT FROM ROW(OLD.chain_pos, OLD.prev_hash, OLD.entry_hash, OLD.key_id, OLD.algo) THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: una fila sellada no se puede resellar';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""
GUARD_TRIGGER_SQL = ("CREATE TRIGGER trg_audit_events_guard BEFORE UPDATE OR DELETE ON audit_events "
                     "FOR EACH ROW EXECUTE FUNCTION audit_events_guard()")


def upgrade():
    op.add_column('audit_events', sa.Column('chain_pos', sa.BigInteger(), nullable=True))
    op.add_column('audit_events', sa.Column('prev_hash', sa.String(length=64), nullable=True))
    op.add_column('audit_events', sa.Column('entry_hash', sa.String(length=64), nullable=True))
    op.add_column('audit_events', sa.Column('key_id', sa.String(length=16), nullable=True))
    op.add_column('audit_events', sa.Column('algo', sa.String(length=16), nullable=True))
    op.create_unique_constraint('uq_audit_events_chain_pos', 'audit_events', ['chain_pos'])
    op.execute(GUARD_FUNCTION_SQL)
    op.execute(GUARD_TRIGGER_SQL)


def downgrade():
    op.execute('DROP TRIGGER IF EXISTS trg_audit_events_guard ON audit_events')
    op.execute('DROP FUNCTION IF EXISTS audit_events_guard()')
    op.drop_constraint('uq_audit_events_chain_pos', 'audit_events', type_='unique')
    for c in ('algo', 'key_id', 'entry_hash', 'prev_hash', 'chain_pos'):
        op.drop_column('audit_events', c)
