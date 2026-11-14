"""unique constraint uq_ioc_value_type (+ fusion previa de IOCs duplicados)

Revision ID: c2d4e6f8a0b1
Revises: a1c3f5e7d9b2
Create Date: 2026-11-13 20:00:00.000000

Migración escrita a mano (NO autogenerate, ver CLAUDE.md).

El modelo `IOC` declara `UniqueConstraint('value', 'ioc_type', name='uq_ioc_value_type')`
pero ninguna migración lo creaba (solo existía el índice NO único idx_ioc_value_type),
así que la BD real aceptaba duplicados (la BD de dev tenía 5 pares) y el insert
check-then-act de la API podía duplicar IOCs bajo concurrencia.

Antes de crear el constraint se FUSIONAN los duplicados existentes:
  * conserva el IOC de menor id (keeper) de cada (value, ioc_type);
  * reapunta ioc_analyses / session_iocs / incident_iocs al keeper (en las tablas
    pivote primero se eliminan las filas que quedarían duplicadas por sus propios
    UNIQUE (session_id, ioc_id) / (incident_id, ioc_id));
  * keeper agrega: times_analyzed = suma, first_seen = mínimo, last_analyzed = máximo,
    is_whitelisted = OR (una decisión explícita de whitelist no se pierde);
  * borra los IOCs sobrantes.

downgrade() solo quita el constraint: los duplicados fusionados no son recuperables.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c2d4e6f8a0b1'
down_revision = 'a1c3f5e7d9b2'
branch_labels = None
depends_on = None


def upgrade():
    # Mapa old_id -> keeper_id solo para los IOCs duplicados (idempotente: sin duplicados no hace nada)
    op.execute("""
        CREATE TEMP TABLE _ioc_remap ON COMMIT DROP AS
        SELECT i.id AS old_id, k.keeper_id
        FROM iocs i
        JOIN (SELECT value, ioc_type, MIN(id) AS keeper_id
              FROM iocs GROUP BY value, ioc_type HAVING COUNT(*) > 1) k
          ON k.value = i.value AND k.ioc_type = i.ioc_type
    """)

    # Tablas pivote: quitar filas que colisionarían tras el reapuntado, luego reapuntar
    for table, parent_col in (('session_iocs', 'session_id'), ('incident_iocs', 'incident_id')):
        op.execute(f"""
            DELETE FROM {table}
            WHERE id IN (
                SELECT id FROM (
                    SELECT p.id,
                           ROW_NUMBER() OVER (
                               PARTITION BY p.{parent_col}, r.keeper_id
                               ORDER BY (p.ioc_id = r.keeper_id) DESC, p.id
                           ) AS rn
                    FROM {table} p JOIN _ioc_remap r ON r.old_id = p.ioc_id
                ) t WHERE t.rn > 1
            )
        """)
        op.execute(f"""
            UPDATE {table} p SET ioc_id = r.keeper_id
            FROM _ioc_remap r
            WHERE p.ioc_id = r.old_id AND r.old_id <> r.keeper_id
        """)

    op.execute("""
        UPDATE ioc_analyses a SET ioc_id = r.keeper_id
        FROM _ioc_remap r
        WHERE a.ioc_id = r.old_id AND r.old_id <> r.keeper_id
    """)

    # Agregados al keeper (calculados sobre TODAS las filas del grupo, keeper incluido)
    op.execute("""
        UPDATE iocs k SET
            times_analyzed = g.times,
            first_seen     = g.first_seen,
            last_analyzed  = g.last_analyzed,
            is_whitelisted = g.whitelisted,
            whitelist_reason = COALESCE(k.whitelist_reason, g.reason)
        FROM (
            SELECT r.keeper_id,
                   SUM(COALESCE(i.times_analyzed, 0))   AS times,
                   MIN(i.first_seen)                     AS first_seen,
                   MAX(i.last_analyzed)                  AS last_analyzed,
                   BOOL_OR(COALESCE(i.is_whitelisted, FALSE)) AS whitelisted,
                   MAX(i.whitelist_reason)               AS reason
            FROM _ioc_remap r JOIN iocs i ON i.id = r.old_id
            GROUP BY r.keeper_id
        ) g
        WHERE k.id = g.keeper_id
    """)

    op.execute("DELETE FROM iocs WHERE id IN (SELECT old_id FROM _ioc_remap WHERE old_id <> keeper_id)")

    op.create_unique_constraint('uq_ioc_value_type', 'iocs', ['value', 'ioc_type'])


def downgrade():
    op.drop_constraint('uq_ioc_value_type', 'iocs', type_='unique')
