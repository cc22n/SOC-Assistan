"""
Rol de BD de la aplicación, SIN privilegios (hallazgo 1 de prelaunch-report-3).

La imagen oficial de Postgres crea `POSTGRES_USER` como SUPERUSUARIO. Si la app se conecta con él, cualquier inyección SQL puede
`ALTER TABLE audit_events DISABLE TRIGGER ...` (o borrar el trigger) y el trigger de solo agregar de WP1 no vale nada.

Separación:
  * `soc_admin` (superusuario, dueño de las tablas): SOLO migraciones y este alta de rol (`docker/init_db.py`, al arrancar `app`).
  * `soc_app` (NOSUPERUSER, no dueño): lo que usan Gunicorn, el daemon `feeds` y la CLI. Puede leer y escribir los datos, pero no hacer
    DDL, ni `DISABLE TRIGGER` (exige ser dueño), ni borrar filas de `audit_events` (se le retira el privilegio DELETE además del trigger).

Es idempotente (se ejecuta en cada arranque): crea el rol si falta, SINCRONIZA su contraseña y repasa los privilegios. Las tablas futuras
(migraciones que ejecuta el administrador) heredan los privilegios por `ALTER DEFAULT PRIVILEGES`.
"""
import re
from typing import Dict

from psycopg2 import sql

_ROLE_RE = re.compile(r'^[a-z_][a-z0-9_]{0,62}$')
MIN_PASSWORD_LEN = 16
# `alembic_version` no la necesita la app: quien la edita decide qué migraciones se vuelven a ejecutar.
_NO_ACCESS_TABLES = ('alembic_version',)
_NO_DELETE_TABLES = ('audit_events',)


def ensure_app_role(engine, app_user: str, app_password: str) -> Dict[str, object]:
    """Crea/actualiza `app_user` con los mínimos privilegios. Debe ejecutarlo el ADMINISTRADOR de la BD. Devuelve un resumen."""
    if not _ROLE_RE.match(app_user or ''):
        raise ValueError('APP_DB_USER debe ser minúsculas/dígitos/guion bajo (máx. 63)')
    if not app_password or len(app_password) < MIN_PASSWORD_LEN:
        raise ValueError(f'APP_DB_PASSWORD debe tener al menos {MIN_PASSWORD_LEN} caracteres')
    conn = engine.raw_connection()
    try:
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        cur.execute('SELECT current_user, current_database()')
        admin, dbname = cur.fetchone()
        if admin == app_user:
            raise ValueError('APP_DB_USER no puede ser el mismo rol que ejecuta las migraciones')
        ident, pw = sql.Identifier(app_user), sql.Literal(app_password)
        cur.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (app_user,))
        base = sql.SQL('LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(pw)
        creado = cur.fetchone() is None
        cur.execute((sql.SQL('CREATE ROLE {} ') if creado else sql.SQL('ALTER ROLE {} ')).format(ident) + base)
        stmts = [
            sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier(dbname), ident),
            sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(ident),
            sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}').format(ident),
            sql.SQL('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}').format(ident),
            sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}')
               .format(sql.Identifier(admin), ident),
            sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}')
               .format(sql.Identifier(admin), ident),
        ]
        for s in stmts:
            cur.execute(s)
        def existe(t):
            cur.execute('SELECT to_regclass(%s)', (f'public.{t}',))
            return cur.fetchone()[0] is not None

        for t in _NO_ACCESS_TABLES:
            if existe(t):
                cur.execute(sql.SQL('REVOKE ALL ON TABLE {} FROM {}').format(sql.Identifier(t), ident))
        for t in _NO_DELETE_TABLES:
            if existe(t):
                cur.execute(sql.SQL('REVOKE DELETE, TRUNCATE ON TABLE {} FROM {}').format(sql.Identifier(t), ident))
        return {'created': creado, 'role': app_user, 'admin': admin, 'database': dbname}
    finally:
        # `raw_connection()` es del POOL: close() la devuelve, y el modo autocommit PERSISTE en la conexión DBAPI. Sin restaurarlo, el
        # siguiente que la reutilice trabajaría en autocommit y su rollback no deshacería nada (lo destapó un test de otra suite).
        try:
            conn.set_session(autocommit=False)
        except Exception:
            pass
        conn.close()
