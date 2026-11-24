"""
Inicialización de BD para Docker.

Espera a que Postgres acepte conexiones y aplica las migraciones de Alembic
(flask db upgrade) -- el esquema completo (incluida la extensión pg_trgm)
vive en migrations/versions/, no en create_all() + SQL suelto.

Se ejecuta en el CMD del contenedor antes de arrancar gunicorn.
"""
import os
import sys
import time

# La app corre con un rol SIN privilegios (APP_DB_USER, `DATABASE_URL`); las migraciones y el alta de ese rol exigen el administrador
# (`MIGRATION_DATABASE_URL`). Debe fijarse ANTES de importar `app` (la configuración lee DATABASE_URL al importarse).
if os.environ.get('MIGRATION_DATABASE_URL'):
    os.environ['DATABASE_URL'] = os.environ['MIGRATION_DATABASE_URL']

from flask_migrate import upgrade
from sqlalchemy import text

from app import create_app, db

MAX_ATTEMPTS = 30
WAIT_SECONDS = 2

app = create_app(os.getenv('FLASK_ENV', 'production'))

with app.app_context():
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            db.session.execute(text('SELECT 1'))
            break
        except Exception as e:
            db.session.rollback()
            print(f'[init_db] Postgres no disponible (intento {attempt}/{MAX_ATTEMPTS}): {e}', flush=True)
            time.sleep(WAIT_SECONDS)
    else:
        sys.exit('[init_db] Postgres no respondió tras 60s; abortando.')

    upgrade()
    print('[init_db] Migraciones aplicadas.', flush=True)

    from app.services.profile_service import ensure_system_profiles
    print(f'[init_db] Perfiles del sistema: {ensure_system_profiles()}', flush=True)

    # Rol de la aplicación sin privilegios (idempotente: crea, sincroniza contraseña y repasa los privilegios en cada arranque)
    if os.environ.get('APP_DB_PASSWORD'):
        from app.utils.db_roles import ensure_app_role
        info = ensure_app_role(db.engine, os.environ.get('APP_DB_USER', 'soc_app'), os.environ['APP_DB_PASSWORD'])
        print(f"[init_db] Rol de la app '{info['role']}' {'creado' if info['created'] else 'actualizado'} (administrador: {info['admin']}).",
              flush=True)
    else:
        print('[init_db] AVISO: APP_DB_PASSWORD no definido: la app usa el mismo rol que las migraciones (superusuario en la imagen oficial). '
              'El trigger de auditoría no la protege de una inyección SQL.', flush=True)
