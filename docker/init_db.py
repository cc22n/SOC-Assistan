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
