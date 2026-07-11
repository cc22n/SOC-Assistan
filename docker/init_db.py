"""
Inicialización de BD para Docker.

Espera a que Postgres acepte conexiones, crea el esquema con db.create_all()
(el proyecto no usa Alembic) y aplica los índices de performance + tabla de
auditoría, que son idempotentes (todo usa IF NOT EXISTS).

Se ejecuta en el CMD del contenedor antes de arrancar gunicorn.
"""
import os
import sys
import time
from pathlib import Path

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

    db.create_all()

    sql_path = Path(__file__).resolve().parents[1] / 'migrations' / 'add_performance_indexes_and_audit.sql'
    db.session.execute(text(sql_path.read_text(encoding='utf-8')))
    db.session.commit()
    print('[init_db] Esquema e índices listos.', flush=True)
