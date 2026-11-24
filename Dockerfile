FROM python:3.12-slim

# PYTHONPATH=/app: `python docker/init_db.py` pone /app/docker (no /app) en sys.path y
# `from app import ...` fallaba con ModuleNotFoundError -> el contenedor entraba en bucle de reinicios.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# psycopg2-binary trae wheels precompilados: no hace falta gcc/libpq-dev
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Usuario sin privilegios; logs/ debe existir y ser escribible (RotatingFileHandler)
RUN useradd --create-home --shell /usr/sbin/nologin socagent \
    && mkdir -p /app/logs /app/instance \
    && chown -R socagent:socagent /app
USER socagent

EXPOSE 5000

# --start-period: una migracion larga en el arranque no cuenta como fallo (antes dejaba `app` unhealthy y `feeds` esperando).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=90s \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/v2/health', timeout=4).getcode() == 200 else 1)" || exit 1

# init_db.py espera a Postgres, crea el esquema (db.create_all) y aplica los
# índices idempotentes de migrations/. Es Python (no .sh) para que los CRLF
# de checkouts en Windows no rompan el arranque del contenedor.
# `env -u MIGRATION_DATABASE_URL`: el administrador de la BD solo lo necesita init_db.py (migraciones y alta del rol sin privilegios);
# el proceso web NO debe tenerlo en su entorno (prelaunch-report-4 M1).
CMD ["sh", "-c", "python docker/init_db.py && exec env -u MIGRATION_DATABASE_URL gunicorn --bind 0.0.0.0:5000 --workers 3 --worker-class gthread --threads 4 --timeout 120 wsgi:app"]
