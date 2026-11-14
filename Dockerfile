FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

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

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/v2/health', timeout=4).getcode() == 200 else 1)" || exit 1

# init_db.py espera a Postgres, crea el esquema (db.create_all) y aplica los
# índices idempotentes de migrations/. Es Python (no .sh) para que los CRLF
# de checkouts en Windows no rompan el arranque del contenedor.
CMD ["sh", "-c", "python docker/init_db.py && exec gunicorn --bind 0.0.0.0:5000 --workers 3 --worker-class gthread --threads 4 --timeout 120 wsgi:app"]
