#!/usr/bin/env bash
# ==============================================================================
# Script de Restauración de Base de Datos - SOC Agent
# Restaura un dump comprimido en soc_agent tras confirmación interactiva o flag --yes.
# ==============================================================================
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Uso: $0 <ruta_al_archivo_backup.sql.gz> [--yes]"
    exit 1
fi

BACKUP_FILE="$1"
CONFIRM="${2:-}"
DB_NAME="${POSTGRES_DB:-soc_agent}"
DB_USER="${POSTGRES_USER:-soc_admin}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_CONTAINER="${DB_CONTAINER:-soc-db}"
# Un error a mitad NO puede dejar la BD a medias ni imprimir "exito" (prelaunch-report-3, hallazgo 2): ON_ERROR_STOP corta en el primer
# error y --single-transaction lo deshace todo (pg_dump --clean usa DROP/CREATE transaccionales).
PSQL_FLAGS=(-X -v ON_ERROR_STOP=1 --single-transaction)

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: El archivo '${BACKUP_FILE}' no existe."
    exit 1
fi

# El dump debe ser un gzip integro de pg_dump ANTES de tocar nada
if ! gzip -t "${BACKUP_FILE}" 2>/dev/null; then
    echo "Error: '${BACKUP_FILE}' no es un gzip valido (respaldo truncado?). No se ha tocado la base de datos."
    exit 1
fi
# OJO: no `gzip | head | grep -q` directo: con `pipefail`, `head` cierra la tuberia, gzip recibe SIGPIPE (141) y el pipeline
# "falla" aunque la cabecera este (rechazaba volcados REALES de mas de 4 KB; lo destapo verify_docker.sh). Se lee a una variable.
CABECERA="$(gzip -dc "${BACKUP_FILE}" 2>/dev/null | head -c 4096 || true)"
if ! printf '%s' "${CABECERA}" | grep -q "PostgreSQL database dump"; then
    echo "Error: '${BACKUP_FILE}' no parece un volcado de pg_dump. No se ha tocado la base de datos."
    exit 1
fi

echo "================================================================="
echo "ADVERTENCIA: Esta operación sobrescribirá la base de datos '${DB_NAME}'"
echo "Archivo origen: ${BACKUP_FILE}"
echo "================================================================="

if [ "${CONFIRM}" != "--yes" ]; then
    read -r -p "¿Estás seguro de que deseas proceder con la restauración? (escribe 'RESTAURAR'): " RESPONSE
    if [ "${RESPONSE}" != "RESTAURAR" ]; then
        echo "Operación cancelada por el usuario."
        exit 0
    fi
fi

# Con `app` o `feeds` conectados los DROP se bloquean (o se restaura bajo sus pies): hay que pararlos antes.
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    ACTIVAS="$(docker exec -i "${DB_CONTAINER}" psql -U "${DB_USER}" -d postgres -Atc "SELECT count(*) FROM pg_stat_activity WHERE datname='${DB_NAME}'" 2>/dev/null || echo "?")"
    if [ "${ACTIVAS}" != "0" ]; then
        echo "Error: hay ${ACTIVAS} conexion(es) abiertas a '${DB_NAME}'. Para los servicios que la usan y repite:"
        echo "       docker compose stop app feeds"
        exit 1
    fi
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Iniciando restauración de '${DB_NAME}'..."

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo "Restaurando a través del contenedor Docker '${DB_CONTAINER}'..."
    gzip -dc "${BACKUP_FILE}" | docker exec -i "${DB_CONTAINER}" psql "${PSQL_FLAGS[@]}" -U "${DB_USER}" -d "${DB_NAME}"
else
    echo "Restaurando mediante conexión directa psql..."
    gzip -dc "${BACKUP_FILE}" | psql "${PSQL_FLAGS[@]}" -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}"
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Restauración finalizada con éxito."
echo "Siguiente paso: arranca los servicios (docker compose up -d) y ejecuta: flask audit verify  (con la AUDIT_CHAIN_KEY del momento del respaldo)."
