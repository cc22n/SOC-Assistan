#!/usr/bin/env bash
# ==============================================================================
# Script de Respaldo Automatizado de Base de Datos - SOC Agent
# Genera dump comprimido con gzip y mantiene rotación de 7 días.
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/soc-agent}"
DB_NAME="${POSTGRES_DB:-soc_agent}"
DB_USER="${POSTGRES_USER:-soc_admin}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
RETENTION_DAYS=7
DB_CONTAINER="${DB_CONTAINER:-soc-db}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/soc_agent_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Iniciando respaldo de '${DB_NAME}' en '${BACKUP_FILE}'..."

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo "Respaldando mediante contenedor Docker '${DB_CONTAINER}'..."
    # -i (NO -t): con -t Docker asigna un pseudo-TTY y convierte cada \n en \r\n dentro de la tuberia,
    # lo que altera datos con saltos de linea y puede corromper la restauracion (verificado).
    docker exec -i "${DB_CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip > "${BACKUP_FILE}"
else
    echo "Respaldando mediante conexión directa psql/pg_dump..."
    pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip > "${BACKUP_FILE}"
fi

FILESIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Respaldo completado con éxito. Tamaño: ${FILESIZE}"

echo "Rotando respaldos con más de ${RETENTION_DAYS} días de antigüedad..."
find "${BACKUP_DIR}" -name "soc_agent_*.sql.gz" -type f -mtime +"${RETENTION_DAYS}" -delete
echo "Rotación finalizada."
