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

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: El archivo '${BACKUP_FILE}' no existe."
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

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Iniciando restauración de '${DB_NAME}'..."

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^soc-db$"; then
    echo "Restaurando a través del contenedor Docker 'soc-db'..."
    gzip -dc "${BACKUP_FILE}" | docker exec -i soc-db psql -U "${DB_USER}" -d "${DB_NAME}"
else
    echo "Restaurando mediante conexión directa psql..."
    gzip -dc "${BACKUP_FILE}" | psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}"
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Restauración finalizada con éxito."
