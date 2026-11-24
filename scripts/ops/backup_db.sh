#!/usr/bin/env bash
# ==============================================================================
# Script de Respaldo Automatizado de Base de Datos - SOC Agent
# Genera dump comprimido con gzip y mantiene rotación de 7 días.
#
# Garantías (prelaunch-report-4 A4/A6):
#   * Se escribe en un archivo ".partial" y SOLO se renombra al nombre definitivo si el dump está completo: gzip íntegro Y con la
#     marca final de pg_dump ("PostgreSQL database dump complete"). Un respaldo cortado a mitad nunca queda con nombre válido.
#   * Permisos 0600 (el archivo y, mejor, el directorio 0700): el dump contiene TODOS los datos.
#   * `--no-acl`: no se guardan los GRANT. El rol sin privilegios de la app (soc_app) se crea y se le conceden los privilegios al
#     arrancar `app` (docker/init_db.py); así el respaldo se restaura también en un VPS o volumen NUEVO donde ese rol aún no existe.
# Este script NO copia el respaldo fuera del servidor: perder el VPS es perderlo todo. Copia el .sql.gz a otro sitio (cifrado).
# ==============================================================================
set -euo pipefail
umask 077

BACKUP_DIR="${BACKUP_DIR:-/var/backups/soc-agent}"
DB_NAME="${POSTGRES_DB:-soc_agent}"
DB_USER="${POSTGRES_USER:-soc_admin}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
RETENTION_DAYS=7
DB_CONTAINER="${DB_CONTAINER:-soc-db}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/soc_agent_${TIMESTAMP}.sql.gz"
PARTIAL_FILE="${BACKUP_FILE}.partial"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}" 2>/dev/null || true
trap 'rm -f "${PARTIAL_FILE}"' EXIT          # un fallo no deja basura; en éxito el .partial ya se renombró

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Iniciando respaldo de '${DB_NAME}' en '${BACKUP_FILE}'..."

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo "Respaldando mediante contenedor Docker '${DB_CONTAINER}'..."
    # -i (NO -t): con -t Docker asigna un pseudo-TTY y convierte cada \n en \r\n dentro de la tuberia,
    # lo que altera datos con saltos de linea y puede corromper la restauracion (verificado).
    docker exec -i "${DB_CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists --no-acl | gzip > "${PARTIAL_FILE}"
else
    echo "Respaldando mediante conexión directa psql/pg_dump..."
    pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists --no-acl | gzip > "${PARTIAL_FILE}"
fi

# Verificación ANTES de darlo por bueno: gzip íntegro y marca final de pg_dump (un dump cortado a mitad pasa un `gzip -t` si el corte
# cae en un límite de bloque, y antes quedaba con nombre válido). `tail` lee todo el flujo: no hay SIGPIPE con pipefail.
if ! gzip -t "${PARTIAL_FILE}" 2>/dev/null; then
    echo "Error: el respaldo generado no es un gzip valido. No se guarda."
    exit 1
fi
COLA="$(gzip -dc "${PARTIAL_FILE}" 2>/dev/null | tail -c 4096 || true)"
if ! printf '%s' "${COLA}" | grep -q "PostgreSQL database dump complete"; then
    echo "Error: el respaldo esta INCOMPLETO (falta la marca final de pg_dump). No se guarda."
    exit 1
fi
mv "${PARTIAL_FILE}" "${BACKUP_FILE}"

FILESIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Respaldo completado con éxito. Tamaño: ${FILESIZE}"

echo "Rotando respaldos con más de ${RETENTION_DAYS} días de antigüedad..."
find "${BACKUP_DIR}" -name "soc_agent_*.sql.gz" -type f -mtime +"${RETENTION_DAYS}" -delete
echo "Rotación finalizada."
