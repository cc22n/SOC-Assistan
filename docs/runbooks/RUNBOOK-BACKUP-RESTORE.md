# 📖 Runbook: Respaldo y Restauración de Base de Datos (PostgreSQL)

**Sistema:** SOC Agent  
**Base de Datos:** PostgreSQL 16 (`soc_agent`)  
**Frecuencia:** Diaria a las 02:00 UTC  
**Retención:** 7 días locales  

---

## 1. Estrategia de Respaldo

Los respaldos se generan mediante `pg_dump` con formato SQL comprimido con gzip (`.sql.gz`), incluyendo opciones `--clean --if-exists` para facilitar una restauración limpia.

### Ejecución Manual:
```bash
./scripts/ops/backup_db.sh
```

### Configuración en Crontab (Servidor de Producción / VPS):
```bash
# Editar crontab del usuario root o socagent
crontab -e

# Agregar línea para respaldo diario a las 02:00 AM UTC
0 2 * * * /app/scripts/ops/backup_db.sh >> /var/log/soc_backup.log 2>&1
```

---

## 2. Procedimiento de Restauración ante Desastre (DR)

### Pasos Operativos:
1. **Identificar el archivo de respaldo:**
   ```bash
   ls -lh /var/backups/soc-agent/
   ```
2. **Parar TODO lo que usa la BD (app y daemon de feeds).** Con conexiones abiertas los `DROP` se bloquean y el script se niega a continuar:
   ```bash
   docker compose stop app feeds
   ```
3. **Ejecutar la restauración:**
   ```bash
   ./scripts/ops/restore_db.sh /var/backups/soc-agent/soc_agent_YYYYMMDD_HHMMSS.sql.gz
   ```
   El script valida antes que el archivo es un gzip íntegro de `pg_dump` y restaura con `ON_ERROR_STOP` y `--single-transaction`: si algo falla
   a mitad, **se deshace todo**, devuelve error y NO imprime "éxito" (antes dejaba la BD a medias y lo decía). Probado de punta a punta
   en `scripts/ops/verify_docker.sh` (sección 7).
4. **Reiniciar la aplicación:**
   ```bash
   docker compose up -d app feeds
   ```
   Al arrancar, `docker/init_db.py` repasa los privilegios del rol `soc_app` (el dump no tiene por qué conservarlos igual).
   Después, verifica la cadena de auditoría: `docker exec soc-agent flask audit verify` (ver `RUNBOOK-AUDIT-CHAIN.md`).
5. **Verificar el estado del servicio:**
   ```bash
   curl -I http://127.0.0.1:5000/api/v2/health
   ```

## Restaurar en un VPS o volumen NUEVO (recuperación ante desastres)

El respaldo no incluye los `GRANT` (`pg_dump --no-acl`) y `restore_db.sh` descarta los de respaldos antiguos: el rol `soc_app` no existe en
un servidor nuevo y no hace falta que exista para restaurar. Orden:

1. Levanta solo la BD: `docker compose up -d db` (con `POSTGRES_PASSWORD` definida).
2. Restaura: `./scripts/ops/restore_db.sh /ruta/soc_agent_AAAAMMDD_HHMMSS.sql.gz` (como `soc_admin`; el script pide confirmación).
3. Arranca todo: `docker compose up -d`. Al arrancar, `app` crea el rol `soc_app` con la contraseña de `APP_DB_PASSWORD` y repasa sus
   privilegios (`docker/init_db.py`); `feeds` espera a que `app` esté sano.
4. `docker exec soc-agent flask audit verify` con la `AUDIT_CHAIN_KEY` del momento del respaldo (que NO viaja en él: guárdala aparte).

## Calidad y custodia de los respaldos

- `backup_db.sh` escribe en `*.partial` y solo lo renombra si el dump está **completo** (gzip íntegro y marca final de `pg_dump`):
  un corte a mitad nunca queda con nombre válido. `restore_db.sh` vuelve a exigir esa marca.
- Los archivos salen con permisos `0600` y el directorio `0700`: el dump contiene todos los datos (hashes de contraseñas incluidos).
- **El script NO copia el respaldo fuera del servidor.** Perder el VPS o su disco es perderlo todo (BD, respaldos y, si está allí, la
  `AUDIT_CHAIN_KEY`). Copia los `.sql.gz` a otro sitio, **cifrados** (por ejemplo `age`/`gpg` + `rclone` o `scp` a otro proveedor), y
  comprueba el restore periódicamente. La clave de la cadena va en otro sitio distinto del respaldo.

## Migraciones manuales

Las migraciones solo corren al arrancar `app` (como administrador). Un `flask db upgrade` a mano dentro del contenedor falla por permisos
(`soc_app` no es dueño de las tablas): usa `docker exec soc-agent sh -c 'DATABASE_URL="$MIGRATION_DATABASE_URL" flask db upgrade'` o reinicia `app`.

