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
