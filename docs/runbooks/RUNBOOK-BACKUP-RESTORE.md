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
2. **Detener temporalmente el servicio web (para evitar escrituras concurrentes):**
   ```bash
   docker stop soc-agent
   ```
3. **Ejecutar la restauración:**
   ```bash
   ./scripts/ops/restore_db.sh /var/backups/soc-agent/soc_agent_YYYYMMDD_HHMMSS.sql.gz
   ```
4. **Reiniciar la aplicación:**
   ```bash
   docker start soc-agent
   ```
5. **Verificar el estado del servicio:**
   ```bash
   curl -I http://127.0.0.1:5000/api/v2/health
   ```
