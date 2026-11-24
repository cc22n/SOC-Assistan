# Runbook: cadena criptográfica de la auditoría (WP1)

Cada evento de `audit_events` se sella al insertarse con `HMAC-SHA256(AUDIT_CHAIN_KEY, fila + eslabón anterior + posición)`.
Quien solo tenga la BD no puede editar, borrar, insertar ni reordenar eventos sin que `flask audit verify` lo detecte.

## Comandos

| Comando | Para qué |
|---|---|
| `flask audit status` | ¿hay clave? (muestra su `key_id`, nunca la clave), extremo de la cadena, filas sin sellar |
| `flask audit verify [--anchor POS:HASH]` | recalcula toda la cadena; código de salida 1 si está rota |
| `flask audit anchor` | imprime el extremo `POS:HASH`: guárdalo FUERA del servidor |
| `flask audit seal-legacy` | sella (una vez) las filas anteriores a la cadena |
| `GET /api/v2/admin/audit/verify[?anchor=POS:HASH]` | lo mismo, para admin |

Con `TELEGRAM_*` configurado el daemon `feeds` verifica la cadena y envía el ancla cada 24 h. **Guarda esos mensajes**: son el único
testigo que detecta que alguien borró las ÚLTIMAS filas (la cadena sola no lo ve).

## La clave `AUDIT_CHAIN_KEY`

- Obligatoria en producción (32+ caracteres); sin ella la app no arranca.
- Guárdala **fuera de la BD y de sus copias de seguridad** (gestor de secretos o `.env` del host, nunca en el mismo respaldo que el dump).
  Si el respaldo y la clave viajan juntos, quien robe el respaldo puede falsificar la cadena.
- No hace falta para restaurar un respaldo (el dump no la contiene), sí para que `verify` valide lo restaurado.

## Rotar la clave (planificado)

1. Genera la nueva: `python -c "import secrets; print(secrets.token_hex(32))"`.
2. Pon la **anterior** en `AUDIT_CHAIN_PREVIOUS_KEYS` (varias, separadas por coma) y la nueva en `AUDIT_CHAIN_KEY`. Reinicia `app` y `feeds`.
3. `flask audit verify` debe seguir diciendo "ÍNTEGRA": lo antiguo se valida con la clave anterior, lo nuevo con la nueva.
4. **No borres** la clave anterior de `AUDIT_CHAIN_PREVIOUS_KEYS` mientras existan filas selladas con ella.

## Si se PIERDE la clave (o se cambia sin declarar la anterior)

Síntoma: la app funciona, pero `flask audit verify` dice `CADENA ROTA - sellada con una clave desconocida (<key_id>)`. No es una intrusión
por sí mismo: las filas antiguas ya no se pueden recalcular.

1. **Descarta una intrusión primero.** Si tienes anclas de Telegram anteriores, compara: `flask audit verify --anchor POS:HASH` con el
   ancla más reciente que recibiste debe dar `ancla: ok` aunque falte la clave (comprueba posición y enlace).
2. Anota el `key_id` perdido (sale en el mensaje de rotura; el de la clave actual sale en `flask audit status`).
3. Pon una **clave nueva** en `AUDIT_CHAIN_KEY` y declara la perdida en `AUDIT_CHAIN_LOST_KEY_IDS=<key_id>`. Reinicia `app` y `feeds`.
4. `verify` pasa a "ÍNTEGRA" con `sin poder recalcular: N`. Esas N filas solo tienen comprobados enlace y posición, **no su contenido**:
   a partir de aquí lo anterior a la pérdida es evidencia más débil. Apunta en la bitácora la fecha, el `key_id` y el último ancla válido.
5. Lo nuevo (sellado con la clave nueva) queda protegido íntegramente.

## Restaurar un respaldo

Ver `RUNBOOK-BACKUP-RESTORE.md`. Tras restaurar: arranca los servicios y ejecuta `flask audit verify` con la clave de aquel momento
(más `AUDIT_CHAIN_PREVIOUS_KEYS` si rotaste después). Si restauraste un respaldo ANTERIOR al último ancla recibido, `verify --anchor`
fallará ("la cadena termina antes del ancla"): es lo esperado, porque has perdido esos eventos.

## Roles de BD

La app corre como `APP_DB_USER` (por defecto `soc_app`): sin superusuario, no dueño de las tablas, sin DELETE sobre `audit_events` y
sin poder apagar el trigger `audit_events_guard`. Solo `docker/init_db.py` usa al administrador (`MIGRATION_DATABASE_URL`).
Si la app volviera a conectarse como `soc_admin` (superusuario en la imagen oficial), el trigger dejaría de proteger ante una inyección SQL.
