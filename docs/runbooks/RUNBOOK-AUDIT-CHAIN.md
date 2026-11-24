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

**Lo que se pierde (honestidad):** las filas selladas con la clave perdida dejan de tener su CONTENIDO protegido; solo se siguen
comprobando su posición y su enlace. Alguien con permisos de dueño sobre la tabla podría editarlas sin que se note, y el ancla de Telegram
no lo ve (solo fija el hash del extremo). Por eso:

1. **Descarta una intrusión comparando con un respaldo ANTERIOR al incidente**, no solo con el ancla. `flask audit verify --anchor POS:HASH`
   con un ancla recibida antes de la pérdida comprueba posición y enlace, **no** que el contenido siga igual.
2. Ejecuta `flask audit verify`: para cada clave desconocida muestra desde qué eslabón aparece y hasta dónde llega su **primer tramo
   contiguo**. Esa cifra es una SUGERENCIA, no una prueba: confirma el tope con tus anclas (el último eslabón legítimo con esa clave).
3. Pon una **clave nueva** en `AUDIT_CHAIN_KEY` y declara la perdida **CON TOPE**: `AUDIT_CHAIN_LOST_KEY_IDS=<key_id>:<última_posición>`.
   Reinicia `app` y `feeds`. **El tope es obligatorio**: una entrada sin él se ignora, y una fila con esa clave por ENCIMA del tope sigue siendo
   rotura. Sin tope, quien pudiera insertar en `audit_events` (una inyección SQL) añadiría filas falsas con ese `key_id` (es público) y
   la cadena seguiría "íntegra". No declares un tope mayor que lo legítimo: reabre ese hueco.
4. `verify` pasa a "ÍNTEGRA" con `sin poder recalcular: N`. Anota en la bitácora la fecha, el `key_id`, el tope y el último ancla válido.
5. Lo nuevo (sellado con la clave nueva) queda protegido íntegramente.

El mismo criterio vale para el histórico sin clave (`AUDIT_CHAIN_ACCEPT_UNKEYED=<última posición sin clave>`): hay que dar la posición;
`true` ya no se acepta, porque SHA-256 sin clave es forjable en cualquier posición.

## Restaurar un respaldo

Ver `RUNBOOK-BACKUP-RESTORE.md`. Tras restaurar: arranca los servicios y ejecuta `flask audit verify` con la clave de aquel momento
(más `AUDIT_CHAIN_PREVIOUS_KEYS` si rotaste después). Si restauraste un respaldo ANTERIOR al último ancla recibido, `verify --anchor`
fallará ("la cadena termina antes del ancla"): es lo esperado, porque has perdido esos eventos.

## Roles de BD

La app corre como `APP_DB_USER` (por defecto `soc_app`): sin superusuario, no dueño de las tablas, sin DELETE sobre `audit_events` y
sin poder apagar el trigger `audit_events_guard`. Solo `docker/init_db.py` usa al administrador (`MIGRATION_DATABASE_URL`).
Si la app volviera a conectarse como `soc_admin` (superusuario en la imagen oficial), el trigger dejaría de proteger ante una inyección SQL.
