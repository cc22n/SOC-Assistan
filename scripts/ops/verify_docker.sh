#!/usr/bin/env bash
# =============================================================================
# Verifica que `docker compose up --build` produce un stack SANO, sin tocar otros
# proyectos de Docker ni usar secretos reales.
#
#   bash scripts/ops/verify_docker.sh            # construye, comprueba y destruye todo
#   KEEP=1 bash scripts/ops/verify_docker.sh     # deja el stack levantado para inspeccionarlo
#
# Aislamiento: proyecto "socverify" (volumenes propios), puerto 127.0.0.1:5071, nombres de
# contenedor propios y un env_file temporal SIN API keys (solo SECRET_KEY aleatoria).
# Origen: una instalacion limpia desde requirements.txt destapo que el contenedor nunca
# arrancaba (PYTHONPATH) y que SQLAlchemy 2.1 / tzdata rompian la imagen.
# =============================================================================
set -u
cd "$(dirname "$0")/../.."

PROJECT="${VERIFY_PROJECT:-socverify}"
PORT="${VERIFY_PORT:-5071}"
BASE="http://127.0.0.1:${PORT}"
TMP="$(mktemp -d)"
win() { command -v cygpath >/dev/null 2>&1 && cygpath -m "$1" || echo "$1"; }   # ruta valida para docker.exe

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [OK]   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FALLA] %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (esperado=$3, obtenido=$2)"; fi; }
http() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32)); print('AUDIT_CHAIN_KEY=' + secrets.token_hex(32)); print('FLASK_APP=wsgi.py')" > "$TMP/verify.env"
# POSTGRES_PASSWORD y APP_DB_PASSWORD son obligatorias en docker-compose.yml (sin valor por defecto): se generan al azar
export POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(16))')"
export APP_DB_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(16))')"
export REDIS_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(16))')"
cat > "$TMP/override.yml" <<EOF
services:
  app:
    container_name: ${PROJECT}-app
    ports: !override
      - "127.0.0.1:${PORT}:5000"
    env_file: !override
      - path: $(win "$TMP/verify.env")
        required: true
  feeds:
    env_file: !override
      - path: $(win "$TMP/verify.env")
        required: true
  db:
    container_name: ${PROJECT}-db
  redis:
    container_name: ${PROJECT}-redis
EOF
DC=(docker compose -p "$PROJECT" -f docker-compose.yml -f "$(win "$TMP/override.yml")")

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    "${DC[@]}" down -v --rmi local >/dev/null 2>&1
  else
    echo "KEEP=1: stack dejado en pie en $BASE (proyecto $PROJECT)"
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "== 1. build limpio e inicio"
"${DC[@]}" build app >"$TMP/build.log" 2>&1 && ok "docker compose build" || { bad "docker compose build"; tail -20 "$TMP/build.log"; exit 1; }
"${DC[@]}" up -d >"$TMP/up.log" 2>&1 && ok "docker compose up" || { bad "docker compose up"; cat "$TMP/up.log"; exit 1; }

echo "== 2. el contenedor llega a healthy (sin bucle de reinicios)"
STATE=""
for _ in $(seq 1 40); do
  STATE="$(docker inspect "${PROJECT}-app" --format '{{.State.Health.Status}}' 2>/dev/null)"
  [ "$STATE" = "healthy" ] && break
  sleep 3
done
check "healthcheck" "$STATE" "healthy"
check "sin reinicios" "$(docker inspect "${PROJECT}-app" --format '{{.RestartCount}}')" "0"
FEEDS_ID=""; for i in $(seq 1 20); do FEEDS_ID="$("${DC[@]}" ps -q feeds 2>/dev/null)"; [ -n "$FEEDS_ID" ] && break; sleep 2; done
FEEDS_LOG=""; for i in $(seq 1 30); do FEEDS_LOG="$(docker logs "$FEEDS_ID" 2>&1)"; echo "$FEEDS_LOG" | grep -q "feeds daemon iniciado" && break; sleep 2; done
echo "$FEEDS_LOG" | grep -q "feeds daemon iniciado" && ok "el servicio feeds arranca y el daemon inicia" || { bad "el servicio feeds no inicia el daemon"; echo "$FEEDS_LOG" | tail -5; }
check "feeds sin reinicios" "$(docker inspect "$FEEDS_ID" --format '{{.RestartCount}}')" "0"
FEEDS_OK=""; for i in $(seq 1 40); do docker exec "$FEEDS_ID" flask feeds status 2>/dev/null | grep -q "cisa_kev .*última=ok" && { FEEDS_OK=1; break; }; sleep 3; done
[ -n "$FEEDS_OK" ] && ok "el daemon ejecuto una fuente real (KEV) y quedo registrada en feed_runs" || bad "el daemon no completo ninguna ejecucion de KEV en 2 min"
docker exec "$FEEDS_ID" flask telegram status 2>/dev/null | grep -q "avisos activos    : NO" && ok "Telegram desactivado sin token (el daemon se comporta como antes)" || bad "Telegram no queda desactivado sin token"

LOG="$(docker logs "${PROJECT}-app" 2>&1)"
echo "$LOG" | grep -q "Running upgrade  -> " && ok "Alembic aplico las migraciones desde una BD vacia" || bad "migraciones no aplicadas"
echo "$LOG" | grep -q "Using worker: gthread" && ok "Gunicorn usa gthread" || bad "Gunicorn no usa gthread"
echo "$LOG" | grep -q "No module named" && bad "ModuleNotFoundError en el arranque" || ok "sin ModuleNotFoundError"

echo "== 3. HTTP desde fuera"
check "GET /api/v2/health" "$(http $BASE/api/v2/health)" "200"
curl -s $BASE/api/v2/health | grep -q '"database":{"latency_ms":[0-9.]*,"status":"healthy"}' && ok "BD sana en /health" || bad "BD no sana en /health"
curl -s $BASE/api/v2/health | grep -q '"redis":{"latency_ms":[0-9.]*,"status":"healthy"}' && ok "Redis sano en /health" || bad "Redis no sano en /health"
HDR="$(curl -sI $BASE/auth/login)"
echo "$HDR" | grep -qi "content-security-policy:.*'nonce-" && ok "CSP con nonce" || bad "CSP sin nonce"
echo "$HDR" | grep -qi "upgrade-insecure-requests" && ok "CSP: upgrade-insecure-requests en produccion" || bad "falta upgrade-insecure-requests"
echo "$HDR" | grep -qi "strict-transport-security" && ok "HSTS" || bad "sin HSTS"
check "Host: evil.com rechazado" "$(http -H 'Host: evil.com' $BASE/auth/login)" "400"
check "X-Forwarded-Host: evil.com rechazado" "$(http -H 'X-Forwarded-Host: evil.com' $BASE/auth/login)" "400"
check "Host: localhost permitido" "$(http -H 'Host: localhost' $BASE/auth/login)" "200"
CSP_LINE="$(echo "$HDR" | grep -i '^content-security-policy:' | tr ';' '\n')"
echo "$CSP_LINE" | grep -i 'style-src ' | grep -qi "unsafe-inline" && bad "style-src permite 'unsafe-inline'" || ok "style-src sin 'unsafe-inline' (solo style-src-attr)"
echo "$CSP_LINE" | grep -qi "tailwindcss" && bad "la CSP aun permite cdn.tailwindcss.com" || ok "la CSP ya no menciona el CDN de Tailwind"
CT="$(curl -sI $BASE/static/css/tailwind.css | grep -i '^content-type:' | tr -d '\r')"
check "CSS de Tailwind compilado servido" "$(http $BASE/static/css/tailwind.css)" "200"
echo "$CT" | grep -qi "text/css" && ok "tailwind.css con Content-Type text/css" || bad "tailwind.css sin text/css ($CT)"
# El nonce cambia en CADA peticion: cabecera y cuerpo deben salir de la MISMA respuesta
FULL="$(curl -si $BASE/auth/login)"
HDR_NONCE="$(echo "$FULL" | grep -i '^content-security-policy:' | grep -io "style-src 'self' 'nonce-[A-Za-z0-9_-]*'" | grep -o "nonce-[A-Za-z0-9_-]*" | head -1)"
[ -n "$HDR_NONCE" ] && echo "$FULL" | grep -q "<style nonce=\"${HDR_NONCE#nonce-}\"" && ok "el <style> de la pagina lleva el nonce de la cabecera" || bad "el <style> no lleva el nonce de la cabecera"
check "GET /auth/logout -> 405" "$(http $BASE/auth/logout)" "405"
check "estatico ui-actions.js" "$(http $BASE/static/ui-actions.js)" "200"

echo "== 4. flujo autenticado con CSRF real (cookies Secure de produccion)"
J="$TMP/cookies"; PW="Vf1!$(python -c 'import secrets;print(secrets.token_urlsafe(12))')"
tok()  { grep -o 'name="csrf_token"[^>]*value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)".*/\1/'; }
meta() { grep -o 'name="csrf-token" content="[^"]*"' | head -1 | sed -E 's/.*content="([^"]*)".*/\1/'; }
code() { curl -s -o /dev/null -w '%{http_code}' -b "$J" -c "$J" "$@"; }
T="$(curl -s -b "$J" -c "$J" $BASE/auth/register | tok)"
check "registro sin token CSRF -> 400" "$(code -X POST -d 'username=u&email=a@x.test&password=x&password2=x' $BASE/auth/register)" "400"
T="$(curl -s -b "$J" -c "$J" $BASE/auth/register | tok)"
check "registro del primer usuario -> 302" "$(code -X POST --data-urlencode username=admin_v --data-urlencode email=admin_v@soc.test --data-urlencode "password=$PW" --data-urlencode "password2=$PW" --data-urlencode "csrf_token=$T" $BASE/auth/register)" "302"
T="$(curl -s -b "$J" -c "$J" $BASE/auth/login | tok)"
check "login con token -> 302" "$(code -X POST --data-urlencode username=admin_v --data-urlencode "password=$PW" --data-urlencode "csrf_token=$T" $BASE/auth/login)" "302"
check "dashboard autenticado" "$(code $BASE/dashboard)" "200"
NPROF="$(curl -s -b "$J" -c "$J" $BASE/api/v2/profiles | python -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for p in d["profiles"] if p["is_system"]))' 2>/dev/null)"
check "perfiles del sistema sembrados por init_db en el contenedor" "$NPROF" "10"
check "pagina /profiles autenticada" "$(code $BASE/profiles)" "200"
M="$(curl -s -b "$J" -c "$J" $BASE/dashboard | meta)"
check "logout POST sin token -> 400" "$(code -X POST $BASE/auth/logout)" "400"
check "logout POST con token -> 302" "$(code -X POST -H "X-CSRFToken: $M" $BASE/auth/logout)" "302"
check "dashboard tras logout -> 302" "$(code $BASE/dashboard)" "302"

echo "== 4b. cadena criptografica de la auditoria (WP1)"
AV="$(docker exec "${PROJECT}-app" flask audit verify 2>&1)"; AVRC=$?
{ [ "$AVRC" = "0" ] && echo "$AV" | grep -q "eslabones comprobados"; } && ok "flask audit verify: la cadena de los eventos reales (registro/login/logout) es integra" || bad "flask audit verify fallo (rc=$AVRC): $(echo "$AV" | tail -2)"
DELOUT="$(docker exec "${PROJECT}-db" psql -U soc_admin -d soc_agent -c "DELETE FROM audit_events" 2>&1)"
echo "$DELOUT" | grep -q "solo agregar" && ok "el trigger de la BD real bloquea DELETE sobre audit_events" || bad "el trigger no bloqueo el DELETE: $DELOUT"
NOKEY="$(docker exec "${PROJECT}-app" env -u AUDIT_CHAIN_KEY flask audit status 2>&1)"
echo "$NOKEY" | grep -q "AUDIT_CHAIN_KEY" && ok "produccion se niega a arrancar sin AUDIT_CHAIN_KEY" || bad "produccion arranco sin AUDIT_CHAIN_KEY"

echo "== 4c. roles de BD: la app NO es superusuario (prelaunch-report-3)"
PSQLA() { docker exec -i "${PROJECT}-db" psql -U soc_admin -d soc_agent -Atc "$1" 2>&1; }
SOCAPP() { docker exec -i -e PGPASSWORD="$APP_DB_PASSWORD" "${PROJECT}-db" psql -U soc_app -d soc_agent -h 127.0.0.1 -Atc "$1" 2>&1; }
check "soc_app no es superusuario" "$(PSQLA "SELECT rolsuper FROM pg_roles WHERE rolname='soc_app'")" "f"
check "app y daemon se conectan como soc_app" "$(PSQLA "SELECT count(*)>0 FROM pg_stat_activity WHERE datname='soc_agent' AND usename='soc_app'")" "t"
check "ninguna conexion de la app usa al administrador" "$(PSQLA "SELECT count(*) FROM pg_stat_activity WHERE datname='soc_agent' AND usename='soc_admin' AND application_name=''")" "0"
check "control: soc_app SI puede leer la auditoria" "$(SOCAPP "SELECT count(*)>0 FROM audit_events")" "t"
SOCAPP "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_guard" | grep -qiE "must be owner|debe ser" && ok "soc_app NO puede apagar el trigger de auditoria (exige ser dueño)" || bad "soc_app pudo (o falló raro) apagando el trigger"
SOCAPP "DELETE FROM audit_events" | grep -qi "permission denied" && ok "soc_app no tiene privilegio DELETE sobre audit_events" || bad "soc_app puede borrar auditoria"
SOCAPP "DROP TABLE users CASCADE" | grep -qiE "must be owner|debe ser" && ok "soc_app no puede hacer DDL" || bad "soc_app pudo hacer DDL"
SOCAPP "SELECT count(*) FROM alembic_version" | grep -qi "permission denied" && ok "soc_app no accede a alembic_version" || bad "soc_app accede a alembic_version"
: > "$TMP/empty.env"
CFG="$(env -u POSTGRES_PASSWORD -u APP_DB_PASSWORD docker compose --env-file "$(win "$TMP/empty.env")" -f docker-compose.yml config 2>&1)"; CFGRC=$?
{ [ "$CFGRC" != "0" ] && echo "$CFG" | grep -qE "POSTGRES_PASSWORD|APP_DB_PASSWORD"; } && ok "compose se niega a arrancar sin POSTGRES_PASSWORD/APP_DB_PASSWORD (ya no hay contraseña pública por defecto)" || bad "compose arranco sin contraseñas"

echo "== 5. concurrencia real de Gunicorn (conexiones colgadas)"
python - "$BASE" <<'PYEOF'
import socket, sys, time, urllib.request
host, port = sys.argv[1].replace('http://', '').split(':'); port = int(port)
def normal():
    t = time.perf_counter()
    try:
        urllib.request.urlopen(f'http://{host}:{port}/api/v2/health', timeout=4).read()
        return (time.perf_counter() - t) * 1000
    except Exception:
        return None
normal()
res = {}
for n in (3, 9):
    socks = []
    for _ in range(n):
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b'GET /auth/login HTTP/1.1\r\nHost: localhost\r\n'); socks.append(s)
    time.sleep(0.6); res[n] = normal()
    for s in socks: s.close()
    time.sleep(0.8)
# Con workers sync (3) bastaban 3 conexiones colgadas para bloquear SIEMPRE. Con gthread (4 hilos por
# worker) 3 conexiones nunca saturan un worker, ni aunque todas caigan en el mismo: eso es DETERMINISTA y
# es lo que se exige. Con mas conexiones el resultado depende de como el kernel reparte las conexiones
# entre workers (gthread las acepta y encola aunque sus hilos esten ocupados), asi que 9 es solo informativo.
print('   latencia con conexiones colgadas (ms):', {k: (None if v is None else round(v)) for k, v in res.items()},
      '(solo 3 es criterio; 9 informativo)')
sys.exit(0 if (res[3] is not None and res[3] < 1500) else 1)
PYEOF
[ $? -eq 0 ] && ok "3 conexiones colgadas no bloquean el servicio (con workers sync lo bloqueaban)" || bad "se bloquea con solo 3 conexiones colgadas"

echo "== 6. imagen y contenedor"
check "no corre como root" "$(docker exec "${PROJECT}-app" id -un)" "socagent"
LEAK="$(docker run --rm --entrypoint sh "${PROJECT}-app" -c 'ls -a /app | grep -E "^\.env" | grep -v "^\.env\.example$"; grep -rIlE "(AIzaSy[0-9A-Za-z_-]{30,}|xai-[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{30,})" /app 2>/dev/null' | head -3)"
[ -z "$LEAK" ] && ok "sin .env ni API keys dentro de la imagen" || bad "posibles secretos en la imagen: $LEAK"
for c in app db redis; do
  LC="$(docker inspect "${PROJECT}-$c" --format '{{.HostConfig.LogConfig.Type}} {{.HostConfig.LogConfig.Config}}')"
  [ "$LC" = "json-file map[max-file:5 max-size:50m]" ] && ok "rotacion de logs en $c" || bad "sin rotacion de logs en $c ($LC)"
done
docker inspect "${PROJECT}-app" --format '{{.HostConfig.PortBindings}}' | grep -q "127.0.0.1" && ok "puerto publicado solo en 127.0.0.1" || bad "puerto expuesto en todas las interfaces"

echo "== 7. backup y restore REALES (scripts/ops/backup_db.sh y restore_db.sh)"
BK="$TMP/backups"; mkdir -p "$BK"; DBC="${PROJECT}-db"
CNT() { PSQLA "SELECT count(*) FROM $1"; }
AUD0="$(CNT audit_events)"; USR0="$(CNT users)"
BACKUP_DIR="$BK" DB_CONTAINER="$DBC" bash scripts/ops/backup_db.sh >"$TMP/backup.log" 2>&1; BKRC=$?
DUMP="$(ls "$BK"/soc_agent_*.sql.gz 2>/dev/null | head -1)"
{ [ "$BKRC" = "0" ] && [ -s "$DUMP" ] && gzip -t "$DUMP"; } && ok "backup_db.sh genera un gzip integro ($(du -h "$DUMP" | cut -f1))" || { bad "backup_db.sh fallo"; tail -3 "$TMP/backup.log"; }
OUT="$(DB_CONTAINER="$DBC" bash scripts/ops/restore_db.sh "$DUMP" --yes 2>&1)"; RC=$?
{ [ "$RC" != "0" ] && echo "$OUT" | grep -q "conexion"; } && ok "restore se niega con app/feeds conectados (los DROP se bloquearian)" || bad "restore no detecto conexiones activas (rc=$RC)"
head -c 200 "$DUMP" > "$TMP/truncado.sql.gz"
OUT="$(DB_CONTAINER="$DBC" bash scripts/ops/restore_db.sh "$TMP/truncado.sql.gz" --yes 2>&1)"; RC=$?
{ [ "$RC" != "0" ] && ! echo "$OUT" | grep -q "finalizada con"; } && ok "un respaldo truncado se rechaza antes de tocar la BD" || bad "restore acepto un respaldo truncado"
T0=$(date +%s)
"${DC[@]}" stop app feeds >/dev/null 2>&1
T1=$(date +%s)
# M6: con `init: true` y stop_grace_period el daemon termina con SIGTERM (143) o limpio (0); antes era PID 1 sin manejador y moria con SIGKILL (137)
FEEDS_EXIT="$(docker inspect "$FEEDS_ID" --format '{{.State.ExitCode}}' 2>/dev/null)"
APP_EXIT="$(docker inspect "${PROJECT}-app" --format '{{.State.ExitCode}}' 2>/dev/null)"
{ [ "$FEEDS_EXIT" != "137" ] && [ "$APP_EXIT" != "137" ]; } && ok "docker stop no mata app ni feeds con SIGKILL (exit app=$APP_EXIT feeds=$FEEDS_EXIT, $((T1-T0)) s)" || bad "app/feeds terminan con SIGKILL (137): app=$APP_EXIT feeds=$FEEDS_EXIT"
# dump con un error A MITAD: debe deshacerlo todo y NO decir 'exito' (antes dejaba la BD a medias y lo decia)
python - "$TMP/malo.sql.gz" <<'PYEOF'
import gzip, sys
with gzip.open(sys.argv[1], 'wt') as f:
    f.write('--\n-- PostgreSQL database dump\n--\nTRUNCATE users CASCADE;\nSELECT * FROM tabla_que_no_existe;\n')
PYEOF
OUT="$(DB_CONTAINER="$DBC" bash scripts/ops/restore_db.sh "$TMP/malo.sql.gz" --yes 2>&1)"; RC=$?
{ [ "$RC" != "0" ] && ! echo "$OUT" | grep -q "finalizada con"; } && ok "un error a mitad del restore devuelve error y NO imprime exito" || bad "restore con error imprimio exito (rc=$RC)"
check "...y la BD queda intacta (transaccion deshecha: users sigue igual)" "$(CNT users)" "$USR0"
OUT="$(DB_CONTAINER="$DBC" bash scripts/ops/restore_db.sh "$DUMP" --yes 2>&1)"; RC=$?
{ [ "$RC" = "0" ] && echo "$OUT" | grep -q "finalizada con"; } && ok "restore real del respaldo: finaliza con exito" || { bad "restore real fallo (rc=$RC)"; echo "$OUT" | tail -5; }
check "tras el restore, mismos usuarios" "$(CNT users)" "$USR0"
check "tras el restore, misma auditoria" "$(CNT audit_events)" "$AUD0"

# A5: restaurar en un VPS o volumen NUEVO, donde el rol soc_app aun no existe. Un respaldo ANTIGUO (con GRANT ... TO soc_app) abortaba entero
# ("role soc_app does not exist", exit 3, nada restaurado). Se simula: dump con privilegios, se borra el rol, se restaura.
check "el respaldo nuevo no lleva GRANT (pg_dump --no-acl)" "$(gzip -dc "$DUMP" | grep -c '^GRANT')" "0"
docker exec -i "$DBC" pg_dump -U soc_admin -d soc_agent --clean --if-exists 2>/dev/null | gzip > "$TMP/antiguo_con_grants.sql.gz"
check "el respaldo antiguo SI lleva GRANT a soc_app (la simulacion es valida)" "$([ "$(gzip -dc "$TMP/antiguo_con_grants.sql.gz" | grep -c '^GRANT .* TO soc_app')" -gt 0 ] && echo si || echo no)" "si"
PSQLA "DROP OWNED BY soc_app" >/dev/null; PSQLA "DROP ROLE soc_app" >/dev/null
check "servidor nuevo simulado: el rol soc_app no existe" "$(PSQLA "SELECT count(*) FROM pg_roles WHERE rolname='soc_app'")" "0"
OUT="$(DB_CONTAINER="$DBC" bash scripts/ops/restore_db.sh "$TMP/antiguo_con_grants.sql.gz" --yes 2>&1)"; RC=$?
{ [ "$RC" = "0" ] && echo "$OUT" | grep -q "finalizada con"; } && ok "restore de un respaldo antiguo en un volumen NUEVO (sin el rol soc_app) funciona" || { bad "restore en volumen NUEVO fallo (rc=$RC)"; echo "$OUT" | tail -4; }
check "...con los mismos usuarios" "$(CNT users)" "$USR0"
"${DC[@]}" up -d app feeds >/dev/null 2>&1
STATE=""; for _ in $(seq 1 40); do STATE="$(docker inspect "${PROJECT}-app" --format '{{.State.Health.Status}}' 2>/dev/null)"; [ "$STATE" = "healthy" ] && break; sleep 3; done
check "la app vuelve a estar sana tras el restore" "$STATE" "healthy"
AV="$(docker exec "${PROJECT}-app" flask audit verify 2>&1)"; AVRC=$?
{ [ "$AVRC" = "0" ] && echo "$AV" | grep -q "eslabones comprobados"; } && ok "flask audit verify tras el restore: la cadena sigue integra (el trigger y la cadena sobreviven a pg_dump --clean)" || bad "la cadena no verifica tras el restore: $(echo "$AV" | tail -2)"
check "soc_app sigue sin ser superusuario tras el restore" "$(PSQLA "SELECT rolsuper FROM pg_roles WHERE rolname='soc_app'")" "f"
check "init_db recreo el rol soc_app al arrancar app (volumen nuevo)" "$(PSQLA "SELECT count(*) FROM pg_roles WHERE rolname='soc_app'")" "1"
check "...y soc_app puede leer los datos restaurados" "$(SOCAPP "SELECT count(*) FROM users")" "$USR0"

echo "== 8. despliegue: ALLOWED_HOSTS con un dominio real, Redis y entorno del proceso web"
# A1: con un dominio real en ALLOWED_HOSTS el HEALTHCHECK (127.0.0.1) recibia 400: app unhealthy y feeds sin arrancar. Se recrea `app` con
# ALLOWED_HOSTS=soc.verify.test (sin 127.0.0.1) y se exige que llegue a healthy.
ALLOWED_HOSTS=soc.verify.test "${DC[@]}" up -d app feeds >/dev/null 2>&1
STATE=""; for _ in $(seq 1 50); do STATE="$(docker inspect "${PROJECT}-app" --format '{{.State.Health.Status}}' 2>/dev/null)"; [ "$STATE" = "healthy" ] && break; sleep 3; done
check "app llega a healthy con ALLOWED_HOSTS=soc.verify.test (sin 127.0.0.1): la sonda local se acepta" "$STATE" "healthy"
check "el dominio real responde" "$(http -H 'Host: soc.verify.test' $BASE/api/v2/health)" "200"
check "...y un cliente externo con Host 127.0.0.1 (via el puerto publicado) se rechaza" "$(http $BASE/api/v2/health)" "400"
check "feeds sigue en marcha tras recrear app" "$(docker inspect "$("${DC[@]}" ps -q feeds)" --format '{{.State.Running}}')" "true"
# M3: Redis exige contraseña
RPING="$(docker exec "${PROJECT}-redis" redis-cli ping 2>&1)"
echo "$RPING" | grep -q "NOAUTH" && ok "Redis rechaza al cliente sin contraseña (NOAUTH)" || bad "Redis responde sin contraseña: $RPING"
check "Redis acepta la contraseña" "$(docker exec "${PROJECT}-redis" redis-cli --no-auth-warning -a "$REDIS_PASSWORD" ping 2>&1)" "PONG"
# M1: el proceso web no conserva las credenciales del administrador
WEBENV="$(docker exec "${PROJECT}-app" sh -c 'tr "\0" "\n" < /proc/1/environ' 2>/dev/null)"
echo "$WEBENV" | grep -q "^MIGRATION_DATABASE_URL=" && bad "el proceso web (PID 1) conserva MIGRATION_DATABASE_URL" || ok "MIGRATION_DATABASE_URL no esta en el entorno del proceso web (gunicorn, PID 1)"
echo "$WEBENV" | grep -q "^DATABASE_URL=.*soc_app" && ok "...y su DATABASE_URL usa soc_app" || bad "DATABASE_URL del proceso web no usa soc_app"

echo
echo "RESULTADO: $PASS correctas, $FAIL fallidas"
[ "$FAIL" -eq 0 ]
