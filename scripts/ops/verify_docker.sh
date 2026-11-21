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

python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32)); print('FLASK_APP=wsgi.py')" > "$TMP/verify.env"
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

echo
echo "RESULTADO: $PASS correctas, $FAIL fallidas"
[ "$FAIL" -eq 0 ]
