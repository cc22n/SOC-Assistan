#!/usr/bin/env bash
# =============================================================================
# Compila app/static/css/tailwind.css (Tailwind CSS 3.4.17, la misma versión que servía el CDN).
#
#   bash scripts/build_css.sh          # regenera el CSS
#   bash scripts/build_css.sh --check  # falla si el CSS commiteado no coincide con el que saldría ahora
#
# Requiere Node >= 18 y acceso al registro de npm (descarga tailwindcss@3.4.17 a la caché de npm; no se
# instala nada en el repo). El CSS generado SE COMMITEA: la imagen Docker no necesita Node.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

TAILWIND_VERSION="3.4.17"
OUT="app/static/css/tailwind.css"

build() {
  npx --yes "tailwindcss@${TAILWIND_VERSION}" \
    -c ./tailwind.config.js \
    -i ./app/static/css/tailwind.input.css \
    -o "$1" \
    --minify
}

if [ "${1:-}" = "--check" ]; then
  TMP="$(mktemp)"
  build "$TMP" >/dev/null 2>&1
  if cmp -s "$TMP" "$OUT"; then
    echo "OK: $OUT está al día"
  else
    echo "DESACTUALIZADO: $OUT no coincide con la compilación actual. Ejecuta: bash scripts/build_css.sh"
    rm -f "$TMP"
    exit 1
  fi
  rm -f "$TMP"
else
  build "$OUT"
  echo "Generado $OUT ($(wc -c < "$OUT") bytes)"
fi
