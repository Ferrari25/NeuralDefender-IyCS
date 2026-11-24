#!/usr/bin/env bash
# Pruebas de performance del panel con k6 (tests/performance/neuraldefender.js).
#
#   ./scripts/pruebas_de_performance.sh [humo|carga|estres|pico|login]   (default: humo)
#
# k6 corre en un contenedor (grafana/k6, versión fija): no hay que instalar nada.
# Usa la red del host para llegar al panel en 127.0.0.1:5000, que es el único
# puerto publicado.
#
# Credenciales: K6_USUARIO y K6_CLAVE del entorno. Si no están, se usa el usuario
# de solo lectura `k6-carga` (rol auditor: no puede decidir nada) y se crea la
# primera vez con una contraseña aleatoria guardada en .k6-credenciales (0600,
# fuera de git).
#
# Resultados en reportes/performance/<fecha>-<perfil>.{html,json}: el HTML es el
# panel web de k6 exportado (gráficos de latencia, VUs y errores en el tiempo).
set -euo pipefail

cd "$(dirname "$0")/.."

PERFIL="${1:-${PERFIL:-humo}}"
K6_IMAGEN="grafana/k6:1.3.0"
BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
CREDENCIALES=".k6-credenciales"
SALIDA="reportes/performance"

case "$PERFIL" in
  humo|carga|estres|pico|login) ;;
  *) echo "Perfil desconocido: $PERFIL (humo|carga|estres|pico|login)" >&2; exit 2 ;;
esac

if ! curl -fsS "$BASE_URL/api/v1/healthz" >/dev/null; then
  echo "❌ El panel no responde en $BASE_URL. Levantarlo con ./scripts/start.sh o" >&2
  echo "   docker compose up -d gateway" >&2
  exit 1
fi

if [[ -z "${K6_USUARIO:-}" || -z "${K6_CLAVE:-}" ]]; then
  if [[ ! -f "$CREDENCIALES" ]]; then
    echo "→ Creando el usuario de solo lectura k6-carga (rol auditor)…"
    clave="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    docker compose exec -T -e SIEM_NEW_PASSWORD="$clave" auth \
      python manage_users.py crear k6-carga --rol auditor
    umask 077
    printf 'K6_USUARIO=k6-carga\nK6_CLAVE=%s\n' "$clave" > "$CREDENCIALES"
  fi
  # shellcheck disable=SC1090
  set -a
  # shellcheck source=/dev/null # ruta variable: .k6-credenciales no se versiona
  source "$CREDENCIALES"
  set +a
fi

mkdir -p "$SALIDA"
marca="$(date +%Y%m%d-%H%M%S)-$PERFIL"

echo "→ k6 · perfil $PERFIL contra $BASE_URL (resultados en $SALIDA/$marca.*)"
set +e
docker run --rm --network host \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/performance:/pruebas:ro" \
  -v "$PWD/$SALIDA:/salida" \
  -e PERFIL="$PERFIL" -e BASE_URL="$BASE_URL" \
  -e K6_USUARIO -e K6_CLAVE \
  -e K6_WEB_DASHBOARD=true \
  -e K6_WEB_DASHBOARD_EXPORT="/salida/$marca.html" \
  -e K6_WEB_DASHBOARD_PORT=-1 \
  "$K6_IMAGEN" run --summary-export "/salida/$marca.json" /pruebas/neuraldefender.js
codigo=$?
set -e

case $codigo in
  0)  echo "✅ Perfil $PERFIL: todos los umbrales se cumplieron." ;;
  99) echo "⚠️  Perfil $PERFIL: algún umbral no se cumplió (ver el resumen de arriba)." ;;
  *)  echo "❌ k6 terminó con error ($codigo)." ;;
esac
echo "   Reporte: $SALIDA/$marca.html"
exit $codigo
