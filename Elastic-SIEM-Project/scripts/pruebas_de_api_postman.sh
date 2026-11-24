#!/usr/bin/env bash
# Pruebas de servicio (API) con Postman + Newman sobre la malla aislada.
#
# Levanta los 8 servicios reales en procesos locales con datos temporales
# (tests/postman/malla_postman.py), corre la colección con Newman en Docker y
# deja el reporte en reportes/postman/. Las escrituras nunca tocan la auditoría
# real del stack: es inmutable (RF-AUD-03).
#
# Uso: ./scripts/pruebas_de_api_postman.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

TMP="$(mktemp -d)"
ENTORNO="$TMP/entorno.json"
SALIDA="reportes/postman"
mkdir -p "$SALIDA"

python3 tests/postman/malla_postman.py --entorno "$ENTORNO" > "$TMP/malla.log" 2>&1 &
MALLA=$!
trap 'kill $MALLA 2>/dev/null || true; wait $MALLA 2>/dev/null || true; rm -rf "$TMP"' EXIT

for _ in $(seq 1 60); do
  grep -q "malla lista" "$TMP/malla.log" 2>/dev/null && break
  kill -0 $MALLA 2>/dev/null || { cat "$TMP/malla.log"; exit 1; }
  sleep 1
done
grep "malla lista" "$TMP/malla.log"

FECHA="$(date +%Y%m%d-%H%M%S)"
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/postman:/etc/newman:ro" -v "$TMP:/entorno:ro" -v "$PWD/$SALIDA:/salida" \
  postman/newman:6-alpine run neuraldefender.postman_collection.json \
  -e /entorno/entorno.json --color on \
  -r cli,json --reporter-json-export "/salida/newman-$FECHA.json"
echo "Reporte: $SALIDA/newman-$FECHA.json"
