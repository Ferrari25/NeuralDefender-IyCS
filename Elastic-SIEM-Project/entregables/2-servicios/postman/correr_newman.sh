#!/bin/bash
# Corre las dos colecciones con Newman 6 (en Docker) contra la malla aislada, con los reporters
# cli, json y htmlextra. Reinicia la malla antes para partir de un estado limpio.
#
# Uso (desde Elastic-SIEM-Project/):
#   ./entregables/2-servicios/postman/correr_newman.sh <carpeta de salida>
#   ./entregables/2-servicios/postman/correr_newman.sh entregables/2-servicios/reportes/corrida-1
#
# Genera en la carpeta de salida, para cada colección: coleccion<N>-<nombre>.html, .json y .txt (consola).
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../../.." && pwd)"
SALIDA="$(mkdir -p "${1:?falta la carpeta de salida}" && cd "$1" && pwd)"
cd "$RAIZ" || exit 1

"$AQUI/malla.sh" reiniciar || exit 1
echo

correr() { # numero nombre archivo titulo
  local n=$1 nombre=$2 archivo=$3 titulo=$4 base="coleccion$1-$2"
  echo "=== Colección $n: $titulo"
  docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$AQUI:/etc/newman:ro" -v "$SALIDA:/salida" --entrypoint sh postman/newman:6-alpine -c "
      npm install --prefix /tmp/rep newman-reporter-htmlextra >/dev/null 2>&1
      NODE_PATH=/tmp/rep/node_modules newman run /etc/newman/$archivo -n 1 \
        -e /etc/newman/NeuralDefender-malla.postman_environment.json --color off \
        -r cli,json,htmlextra --reporter-json-export /salida/$base.json \
        --reporter-htmlextra-export /salida/$base.html --reporter-htmlextra-title '$titulo' \
        --reporter-htmlextra-browserTitle 'NeuralDefender - $titulo'" 2>&1 | tee "$SALIDA/$base.txt"
  echo
}
correr 1 gateway NeuralDefender-Coleccion1-gateway.postman_collection.json "Colección 1 (gateway)"
correr 2 internos NeuralDefender-Coleccion2-internos.postman_collection.json "Colección 2 (servicios internos)"
echo "Reportes en: $SALIDA"
