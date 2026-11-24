#!/bin/bash
# Corrida de las dos colecciones de Postman con Newman, pensada para grabar el video del entregable 2.
# Un solo comando, sin pausas ni cortes:
#
#   ./entregables/2-servicios/postman/video_newman.sh
#
# Hace, en este orden:
#   1. Reinicia la malla aislada (estado limpio) y comprueba que responde.
#   2. Corre la colección 1 (gateway) y después la 2 (servicios internos) con Newman en Docker
#      (postman/newman:6-alpine), 1 iteración, con color en pantalla (reporter cli).
#   3. Genera el reporte htmlextra y el JSON de cada una en entregables/2-servicios/reportes/corrida-video/
#      (esa carpeta se vuelve a crear en cada corrida; corrida-1 y corrida-2 no se tocan).
#   4. Muestra el resumen final: peticiones, aserciones, fallidas, tiempos y cobertura de endpoints.
# Las dos colecciones corren en la misma malla, una detrás de la otra: no hace falta reiniciar entre ellas.
#   DELAY=0 ./entregables/2-servicios/postman/video_newman.sh   corre sin pausa entre peticiones (unos 40 s en total).
# La primera vez baja el reporter htmlextra a ~/.cache/neuraldefender-newman (después ya no espera).
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../../.." && pwd)"
cd "$RAIZ" || exit 1
MALLA="$AQUI/malla.sh"
SALIDA="$RAIZ/entregables/2-servicios/reportes/corrida-video"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/neuraldefender-newman"
IMAGEN="postman/newman:6-alpine"
TTY=(); [[ -t 1 ]] && TTY=(-t)
DELAY="${DELAY:-300}"; PAUSA=(); [[ "$DELAY" -gt 0 ]] && PAUSA=(--delay-request "$DELAY")   # ms entre peticiones: con 0 Newman termina cada colección en 2 o 3 s y no se llega a leer nada

mkdir -p "$CACHE"
if [[ ! -d "$CACHE/node_modules/newman-reporter-htmlextra" ]]; then
  echo "Preparando el reporter htmlextra (solo la primera vez)..."
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$CACHE:/cache" --entrypoint sh "$IMAGEN" \
    -c "npm install --prefix /cache newman-reporter-htmlextra >/dev/null 2>&1" || { echo "No se pudo preparar htmlextra"; exit 1; }
fi
rm -rf "$SALIDA"; mkdir -p "$SALIDA"

echo "=== 1. Malla aislada: reinicio y verificación"
"$MALLA" reiniciar | grep -E "malla lista|incidentes:|coincide|no arrancó|en uso"
"$MALLA" estado | sed -n '2,9p'
echo

correr() {  # <archivo de la colección> <nombre del reporte> <título>
  local t0=$SECONDS
  docker run --rm "${TTY[@]}" --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e NODE_PATH=/cache/node_modules \
    -v "$AQUI:/etc/newman:ro" -v "$CACHE:/cache:ro" -v "$SALIDA:/salida" "$IMAGEN" \
    run "/etc/newman/$1" -e /etc/newman/NeuralDefender-malla.postman_environment.json -n 1 --color on "${PAUSA[@]}" \
    -r cli,json,htmlextra --reporter-json-export "/salida/$2.json" --reporter-htmlextra-export "/salida/$2.html" \
    --reporter-htmlextra-title "$3"
  TIEMPO[$2]=$((SECONDS - t0))
}
declare -A TIEMPO

echo "=== 2. Colección 1 - Gateway (pruebas CP-SERV-01 a CP-SERV-49)"
correr NeuralDefender-Coleccion1-gateway.postman_collection.json coleccion1-gateway "Colección 1 (gateway)"
echo
echo "=== 3. Colección 2 - Servicios internos (pruebas CP-SERV-50 a CP-SERV-89)"
correr NeuralDefender-Coleccion2-internos.postman_collection.json coleccion2-internos "Colección 2 (servicios internos)"
echo

echo "=== 4. Resumen de la corrida"
for a in coleccion1-gateway coleccion2-internos; do
  [[ -s "$SALIDA/$a.json" ]] || { echo "  ERROR: Newman no generó $a.json; la corrida no terminó bien."; exit 1; }
done
python3 - "$SALIDA" "${TIEMPO[coleccion1-gateway]:-0}" "${TIEMPO[coleccion2-internos]:-0}" <<'E'
import json, sys
d, t1, t2 = sys.argv[1], sys.argv[2], sys.argv[3]
tot_p = tot_a = tot_f = 0
print(f"  {'Colección':<34}{'Peticiones':>11}{'Aserciones':>12}{'Fallidas':>10}{'Tiempo':>9}")
for nombre, arch, t in (("1 - Gateway", "coleccion1-gateway", t1), ("2 - Servicios internos", "coleccion2-internos", t2)):
    s = json.load(open(f"{d}/{arch}.json"))["run"]["stats"]
    p, a, f = s["requests"]["total"], s["assertions"]["total"], s["assertions"]["failed"]
    tot_p, tot_a, tot_f = tot_p + p, tot_a + a, tot_f + f
    print(f"  {nombre:<34}{p:>11}{a:>12}{f:>10}{t + ' s':>9}")
print(f"  {'TOTAL':<34}{tot_p:>11}{tot_a:>12}{tot_f:>10}")
print(f"\n  Aserciones aprobadas: {tot_a - tot_f}/{tot_a}")
E
python3 "$AQUI/analizar_corrida.py.txt" "$SALIDA" | grep "^Ambas" | sed 's/ | sin petición.*//; s/^Ambas:/  Cobertura de endpoints (de 56):/'
echo
echo "  Reportes HTML: $SALIDA"
