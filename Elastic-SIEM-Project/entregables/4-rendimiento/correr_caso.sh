#!/bin/bash
# Corre un caso de rendimiento (CP-REN-NN) con k6 en contenedor contra la malla aislada.
#
#   ./entregables/4-rendimiento/correr_caso.sh <NN|todos> <carpeta de salida> [ESCALA]
#
# Antes de cada caso reinicia la malla con la configuración que pide su precondición (plan, sección 7).
# Por caso guarda en la carpeta de salida: cp-ren-NN.json (--summary-export), cp-ren-NN.html (panel web de k6),
# cp-ren-NN.vmstat.txt (CPU y memoria del equipo cada 5 s) y cp-ren-NN.consola.txt.
# CP-REN-09 corre al mismo tiempo que CP-REN-07 (otro contenedor), así que `07` ejecuta las dos.
# `todos` corre en orden 01, 02, 03, 04, 05, 06, 07 (+09) y 08; los p95 que necesitan 04 y 08 salen de 02 y 01.
# ESCALA (opcional, por defecto 1) acorta las duraciones solo para probar los scripts: no usar en corridas oficiales.
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
MALLA="$RAIZ/entregables/2-servicios/postman/malla.sh"
CASO="${1:?uso: correr_caso.sh <NN|todos> <carpeta de salida> [ESCALA]}"
SALIDA="$(mkdir -p "${2:?falta la carpeta de salida}" && cd "$2" && pwd)"
ESCALA="${3:-1}"
K6_IMAGEN="grafana/k6:1.3.0"
CLAVE="PruebaMalla#2026"                 # contraseña fija de la malla (levantar_malla.py.txt)
cd "$RAIZ" || exit 1

declare -A NOMBRE=([01]=humo [02]=carga-lecturas [03]=carga-escrituras [04]=carga-con-ciclo
  [05]=autenticacion-concurrente [06]=trazabilidad [07]=estres [08]=pico [09]=sonda)
declare -A MALLA_OPC=([01]="--incidentes 100" [02]="--incidentes 100" [03]="--incidentes 100"
  [04]="--incidentes 100 --ciclo" [05]="--analistas 50" [06]="--analistas 50" [07]="--incidentes 100"
  [08]="--incidentes 100")

p95() {  # <json> <metrica>  -> p(95) en ms
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['metrics'][sys.argv[2]]['p(95)'])" "$1" "$2"
}

k6() {  # <NN> [variables -e ...]  (corre un script y deja sus archivos)
  local nn="$1"; shift
  local base="cp-ren-$nn"
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "$RAIZ/tests/performance:/pruebas:ro" -v "$SALIDA:/salida" \
    -e BASE_URL="http://127.0.0.1:18080" -e K6_CLAVE="$CLAVE" -e K6_USUARIO="analista00" -e ESCALA="$ESCALA" \
    -e K6_WEB_DASHBOARD=true -e "K6_WEB_DASHBOARD_EXPORT=/salida/$base.html" -e K6_WEB_DASHBOARD_PORT=-1 \
    "$@" "$K6_IMAGEN" run --summary-export "/salida/$base.json" "/pruebas/cp-ren-$nn-${NOMBRE[$nn]}.js" \
    > "$SALIDA/$base.consola.txt" 2>&1
  echo "$?" > "$SALIDA/$base.codigo.txt"
}

caso() {
  local nn="$1"
  echo "=== CP-REN-$nn (${NOMBRE[$nn]}) — malla: ${MALLA_OPC[$nn]}"
  # shellcheck disable=SC2086  # las opciones de la malla se separan a propósito
  "$MALLA" reiniciar ${MALLA_OPC[$nn]} | grep -E "ciclo:|incidentes:|no arrancó|en uso" || true
  vmstat -t 5 > "$SALIDA/cp-ren-$nn.vmstat.txt" 2>&1 & local vm=$!
  local extra=()
  case "$nn" in
    04) extra=(-e "P95_REN02_INCIDENTES=$(p95 "$SALIDA/cp-ren-02.json" t_incidentes)") ;;
    08) for e in me incidentes decisiones memoria; do
          extra+=(-e "P95_NOM_${e^^}=$(p95 "$SALIDA/cp-ren-01.json" "t_$e")"); done ;;
  esac
  if [[ "$nn" == 07 ]]; then
    k6 09 & local sonda=$!         # la sonda corre en paralelo con el estrés
    k6 07
    wait "$sonda"
  else
    k6 "$nn" "${extra[@]}"
  fi
  kill "$vm" 2>/dev/null; wait "$vm" 2>/dev/null
  echo "    código de k6: $(cat "$SALIDA/cp-ren-$nn.codigo.txt")$([[ "$nn" == 07 ]] && echo "; CP-REN-09: $(cat "$SALIDA/cp-ren-09.codigo.txt")")"
}

if [[ "$CASO" == todos ]]; then
  for nn in 01 02 03 04 05 06 07 08; do caso "$nn"; done
else
  caso "$CASO"
fi
"$MALLA" detener >/dev/null
echo "Resultados en: $SALIDA"
