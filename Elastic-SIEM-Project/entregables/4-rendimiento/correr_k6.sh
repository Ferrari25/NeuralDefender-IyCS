#!/bin/bash
# Corre las pruebas de rendimiento de tests/performance/k6_api_test.js contra la malla aislada, con el
# esquema de perfil de uso por grupo de endpoints (plan 4.1):
#
#   ./entregables/4-rendimiento/correr_k6.sh                        carga + el estrés de los 4 grupos (corrida oficial)
#   ./entregables/4-rendimiento/correr_k6.sh carga                  solo la carga (todos los grupos en paralelo)
#   ./entregables/4-rendimiento/correr_k6.sh lecturas login         solo el estrés de esos grupos
#
# Grupos de estrés: lecturas, decisiones, login, auditoria. Antes de CADA corrida reinicia la malla con
# 100 incidentes, 20 analistas y 1.400 decisiones sembradas (7 días de uso a 200 por día), sin ciclo del pipeline.
# k6 corre con grafana/k6:1.3.0 y --network host. Deja en tests/performance/:
#   summary.json | summary_estres_<grupo>.json    resumen exportado por handleSummary
#   reporte_carga.html | reporte_estres_<grupo>.html   panel web de k6 exportado
#   vmstat_<corrida>.txt                           CPU y memoria del equipo cada 5 s
#   consola_<corrida>.txt                          salida de k6
#   corrida_<corrida>.json                         fecha, hora, duración real y código de salida de k6
# NOTA (opcional) queda escrita en corrida_<corrida>.json y se muestra en el informe.
# ESCALA (por defecto 1) acorta las duraciones SOLO para probar el script: no usar en corridas oficiales.
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
MALLA="$RAIZ/entregables/2-servicios/postman/malla.sh"
DESTINO="$RAIZ/tests/performance"
ESCALA="${ESCALA:-1}"
cd "$RAIZ" || exit 1
OBJETIVOS=("$@"); [[ ${#OBJETIVOS[@]} -eq 0 ]] && OBJETIVOS=(carga lecturas decisiones login auditoria)

for objetivo in "${OBJETIVOS[@]}"; do
  case "$objetivo" in
    carga) escenario=carga; grupo=""; base=carga; resumen=summary.json ;;
    lecturas|decisiones|login|auditoria) escenario=estres; grupo="$objetivo"; base="estres_$objetivo"; resumen="summary_estres_$objetivo.json" ;;
    *) echo "Objetivo desconocido: $objetivo (carga|lecturas|decisiones|login|auditoria)" >&2; exit 2 ;;
  esac
  echo "=== $base: reiniciando la malla (100 incidentes, 20 analistas, 1.400 decisiones, sin ciclo)"
  "$MALLA" reiniciar --incidentes 100 --analistas 20 --decisiones 1400 | grep -E "incidentes:|no arrancó|en uso"
  vmstat -t 5 > "$DESTINO/vmstat_$base.txt" 2>&1 & vm=$!
  inicio="$(date -Iseconds)"; t0=$SECONDS
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "$DESTINO:/repo/tests/performance" -w /repo \
    -e ESCENARIO="$escenario" -e GRUPO="$grupo" -e ESCALA="$ESCALA" -e BASE_URL=http://127.0.0.1:18080 -e K6_CLAVE='PruebaMalla#2026' \
    -e K6_WEB_DASHBOARD=true -e "K6_WEB_DASHBOARD_EXPORT=/repo/tests/performance/reporte_$base.html" -e K6_WEB_DASHBOARD_PORT=-1 \
    grafana/k6:1.3.0 run tests/performance/k6_api_test.js > "$DESTINO/consola_$base.txt" 2>&1
  codigo=$?
  segundos=$((SECONDS - t0)); fin="$(date -Iseconds)"
  kill "$vm" 2>/dev/null; wait "$vm" 2>/dev/null
  printf '{"corrida": "%s", "escenario": "%s", "grupo": "%s", "inicio": "%s", "fin": "%s", "segundos": %d, "codigo_k6": %d, "escala": %s, "resumen": "%s", "nota": "%s"}\n' \
    "$base" "$escenario" "$grupo" "$inicio" "$fin" "$segundos" "$codigo" "$ESCALA" "$resumen" "${NOTA:-}" > "$DESTINO/corrida_$base.json"
  echo "    $base: k6 terminó con código $codigo (0 = todos los umbrales; 99 = alguno no) en $segundos s"
done
"$MALLA" detener > /dev/null
