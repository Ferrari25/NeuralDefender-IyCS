#!/bin/bash
# Controla la malla aislada de NeuralDefender para usarla desde Postman de escritorio.
#
#   ./entregables/2-servicios/postman/malla.sh iniciar     levanta los 8 servicios en segundo plano
#       opciones (iniciar y reiniciar; sin ellas la malla es la de siempre):
#         --incidentes N      siembra N incidentes (por defecto 3)
#         --analistas N       usuarios analista00..analista{N-1} (por defecto 1)
#         --decisiones N      siembra N decisiones en el registro de auditoría (200 por día de uso)
#         --ciclo [SEGUNDOS]  ciclo del pipeline (por defecto cada 120 s) con el collector SIN Elasticsearch
#   ./entregables/2-servicios/postman/malla.sh detener     los apaga y descarta los datos temporales
#   ./entregables/2-servicios/postman/malla.sh reiniciar   detener + iniciar (vuelve al estado inicial)
#   ./entregables/2-servicios/postman/malla.sh estado      dice si corre y consulta la salud de cada servicio
#
# Puertos, token y contraseña son fijos (ver levantar_malla.py.txt) y coinciden con el entorno
# NeuralDefender-malla.postman_environment.json. SIEM_PIPELINE_INTERVALO=0: sin ciclo programado.
# No modifica el producto ni toca el sistema real (los datos de la malla son temporales).
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../../.." && pwd)"
PIDFILE="$AQUI/.malla.pid"; LOG="$AQUI/malla.log"
PUERTOS=(18080 18001 18002 18003 18004 18005 18006 18007)
TOKEN="token-interno-de-prueba-malla-postman-2026-0001"

corriendo() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

iniciar() {
  local opciones=("$@")
  if corriendo; then echo "La malla ya está corriendo (PID $(cat "$PIDFILE"))."; return 0; fi
  for p in "${PUERTOS[@]}"; do
    if (echo > "/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "El puerto $p ya está en uso: no se puede iniciar."; return 1; fi
  done
  cd "$RAIZ" || return 1
  SIEM_PIPELINE_INTERVALO=0 PYTHONPATH="$RAIZ/.devtools${PYTHONPATH:+:$PYTHONPATH}" \
    setsid nohup python3 "$AQUI/levantar_malla.py.txt" "${opciones[@]}" > "$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  for _ in $(seq 1 90); do
    grep -q "^malla lista" "$LOG" 2>/dev/null && { sed -n '/^malla lista/,$p' "$LOG"; return 0; }
    corriendo || { echo "La malla no arrancó. Log:"; cat "$LOG"; rm -f "$PIDFILE"; return 1; }
    sleep 1
  done
  echo "La malla no respondió en 90 s. Log:"; cat "$LOG"; return 1
}

detener() {
  if ! corriendo; then echo "La malla no está corriendo."; rm -f "$PIDFILE"; return 0; fi
  kill -TERM "$(cat "$PIDFILE")"
  for _ in $(seq 1 20); do corriendo || break; sleep 0.5; done
  corriendo && { kill -KILL "$(cat "$PIDFILE")"; echo "Hubo que forzar el cierre."; }
  rm -f "$PIDFILE"; echo "Malla detenida; datos temporales descartados."
}

estado() {
  corriendo && echo "Malla corriendo (PID $(cat "$PIDFILE"))." || { echo "Malla detenida."; return 1; }
  for s in "gateway 18080 /api/v1/healthz" "auth 18001 /v1/healthz" "audit 18002 /v1/healthz" \
           "collector 18003 /v1/healthz" "classifier 18004 /v1/healthz" "analyst 18005 /v1/healthz" \
           "pipeline 18006 /v1/healthz" "knowledge 18007 /v1/healthz"; do
    set -- $s
    printf '  %-11s http://127.0.0.1:%s  ' "$1" "$2"
    curl -s -m 5 -o /dev/null -w 'HTTP %{http_code}\n' "http://127.0.0.1:$2$3" || echo "sin respuesta"
  done
}

case "${1:-}" in
  iniciar) shift; iniciar "$@" ;;
  detener) detener ;;
  reiniciar) shift; detener; iniciar "$@" ;;
  estado) estado ;;
  *) echo "Uso: $0 {iniciar|detener|reiniciar|estado}"; exit 2 ;;
esac
