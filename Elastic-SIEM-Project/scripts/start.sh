#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# start.sh — Levanta TODO el stack y NO devuelve la consola hasta que esté listo.
#
# Arranca el stack Elastic y espera (bloqueando) a que:
#   1. Elasticsearch esté "healthy"
#   2. el servicio `setup` termine OK (password de kibana_system)
#   3. Kibana responda HTTP 200
#   4. las reglas de detección estén desplegadas
# Recién ahí libera la consola, con un resumen del estado.
#
# Además despliega las 13 reglas de detección versionadas en rules/ndjson/.
#
# Uso:  ./scripts/start.sh                 (solo el stack core)
#       ./scripts/start.sh --simulation    (además levanta ssh-target + hydra)
#       SIEM_SKIP_RULES=true ./scripts/start.sh   (sin desplegar reglas)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

# Carga ELASTIC_PASSWORD desde .env para los chequeos autenticados.
ELASTIC_PASSWORD=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- || echo "elastic123")

PROFILE_ARGS=()
[[ "${1:-}" == "--simulation" ]] && PROFILE_ARGS=(--profile simulation)

echo "🚀 Levantando el stack..."
docker compose "${PROFILE_ARGS[@]}" up -d

wait_for() { # descripción  comando-que-debe-dar-exito  intentos
  local desc="$1" cmd="$2" max="${3:-60}" i=0
  printf "⏳ %s" "$desc"
  while (( i < max )); do
    if eval "$cmd" >/dev/null 2>&1; then echo " ✔"; return 0; fi
    printf "."; sleep 3; (( i++ ))
  done
  echo " ✗ (timeout)"; return 1
}

# 1. Elasticsearch healthy
wait_for "Elasticsearch (healthy)" \
  '[ "$(docker inspect -f "{{.State.Health.Status}}" elasticsearch 2>/dev/null)" = "healthy" ]' 60

# 2. setup completó OK
wait_for "Setup kibana_system (exit 0)" \
  '[ "$(docker inspect -f "{{.State.Status}} {{.State.ExitCode}}" siem-setup 2>/dev/null)" = "exited 0" ]' 30

# 3. Kibana responde
wait_for "Kibana (HTTP 200)" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5601/api/status)" = "200" ]' 60

# 4. Reglas de detección desde el repositorio (detección como código, RF-DIF-03).
#    Antes había que crearlas a mano en la consola: quien clonaba el repositorio
#    NO obtenía el mismo sistema. Sube REGLAS DE DETECCIÓN, no acciones.
if [[ "${SIEM_SKIP_RULES:-false}" != "true" ]]; then
  echo
  ./scripts/deploy-rules.sh || echo "[AVISO] No se pudieron desplegar las reglas; el stack igual quedó arriba."
fi

echo
echo "════════════════════════════════════════════════"
docker compose "${PROFILE_ARGS[@]}" ps --format "table {{.Name}}\t{{.Status}}"
echo "════════════════════════════════════════════════"
echo "✅ Stack listo."
echo "   Kibana    → http://127.0.0.1:5601   (elastic / ${ELASTIC_PASSWORD})"
echo "   Panel     → http://127.0.0.1:5000/login   (python3 dashboard.py)"
echo "               Sin usuarios nadie entra:"
echo "               python3 manage_users.py crear <nombre> --rol analyst"
echo "   Próximo   → crear/ajustar reglas (ver rules/rules.md), atacar y correr:"
echo "               python3 siem_pipeline.py  &&  python3 dashboard.py"
