#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# start.sh — Levanta TODO el stack y NO devuelve la consola hasta que esté listo.
#
# Arranca el stack Elastic y la capa IA (microservicios), y espera (bloqueando) a que:
#   1. Elasticsearch esté "healthy"
#   2. el servicio `setup` termine OK (password de kibana_system)
#   3. Kibana responda HTTP 200
#   4. las reglas de detección estén desplegadas
#   5. el gateway (panel de supervisión) responda
# Recién ahí libera la consola, con un resumen del estado.
#
# Además despliega las 14 reglas de detección versionadas en rules/ndjson/.
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

# Token interno de los microservicios: sin él no arranca ninguno (igual que el
# panel sin SECRET_KEY). Si falta en .env, se genera uno — es un secreto entre
# contenedores de esta máquina, no algo que una persona tenga que elegir.
if ! grep -qE '^SIEM_INTERNAL_TOKEN=.{32,}' .env; then
  echo "🔑 Generando SIEM_INTERNAL_TOKEN en .env (no existía)."
  printf '\n# Token interno entre microservicios (generado por start.sh)\nSIEM_INTERNAL_TOKEN=%s\n' \
    "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
fi

# Cada servicio es dueño de su directorio de datos (bind mount). Se crean ACÁ,
# como el usuario actual: si los crea Docker al montarlos, quedan de root y los
# servicios —que corren sin privilegios, con este mismo UID— no pueden escribir.
mkdir -p data/auth data/audit data/collector data/pipeline data/knowledge network_logs
export SIEM_UID SIEM_GID
SIEM_UID=$(id -u)
SIEM_GID=$(id -g)

echo "🚀 Levantando el stack (Elastic + microservicios de la capa IA)..."
docker compose "${PROFILE_ARGS[@]}" up -d --build

wait_for() { # descripción  comando-que-debe-dar-exito  intentos
  local desc="$1" cmd="$2" max="${3:-60}" i=0
  printf "⏳ %s" "$desc"
  while (( i < max )); do
    if eval "$cmd" >/dev/null 2>&1; then echo " ✔"; return 0; fi
    printf "."; sleep 3; i=$((i + 1))
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

# 5. Capa IA: el gateway depende (healthcheck) de auth, audit y pipeline, que a
#    su vez dependen del resto; si responde, la malla entera está arriba.
wait_for "Panel de supervisión (gateway)" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/api/v1/healthz)" = "200" ]' 60

echo
echo "════════════════════════════════════════════════"
docker compose "${PROFILE_ARGS[@]}" ps --format "table {{.Name}}\t{{.Status}}"
echo "════════════════════════════════════════════════"
echo "✅ Stack listo."
echo "   Kibana    → http://127.0.0.1:5601   (elastic / ${ELASTIC_PASSWORD})"
echo "   Panel     → http://127.0.0.1:5000/login   (servicio gateway)"
echo "               Sin usuarios nadie entra:"
echo "               ./scripts/siem.sh usuarios crear <nombre> --rol analyst"
echo "   Próximo   → crear/ajustar reglas (ver rules/rules.md), atacar y correr:"
echo "               ./scripts/siem.sh pipeline"
