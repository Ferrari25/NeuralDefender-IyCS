#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy.sh — Levanta SIEM-IA de punta a punta, TODO reseteado (ver nicotito.md).
#
# Pasos:
#   1. Verifica .env y vm.max_map_count (Elasticsearch no arranca sin él).
#   2. Construye las imágenes de los microservicios de la capa IA.
#   3. Reset completo (./scripts/reset.sh --yes): baja Docker, borra el volumen
#      de Elasticsearch (eventos, índices y alertas) y los artefactos del
#      pipeline. La auditoría se ARCHIVA en data/audit/archivo/, nunca se borra.
#   4. Reinicia los usuarios del panel y crea la cuenta 'nico' (rol analyst),
#      dentro del contenedor del servicio auth.
#   5. Levanta el stack Elastic + la capa IA y despliega las 14 reglas
#      (./scripts/start.sh).
#   6. Verifica que el panel (servicio gateway) responda
#      → http://127.0.0.1:5000/login  (logs: docker compose logs -f gateway)
#
# Uso:  ./scripts/deploy.sh          despliega todo y deja el panel corriendo
#       ./scripts/deploy.sh --stop   apaga la capa IA (los microservicios)
#
# ⚠️  La contraseña de 'nico' está fija en este script para el laboratorio.
#     No uses este script tal cual en un entorno real.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

# NO correr con sudo: el dashboard y los archivos del proyecto (users.json,
# data/, audit/) tienen que ser del usuario normal. Si el script corre como root,
# users.json queda root:root 0600 y el panel —que corre como usuario— no puede
# leerlo: nadie puede iniciar sesión. El script pide sudo solo para Docker.
if [[ $EUID -eq 0 ]]; then
  echo "✗ No corras este script con sudo. Corré:  ./scripts/deploy.sh"
  echo "  (pide la contraseña de sudo solo si Docker la necesita)"
  exit 1
fi

USUARIO="nico"
PASSWORD="123456789000"
ROL="analyst"

SERVICIOS_IA=(gateway pipeline analyst classifier collector audit auth)

# Los servicios corren sin privilegios con el UID/GID de quien despliega: así
# los volúmenes de data/<servicio>/ siguen siendo del usuario (ver start.sh).
export SIEM_UID SIEM_GID
SIEM_UID=$(id -u)
SIEM_GID=$(id -g)

# Un panel lanzado por la versión anterior de este script (proceso suelto, antes
# de la migración a microservicios) ocuparía el puerto 5000.
detener_panel_viejo() {
  local pid_file="data/dashboard.pid"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    kill "$(cat "$pid_file")"
    echo "  Panel anterior (proceso suelto) detenido."
  fi
  rm -f "$pid_file"
}

if [[ "${1:-}" == "--stop" ]]; then
  detener_panel_viejo
  docker compose stop "${SERVICIOS_IA[@]}"
  exit 0
fi

PASO_ACTUAL=""
paso() { PASO_ACTUAL="$1"; printf '\n\033[1;36m━━ %s ━━\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$1"; }
mal()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }

trap 'rc=$?; if (( rc != 0 )); then mal "deploy.sh se cortó en el paso «$PASO_ACTUAL» (código $rc). El panel NO quedó corriendo."; fi' EXIT

# ─── 1 · Requisitos ──────────────────────────────────────────────────────────

paso "1/6 · Requisitos"

if [[ ! -f .env ]]; then
  mal "Falta .env. Copiá .env.example a .env y completalo (nicotito.md §3)."
  exit 1
fi
ok ".env presente"

for cmd in docker python3 curl; do
  command -v "$cmd" >/dev/null || { mal "Falta '$cmd' en el sistema."; exit 1; }
done
ok "docker, python3 y curl disponibles"

# Si el usuario no está en el grupo `docker`, el socket rechaza la conexión. En vez
# de correr TODO con sudo, se antepone al PATH un `docker` que llama a
# `sudo docker`: así reset.sh y start.sh funcionan sin cambios y el resto de los
# archivos sigue siendo del usuario.
if ! docker info >/dev/null 2>&1; then
  echo "  Tu usuario no tiene acceso directo a Docker: se va a usar sudo solo para docker."
  sudo -v
  SHIM_DIR=$(mktemp -d)
  printf '#!/bin/sh\nexec sudo docker "$@"\n' > "$SHIM_DIR/docker"
  chmod +x "$SHIM_DIR/docker"
  export PATH="$SHIM_DIR:$PATH"
  docker info >/dev/null 2>&1 || { mal "Docker no responde ni con sudo (¿está corriendo el servicio?)."; exit 1; }
fi
docker compose version >/dev/null 2>&1 || { mal "Falta Docker Compose v2."; exit 1; }
ok "Docker accesible"

# Archivos que quedaron de root por una corrida anterior con sudo: se devuelven al
# usuario (si no, el panel no puede leer users.json y nadie entra).
DE_ROOT=$(find . -path ./node_modules -prune -o -path ./.devtools -prune -o -path ./elasticsearch -prune \
               -o ! -user "$(id -u)" -print 2>/dev/null || true)
# (`|| true`: find sale con 1 si no puede entrar a una carpeta de root —justo el
# caso que se quiere arreglar— y con `set -e` eso cortaría el script.)
if [[ -n "$DE_ROOT" ]]; then
  echo "  Hay archivos del proyecto que no son tuyos (corrida anterior con sudo); se corrigen:"
  echo "$DE_ROOT" | sed 's/^/    /'
  if ! echo "$DE_ROOT" | xargs -d '\n' sudo chown -R "$(id -u):$(id -g)"; then
    mal "no se pudieron corregir los permisos (sudo chown falló)."
    exit 1
  fi
  ok "permisos corregidos"
fi

if [[ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]]; then
  echo "  vm.max_map_count es bajo; Elasticsearch lo necesita en 262144 (pide sudo)."
  sudo sysctl -w vm.max_map_count=262144 >/dev/null
fi
ok "vm.max_map_count >= 262144"

# Token interno de los microservicios (start.sh también lo genera, pero el paso
# 2 ya lo necesita para validar el compose).
if ! grep -qE '^SIEM_INTERNAL_TOKEN=.{32,}' .env; then
  printf '\n# Token interno entre microservicios (generado por deploy.sh)\nSIEM_INTERNAL_TOKEN=%s\n' \
    "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
  ok "SIEM_INTERNAL_TOKEN generado en .env"
fi

# ─── 2 · Imágenes de los microservicios ──────────────────────────────────────

paso "2/6 · Imágenes de los microservicios (capa IA)"

# Las dependencias Python ya no se instalan en el host: cada servicio trae las
# suyas en su imagen. (.devtools/ sigue haciendo falta solo para las pruebas.)
docker compose build "${SERVICIOS_IA[@]}"
ok "imágenes construidas"

# ─── 3 · Reset ───────────────────────────────────────────────────────────────

paso "3/6 · Reset completo (Docker, eventos, alertas, artefactos)"

detener_panel_viejo
./scripts/reset.sh --yes
if curl -s -o /dev/null http://127.0.0.1:5000/login 2>/dev/null; then
  mal "Hay algo escuchando en el puerto 5000 que no es de este proyecto. Cerralo y reintentá."
  exit 1
fi

# ─── 4 · Usuarios del panel ──────────────────────────────────────────────────

paso "4/6 · Cuenta del panel"

# El almacén vive en el volumen del servicio auth.
USERS_FILE="data/auth/users.json"
mkdir -p data/auth data/audit data/collector data/pipeline data/knowledge
if [[ -f "$USERS_FILE" ]]; then
  # Se guarda una copia por las dudas: son hashes, no se pueden reconstruir.
  cp "$USERS_FILE" "$USERS_FILE.bak"
  rm -f "$USERS_FILE"
  ok "usuarios anteriores eliminados (copia en $USERS_FILE.bak)"
fi

# `run --rm --no-deps`: un contenedor efímero del servicio auth, sobre su mismo
# volumen, sin necesitar el resto del stack arriba.
SIEM_NEW_PASSWORD="$PASSWORD" docker compose run --rm --no-deps -T -e SIEM_NEW_PASSWORD \
  auth python manage_users.py crear "$USUARIO" --rol "$ROL"

# ─── 5 · Stack Elastic + reglas ──────────────────────────────────────────────

paso "5/6 · Stack Elastic + reglas de detección"

./scripts/start.sh

# ─── 6 · Panel de supervisión ────────────────────────────────────────────────

paso "6/6 · Panel de supervisión (gateway)"

# start.sh ya esperó al gateway; acá se confirma que la página de login carga.
if [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/login)" != "200" ]]; then
  mal "el panel no responde. Últimas líneas del gateway:"
  docker compose logs --tail 20 gateway
  exit 1
fi
ok "panel respondiendo"

ELASTIC_PASSWORD=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2-)
echo
echo "════════════════════════════════════════════════"
echo "✅ SIEM-IA listo y corriendo, todo en cero."
echo "   Panel   → http://127.0.0.1:5000/login   ($USUARIO / $PASSWORD)"
echo "   Kibana  → http://127.0.0.1:5601         (elastic / $ELASTIC_PASSWORD)"
echo "   Logs del panel:    docker compose logs -f gateway"
echo "   Correr el análisis: ./scripts/siem.sh pipeline"
echo "   Apagar la capa IA: ./scripts/deploy.sh --stop"
echo "   Apagar el stack:   docker compose --profile simulation down"
echo "════════════════════════════════════════════════"
