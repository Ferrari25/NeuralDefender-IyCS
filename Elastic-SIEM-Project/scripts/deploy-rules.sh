#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy-rules.sh — Despliega el catálogo de reglas de DETECCIÓN en Kibana.
#
# ⚠️  QUÉ SIGNIFICA "DESPLEGAR" ACÁ, Y QUÉ NO.
#
# Este script sube REGLAS DE DETECCIÓN al SIEM: le enseña a Elastic qué patrones
# tiene que reconocer en los logs. NO ejecuta ninguna acción sobre la
# infraestructura, no bloquea IPs, no toca firewalls ni hosts.
#
# La propiedad rectora del proyecto sigue intacta: la IA sugiere, el humano
# decide, y el sistema no ejecuta acciones de contención. Detectar no es actuar.
#
# ─────────────────────────────────────────────────────────────────────────────
# Cierra el hallazgo F-02 de docs/04-auditoria-pruebas-y-demostracion.md y el
# requisito RF-DIF-03 de la ERS (detección como código).
#
# Antes, las reglas se creaban a mano en la consola de Kibana: quien clonaba el
# repositorio y levantaba el stack NO obtenía el mismo sistema. Ahora viajan
# versionadas en rules/ndjson/ y se despliegan con un comando.
#
# Uso:
#   ./scripts/deploy-rules.sh              despliega todas y las deja habilitadas
#   ./scripts/deploy-rules.sh --dry-run    valida los archivos, no toca Kibana
#   ./scripts/deploy-rules.sh --disabled   despliega sin habilitar
#
# Es IDEMPOTENTE: correrlo dos veces no duplica reglas (usa `overwrite=true`, y
# la identidad de cada regla es su `rule_id`, que está fijo en el archivo).
#
# Credenciales: salen de .env. Nunca se imprimen ni se pasan por la línea de
# comandos (donde quedarían en el listado de procesos).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

DIR_REGLAS="rules/ndjson"
KIBANA="${KIBANA_URL:-http://127.0.0.1:5601}"

DRY_RUN=false
HABILITAR=true
for arg in "$@"; do
  case "$arg" in
    --dry-run)  DRY_RUN=true ;;
    --disabled) HABILITAR=false ;;
    -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $arg"; exit 2 ;;
  esac
done

# ─── Validación de los archivos (siempre, aunque no se despliegue) ───────────

if [[ ! -d "$DIR_REGLAS" ]]; then
  echo "[ERROR] No existe '$DIR_REGLAS'."; exit 1
fi

mapfile -t ARCHIVOS < <(find "$DIR_REGLAS" -name '*.ndjson' | sort)
if (( ${#ARCHIVOS[@]} == 0 )); then
  echo "[ERROR] No hay reglas en '$DIR_REGLAS'."; exit 1
fi

echo "🔍 Validando ${#ARCHIVOS[@]} regla(s)..."
if ! python3 - "${ARCHIVOS[@]}" <<'PY'
import json, sys

REQUERIDOS = ("rule_id", "name", "type", "severity", "risk_score", "threat")
vistos, errores = {}, []

for ruta in sys.argv[1:]:
    with open(ruta, encoding="utf-8") as f:
        contenido = f.read().strip()
    if not contenido:
        errores.append(f"{ruta}: archivo vacío"); continue
    if "\n" in contenido:
        errores.append(f"{ruta}: debe tener UNA regla por archivo"); continue
    try:
        regla = json.loads(contenido)
    except json.JSONDecodeError as e:
        errores.append(f"{ruta}: JSON inválido ({e})"); continue

    faltan = [c for c in REQUERIDOS if c not in regla]
    if faltan:
        errores.append(f"{ruta}: faltan campos {faltan}")
    rid = regla.get("rule_id")
    if rid in vistos:
        errores.append(f"{ruta}: rule_id '{rid}' duplicado (ya está en {vistos[rid]})")
    vistos[rid] = ruta

if errores:
    print("\n".join(f"  ✗ {e}" for e in errores), file=sys.stderr)
    sys.exit(1)
print(f"  ✔ {len(vistos)} regla(s) válidas, rule_id únicos.")
PY
then
  echo "[ERROR] La validación falló. No se desplegó nada."; exit 1
fi

if $DRY_RUN; then
  echo "✅ --dry-run: archivos válidos. No se contactó a Kibana."
  exit 0
fi

# ─── Credenciales (desde .env, nunca impresas) ───────────────────────────────

if [[ ! -f .env ]]; then
  echo "[ERROR] Falta .env (copiar de .env.example)."; exit 1
fi
ES_USER="${ES_USER:-elastic}"
ES_PASS=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2-)
if [[ -z "$ES_PASS" ]]; then
  echo "[ERROR] ELASTIC_PASSWORD no está definida en .env."; exit 1
fi

# ─── Kibana tiene que estar listo ────────────────────────────────────────────

printf "⏳ Esperando a Kibana en %s" "$KIBANA"
for i in $(seq 1 60); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA/api/status")" == "200" ]]; then
    echo " ✔"; break
  fi
  printf "."; sleep 3
  if (( i == 60 )); then echo " ✗ (timeout)"; exit 1; fi
done

# ─── Importación ─────────────────────────────────────────────────────────────
#
# El endpoint recibe UN archivo NDJSON con todas las reglas. Se concatenan en un
# temporal en vez de hacer 13 peticiones: el import es atómico y el informe de
# resultado viene completo.

TEMPORAL=$(mktemp "${TMPDIR:-/tmp}/siem-ia-reglas-XXXXXX.ndjson")
trap 'rm -f "$TEMPORAL"' EXIT
cat "${ARCHIVOS[@]}" > "$TEMPORAL"

echo "📤 Importando en Kibana (overwrite=true → idempotente)..."
RESPUESTA=$(curl -s -u "$ES_USER:$ES_PASS" -H 'kbn-xsrf: true' \
  -X POST "$KIBANA/api/detection_engine/rules/_import?overwrite=true" \
  --form "file=@$TEMPORAL")

if ! RESPUESTA="$RESPUESTA" python3 <<'PY'
import json, os, sys

try:
    r = json.loads(os.environ["RESPUESTA"])
except json.JSONDecodeError:
    print("  \u2717 Kibana devolvió una respuesta no-JSON.", file=sys.stderr)
    sys.exit(1)

if not r.get("success", False):
    errores = r.get("errors", [])[:3]
    print(f"  \u2717 Importación con errores: {errores}", file=sys.stderr)
    sys.exit(1)
print(f"  \u2714 {r.get('success_count', 0)} regla(s) importada(s).")
PY
then
  echo "[ERROR] La importación falló."; exit 1
fi

# ─── Habilitar ───────────────────────────────────────────────────────────────

# Los archivos versionados traen `"enabled": true`, así que el import ya las deja
# activas. Para `--disabled` no alcanza con NO habilitarlas: hay que apagarlas
# explícitamente después de importar.
if $HABILITAR; then
  echo "▶️  Habilitando las reglas..."
  ESTADO_DESEADO=true
else
  echo "⏸️  Dejando las reglas deshabilitadas..."
  ESTADO_DESEADO=false
fi

# Una por una con PATCH por `rule_id`. El endpoint _bulk_action trabaja con los
# `id` internos que Kibana genera en cada instalación, y esos son justamente los
# que NO se versionan.
for archivo in "${ARCHIVOS[@]}"; do
  RID=$(python3 -c "import json,sys; print(json.load(open('$archivo'))['rule_id'])")
  curl -s -o /dev/null -u "$ES_USER:$ES_PASS" -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -X PATCH "$KIBANA/api/detection_engine/rules" \
    -d "{\"rule_id\":\"$RID\",\"enabled\":$ESTADO_DESEADO}"
done
if $HABILITAR; then
  echo "  ✔ Reglas habilitadas."
else
  echo "  ✔ Reglas desplegadas y deshabilitadas (revisalas antes de activarlas)."
fi

# ─── Resumen ─────────────────────────────────────────────────────────────────

echo
LISTADO=$(curl -s -u "$ES_USER:$ES_PASS" -H 'kbn-xsrf: true' \
  "$KIBANA/api/detection_engine/rules/_find?per_page=100")

LISTADO="$LISTADO" python3 <<'PY'
import json
import os

d = json.loads(os.environ["LISTADO"])
activas = sum(1 for r in d["data"] if r.get("enabled"))
raya = "=" * 54
print(raya)
print(f"  {d['total']} regla(s) en Kibana \u00b7 {activas} habilitada(s)")
print(raya)
for r in sorted(d["data"], key=lambda x: x["name"]):
    estado = "ON " if r.get("enabled") else "OFF"
    print(f"  [{estado}] {r['severity']:8} {r['name']}")
PY

echo
echo "✅ Listo. Las reglas DETECTAN; ninguna ejecuta acciones de contención."
