#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# export-rules.sh — Trae las reglas de DETECCIÓN de Kibana al repositorio.
#
# El camino inverso de deploy-rules.sh. Sirve para que lo que está versionado y
# lo que está corriendo no se separen: si alguien ajusta un umbral desde la
# consola, este script lo baja a `rules/ndjson/` y el cambio queda en el diff.
#
# Como `deploy-rules.sh`, esto mueve REGLAS DE DETECCIÓN, no acciones sobre la
# infraestructura. El sistema sigue sin ejecutar nada.
#
# Uso:
#   ./scripts/export-rules.sh              escribe en rules/ndjson/
#   ./scripts/export-rules.sh --check      NO escribe; avisa si hay diferencias
#
# `--check` es el modo para CI: sale con 1 si Kibana y el repositorio divergen.
#
# Credenciales: salen de .env, nunca se imprimen.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

DIR_REGLAS="rules/ndjson"
KIBANA="${KIBANA_URL:-http://127.0.0.1:5601}"

SOLO_VERIFICAR=false
for arg in "$@"; do
  case "$arg" in
    --check)   SOLO_VERIFICAR=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $arg"; exit 2 ;;
  esac
done

if [[ ! -f .env ]]; then
  echo "[ERROR] Falta .env."; exit 1
fi
ES_USER="${ES_USER:-elastic}"
ES_PASS=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2-)
if [[ -z "$ES_PASS" ]]; then
  echo "[ERROR] ELASTIC_PASSWORD no está definida en .env."; exit 1
fi

if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA/api/status")" != "200" ]]; then
  echo "[ERROR] Kibana no responde en $KIBANA."; exit 1
fi

TEMPORAL=$(mktemp "${TMPDIR:-/tmp}/siem-ia-export-XXXXXX.ndjson")
trap 'rm -f "$TEMPORAL"' EXIT

echo "📥 Exportando reglas desde Kibana..."
curl -s -u "$ES_USER:$ES_PASS" -H 'kbn-xsrf: true' \
  -X POST "$KIBANA/api/detection_engine/rules/_export" > "$TEMPORAL"

EXPORT="$TEMPORAL" DESTINO="$DIR_REGLAS" VERIFICAR="$SOLO_VERIFICAR" python3 <<'PY'
import json
import os
import pathlib
import sys

# Campos que Kibana genera en cada instalación: identificadores internos y
# marcas temporales. Versionarlos produciría un diff en cada exportación aunque
# la regla no hubiera cambiado, y además ata el archivo a una instalación.
VOLATILES = {"id", "created_at", "created_by", "updated_at", "updated_by",
             "revision", "execution_summary", "outcome", "alias_target_id",
             "alias_purpose"}

destino = pathlib.Path(os.environ["DESTINO"])
verificar = os.environ["VERIFICAR"] == "true"

# El código del catálogo (A1, B2, C3…) se conserva del nombre de archivo actual,
# para no perder la correspondencia con rules/rules.md.
codigo_por_rule_id = {}
for archivo in destino.glob("*.ndjson"):
    try:
        rid = json.loads(archivo.read_text(encoding="utf-8"))["rule_id"]
    except (json.JSONDecodeError, KeyError):
        continue
    codigo_por_rule_id[rid] = archivo.name.split("-", 1)[0]

exportadas, sin_codigo = {}, []
for linea in pathlib.Path(os.environ["EXPORT"]).read_text(encoding="utf-8").splitlines():
    if not linea.strip():
        continue
    regla = json.loads(linea)
    if "rule_id" not in regla:        # la última línea es el resumen del export
        continue
    rid = regla["rule_id"]
    if rid not in codigo_por_rule_id:
        sin_codigo.append(rid)
    exportadas[rid] = {k: v for k, v in regla.items() if k not in VOLATILES}

if not exportadas:
    print("  ✗ Kibana no devolvió ninguna regla.", file=sys.stderr)
    sys.exit(1)

nuevas, cambiadas, iguales = [], [], []
for rid, regla in sorted(exportadas.items()):
    codigo = codigo_por_rule_id.get(rid, "ZZ")
    ruta = destino / f"{codigo}-{rid}.ndjson"
    contenido = json.dumps(regla, ensure_ascii=False, sort_keys=True) + "\n"

    if not ruta.exists():
        nuevas.append(ruta.name)
    elif ruta.read_text(encoding="utf-8") != contenido:
        cambiadas.append(ruta.name)
    else:
        iguales.append(ruta.name)

    if not verificar:
        ruta.write_text(contenido, encoding="utf-8")

# Reglas versionadas que ya no están en Kibana: se avisan, no se borran solas.
huerfanas = [a.name for a in sorted(destino.glob("*.ndjson"))
             if json.loads(a.read_text(encoding="utf-8"))["rule_id"] not in exportadas]

print(f"  {len(exportadas)} regla(s) en Kibana")
print(f"    sin cambios : {len(iguales)}")
print(f"    modificadas : {len(cambiadas)}" + (f" → {cambiadas}" if cambiadas else ""))
print(f"    nuevas      : {len(nuevas)}" + (f" → {nuevas}" if nuevas else ""))
if huerfanas:
    print(f"    ⚠ versionadas pero ausentes de Kibana: {huerfanas}")
if sin_codigo:
    print(f"    ⚠ sin código de catálogo (quedaron como ZZ-): {sin_codigo}")
    print("      Renombralas a su código (A1, B2, C3…) y anotalas en rules/rules.md.")

if verificar and (nuevas or cambiadas or huerfanas):
    print("\n  ✗ Kibana y el repositorio divergen. Corré ./scripts/export-rules.sh",
          file=sys.stderr)
    sys.exit(1)
if verificar:
    print("\n  ✔ Kibana y el repositorio coinciden.")
PY
resultado=$?

if ! $SOLO_VERIFICAR && (( resultado == 0 )); then
  echo
  echo "✅ Reglas escritas en $DIR_REGLAS/. Revisá el diff antes de commitear."
fi
exit $resultado
