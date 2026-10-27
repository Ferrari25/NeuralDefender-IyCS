#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy-ilm.sh — Retención de datos personales en Elasticsearch (ILM).
#
# Cierra RQ-SEC-17 (ERS 7.8 · 7.9.2 · 7.6): las IPs y los usuarios de los logs
# son datos personales (Ley 25.326) y no se pueden guardar sin límite. Antes,
# los índices filebeat-* crecían para siempre.
#
# Qué despliega (idempotente: correrlo dos veces deja lo mismo):
#   1. La política `siem-retencion` → borra cada índice a los
#      SIEM_RETENCION_DIAS días (30 por defecto) de la FECHA DE SUS DATOS.
#   2. Una plantilla de índice para filebeat-* que asigna esa política a cada
#      índice diario nuevo. Solo trae settings: el mapeo sigue siendo dinámico
#      (ver CLAUDE.md, ".keyword").
#   3. La misma política sobre los filebeat-* que YA existen.
#   4. Una fase de borrado en `.alerts-ilm-policy`, la política con la que
#      Kibana gestiona los índices de alertas (también llevan IPs). Se conserva
#      su rollover original.
#
# "Fecha de sus datos" y no "fecha de creación": con
# `index.lifecycle.parse_origination_date` la edad se cuenta desde la fecha del
# nombre (filebeat-8.12.2-AAAA.MM.DD). Un índice reingestado hoy con logs de
# hace dos meses no gana dos meses más de vida.
#
# ⚠️  Borra datos: al desplegarla, los índices más viejos que la retención se
#     eliminan en la próxima pasada de ILM (cada 10 min). Correr antes
#     `./scripts/siem.sh respaldo` si hacen falta. `--dry-run` muestra qué
#     índices caerían, sin tocar nada.
#
# Uso:
#   ./scripts/deploy-ilm.sh              despliega
#   ./scripts/deploy-ilm.sh --dry-run    muestra qué haría
#   SIEM_RETENCION_DIAS=90 ./scripts/deploy-ilm.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

ES="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
POLITICA="siem-retencion"
PLANTILLA="siem-filebeat-retencion"

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $arg"; exit 2 ;;
  esac
done

desde_env() { # variable — del entorno, o si no de .env
  local v="${!1:-}"
  [[ -z "$v" && -f .env ]] && v=$(grep -E "^$1=" .env | head -1 | cut -d= -f2- || true)
  printf '%s' "$v"
}

DIAS=$(desde_env SIEM_RETENCION_DIAS)
DIAS="${DIAS:-30}"
if ! [[ "$DIAS" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERROR] SIEM_RETENCION_DIAS tiene que ser un número de días (≥ 1), no '$DIAS'."; exit 2
fi

META="\"_meta\":{\"origen\":\"scripts/deploy-ilm.sh\",\"requisito\":\"RQ-SEC-17\"}"
CUERPO_POLITICA="{\"policy\":{\"phases\":{\"delete\":{\"min_age\":\"${DIAS}d\",\"actions\":{\"delete\":{}}}},$META}}"
SETTINGS="{\"index.lifecycle.name\":\"$POLITICA\",\"index.lifecycle.parse_origination_date\":true}"
CUERPO_PLANTILLA="{\"index_patterns\":[\"filebeat-*\"],\"priority\":200,\"template\":{\"settings\":$SETTINGS},$META}"
# El rollover es el que trae Kibana de fábrica; solo se agrega el borrado.
CUERPO_ALERTAS="{\"policy\":{\"phases\":{\"hot\":{\"min_age\":\"0ms\",\"actions\":{\"rollover\":{\"max_age\":\"30d\",\"max_primary_shard_size\":\"50gb\"}}},\"delete\":{\"min_age\":\"${DIAS}d\",\"actions\":{\"delete\":{}}}},\"_meta\":{\"managed\":true,\"retencion\":\"scripts/deploy-ilm.sh (RQ-SEC-17)\"}}}"

# Índices filebeat-* cuya fecha (del nombre) ya pasó la retención.
vencidos() { # lista de nombres de índice por stdin
  local corte
  corte=$(date -u -d "-$DIAS days" +%Y.%m.%d)
  while read -r indice; do
    fecha=$(grep -oE '[0-9]{4}\.[0-9]{2}\.[0-9]{2}$' <<<"$indice" || true)
    [[ -n "$fecha" && "$fecha" < "$corte" ]] && echo "  - $indice"
  done
  return 0
}

if $DRY_RUN; then
  echo "[dry-run] retención: $DIAS días"
  echo "[dry-run] PUT _ilm/policy/$POLITICA            $CUERPO_POLITICA"
  echo "[dry-run] PUT _index_template/$PLANTILLA   $CUERPO_PLANTILLA"
  echo "[dry-run] PUT filebeat-*/_settings              $SETTINGS"
  echo "[dry-run] PUT _ilm/policy/.alerts-ilm-policy     $CUERPO_ALERTAS"
fi

ES_PASS=$(desde_env ELASTIC_PASSWORD)
if [[ -z "$ES_PASS" ]]; then
  $DRY_RUN && exit 0
  echo "[ERROR] ELASTIC_PASSWORD no está definida en .env."; exit 1
fi

es() { # método ruta [cuerpo] — falla si la respuesta no es 2xx
  local salida codigo
  salida=$(curl -s -w '\n%{http_code}' -u "$ES_USER:$ES_PASS" -X "$1" "$ES$2" \
             -H 'Content-Type: application/json' ${3:+-d "$3"}) || return 1
  codigo=${salida##*$'\n'}
  if [[ "$codigo" != 2* ]]; then
    echo "[ERROR] $1 $2 → HTTP $codigo: ${salida%$'\n'*}" >&2
    return 1
  fi
  printf '%s' "${salida%$'\n'*}"
}

INDICES=$(es GET "/_cat/indices/filebeat-*?h=index" 2>/dev/null || true)
CAERIAN=$(vencidos <<<"$INDICES")

if $DRY_RUN; then
  if [[ -n "$CAERIAN" ]]; then
    echo "[dry-run] se borrarían (más de $DIAS días):"; echo "$CAERIAN"
  else
    echo "[dry-run] ningún índice existente supera la retención."
  fi
  exit 0
fi

echo "🗓️  Retención de datos personales: $DIAS días (RQ-SEC-17)"
es PUT "/_ilm/policy/$POLITICA" "$CUERPO_POLITICA" >/dev/null
echo "   ✔ política $POLITICA"
es PUT "/_index_template/$PLANTILLA" "$CUERPO_PLANTILLA" >/dev/null
echo "   ✔ plantilla $PLANTILLA (filebeat-* nuevos)"
if [[ -n "$INDICES" ]]; then
  es PUT "/filebeat-*/_settings" "$SETTINGS" >/dev/null
  echo "   ✔ asignada a $(wc -l <<<"$INDICES") índice(s) filebeat-* existentes"
fi
es PUT "/_ilm/policy/.alerts-ilm-policy" "$CUERPO_ALERTAS" >/dev/null
echo "   ✔ borrado a los $DIAS días en .alerts-ilm-policy (alertas)"
if [[ -n "$CAERIAN" ]]; then
  echo "   ⚠️  ILM va a borrar en su próxima pasada:"; echo "$CAERIAN"
fi
