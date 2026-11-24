#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# restaurar.sh — Restaura un respaldo de respaldo.sh (RTO < 30 min, ERS 7.9.3).
#
#   ./scripts/siem.sh restaurar siem-respaldo-<UTC>.tar.gz.enc [--renombrar]
#
# 1. Verifica el SHA-256: un archivo alterado o corrupto NO se restaura.
# 2. Descifra con SIEM_RESPALDO_CLAVE.
# 3. Restaura el snapshot en Elasticsearch. Sin --renombrar, los índices vuelven
#    con su nombre (el caso de desastre: el cluster está vacío; si un índice ya
#    existe, Elasticsearch se niega y no pisa nada). Con --renombrar vuelven
#    como `restaurado-<índice>`, al lado de los actuales, para comparar.
# 4. La auditoría NUNCA se pisa: se deja en $AUDIT_RESTAURADA/<respaldo>/ y se
#    verifica contra el MANIFIESTO. Reemplazar data/audit/ es una decisión de
#    una persona (y después: ./scripts/siem.sh auditoria, que valida la cadena).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

: "${SIEM_RESPALDO_CLAVE:?falta SIEM_RESPALDO_CLAVE}"
ES_HOST="${ES_HOST:-http://elasticsearch:9200}"
ES_USER="${ES_USER:-elastic}"
# Repositorio APARTE y de solo lectura: copiar un repositorio viejo encima del
# diario mezclaría su metadata (index-N) con la que Elasticsearch ya conoce.
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/snapshots}/restauracion"
RESPALDO_DIR="${RESPALDO_DIR:-/respaldos}"
AUDIT_RESTAURADA="${AUDIT_RESTAURADA:-/respaldos/restaurados}"
CON_ES="${SIEM_RESPALDO_ES:-true}"
REPO="siem-restauracion"
REPO_EN_ES="/usr/share/elasticsearch/snapshots/restauracion"

archivo="${1:?uso: restaurar.sh <siem-respaldo-...tar.gz.enc> [--renombrar]}"
renombrar=false
[[ "${2:-}" == "--renombrar" ]] && renombrar=true
[[ "$archivo" == */* ]] || archivo="$RESPALDO_DIR/$archivo"
nombre=$(basename "$archivo" .tar.gz.enc)

echo "[restaurar] verificando el resumen SHA-256..."
(cd "$(dirname "$archivo")" && sha256sum -c "$(basename "$archivo").sha256") \
  || { echo "[ERROR] el SHA-256 no coincide: el respaldo está alterado o corrupto." >&2; exit 1; }

trabajo=$(mktemp -d)
# chmod: la auditoría archivada es de solo lectura, y tar/cp conservan los permisos.
trap 'chmod -R u+w "$trabajo" 2>/dev/null; rm -rf "$trabajo"' EXIT
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:SIEM_RESPALDO_CLAVE -in "$archivo" \
  | tar -C "$trabajo" -xzf - \
  || { echo "[ERROR] no se pudo descifrar (¿clave equivocada?)." >&2; exit 1; }

snapshot=$(sed -n 's/^snapshot=//p' "$trabajo/$nombre/MANIFIESTO.txt")
indices=$(sed -n 's/^indices=//p' "$trabajo/$nombre/MANIFIESTO.txt")

echo "[restaurar] verificando la auditoría contra el MANIFIESTO..."
sumas=$(sed -n '/^# SHA-256/,$p' "$trabajo/$nombre/MANIFIESTO.txt" | tail -n +2)
if [[ -n "$sumas" ]]; then
  (cd "$trabajo/$nombre" && sha256sum -c --quiet - <<<"$sumas") \
    || { echo "[ERROR] la auditoría del respaldo no coincide con su MANIFIESTO." >&2; exit 1; }
fi
mkdir -p "$AUDIT_RESTAURADA"
if [[ -e "$AUDIT_RESTAURADA/$nombre" ]]; then
  chmod -R u+w "$AUDIT_RESTAURADA/$nombre"
  rm -rf "${AUDIT_RESTAURADA:?}/$nombre"
fi
cp -a "$trabajo/$nombre/audit" "$AUDIT_RESTAURADA/$nombre"
echo "[restaurar] auditoría → $AUDIT_RESTAURADA/$nombre (data/audit/ no se tocó)"

if [[ "$snapshot" == "ninguno" || "$CON_ES" != "true" ]]; then
  echo "[restaurar] este respaldo no tiene índices de Elasticsearch (o SIEM_RESPALDO_ES=false)."
  exit 0
fi

es() { # método ruta [cuerpo]
  curl -sS --fail-with-body -u "$ES_USER:${ELASTIC_PASSWORD:?falta ELASTIC_PASSWORD}" \
    -X "$1" "$ES_HOST$2" -H 'Content-Type: application/json' ${3:+-d "$3"}
}

echo "[restaurar] cargando el snapshot $snapshot en el repositorio..."
rm -rf "$SNAPSHOT_DIR"
mkdir -p "$SNAPSHOT_DIR"
cp -a "$trabajo/$nombre/elasticsearch/." "$SNAPSHOT_DIR/"
es PUT "/_snapshot/$REPO" "{\"type\":\"fs\",\"settings\":{\"location\":\"$REPO_EN_ES\",\"readonly\":true}}" >/dev/null
# Al terminar (bien o mal): se da de baja el repositorio y se borra la copia.
trap 'es DELETE "/_snapshot/$REPO" >/dev/null 2>&1 || true; chmod -R u+w "$trabajo" 2>/dev/null; rm -rf "$SNAPSHOT_DIR" "$trabajo"' EXIT

cuerpo="{\"indices\":\"$indices\",\"ignore_unavailable\":true,\"include_global_state\":false"
$renombrar && cuerpo+=",\"rename_pattern\":\"(.+)\",\"rename_replacement\":\"restaurado-\$1\""
cuerpo+="}"
respuesta=$(es POST "/_snapshot/$REPO/$snapshot/_restore?wait_for_completion=true" "$cuerpo") || {
  echo "[ERROR] Elasticsearch rechazó la restauración: $respuesta" >&2
  echo "        Si los índices ya existen, repetir con --renombrar." >&2
  exit 1
}
echo "[restaurar] OK: $(grep -Eo '"successful" *: *[0-9]+' <<<"$respuesta" | head -1) shards restaurados."
