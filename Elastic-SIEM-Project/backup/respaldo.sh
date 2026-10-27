#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# respaldo.sh — Un respaldo completo, cifrado y con resumen criptográfico
# (RQ-SEC-05 · ERS 7.9.2 / 7.9.3: diario, RPO 24 h, RTO < 30 min).
#
# Qué respalda:
#   1. Los índices del SIEM (filebeat-* y las alertas de seguridad), con un
#      snapshot de Elasticsearch al repositorio `siem-respaldo` (path.repo).
#   2. Los registros de auditoría append-only (data/audit/): la evidencia.
#
# Qué deja, en $RESPALDO_DIR:
#   siem-respaldo-<UTC>.tar.gz.enc         AES-256-CBC, clave derivada con PBKDF2
#   siem-respaldo-<UTC>.tar.gz.enc.sha256  resumen SHA-256 del archivo cifrado
# y conserva solo los últimos $SIEM_RESPALDO_RETENCION (7 por defecto).
#
# Cada respaldo es COMPLETO por sí solo: el snapshot se borra del repositorio
# después de empaquetarlo, así que el siguiente vuelve a ser completo y para
# restaurar alcanza con un único archivo (ver restaurar.sh). Es lo que sostiene
# el RTO: no hay que reconstruir una cadena de incrementales.
#
# Lo corre a diario programador.sh dentro del contenedor `backup`; a mano:
#   ./scripts/siem.sh respaldo
#
# Sin el stack Elastic (la capa IA puede correr sola), SIEM_RESPALDO_ES=false
# respalda solo la auditoría y lo dice.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

: "${SIEM_RESPALDO_CLAVE:?falta SIEM_RESPALDO_CLAVE: sin clave no se cifra, y sin cifrar no se respalda}"
if (( ${#SIEM_RESPALDO_CLAVE} < 32 )); then
  echo "[ERROR] SIEM_RESPALDO_CLAVE tiene que tener al menos 32 caracteres." >&2
  exit 2
fi

ES_HOST="${ES_HOST:-http://elasticsearch:9200}"
ES_USER="${ES_USER:-elastic}"
AUDIT_DIR="${AUDIT_DIR:-/datos/audit}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/snapshots}/diario"    # path.repo de ES, montado acá
RESPALDO_DIR="${RESPALDO_DIR:-/respaldos}"
RETENCION="${SIEM_RESPALDO_RETENCION:-7}"
CON_ES="${SIEM_RESPALDO_ES:-true}"
REPO="siem-respaldo"
# Ruta del repositorio VISTA DESDE Elasticsearch (path.repo en elasticsearch.yml).
REPO_EN_ES="/usr/share/elasticsearch/snapshots/diario"
INDICES="filebeat-*,.internal.alerts-security.alerts-*"

[[ "$RETENCION" =~ ^[1-9][0-9]*$ ]] || { echo "[ERROR] SIEM_RESPALDO_RETENCION inválida: $RETENCION" >&2; exit 2; }

marca=$(date -u +%Y%m%dT%H%M%SZ)
nombre="siem-respaldo-$marca"
trabajo=$(mktemp -d)
# chmod: la auditoría archivada es de solo lectura, y cp -a conserva los permisos.
trap 'chmod -R u+w "$trabajo" 2>/dev/null; rm -rf "$trabajo"' EXIT
mkdir -p "$trabajo/$nombre" "$RESPALDO_DIR"

es() { # método ruta [cuerpo]
  curl -sS --fail-with-body -u "$ES_USER:${ELASTIC_PASSWORD:?falta ELASTIC_PASSWORD}" \
    -X "$1" "$ES_HOST$2" -H 'Content-Type: application/json' ${3:+-d "$3"}
}

echo "[respaldo] $nombre"

if [[ "$CON_ES" == "true" ]]; then
  echo "[respaldo] registrando el repositorio de snapshots..."
  es PUT "/_snapshot/$REPO" "{\"type\":\"fs\",\"settings\":{\"location\":\"$REPO_EN_ES\"}}" >/dev/null

  echo "[respaldo] snapshot de $INDICES ..."
  respuesta=$(es PUT "/_snapshot/$REPO/$marca?wait_for_completion=true" \
    "{\"indices\":\"$INDICES\",\"ignore_unavailable\":true,\"include_global_state\":false}")
  # PARTIAL también es un fallo: un respaldo al que le faltan shards no sirve
  # como evidencia, y se tiene que notar hoy, no el día que se necesite.
  if ! grep -Eq '"state" *: *"SUCCESS"' <<<"$respuesta"; then
    echo "[ERROR] el snapshot no terminó en SUCCESS: $respuesta" >&2
    es DELETE "/_snapshot/$REPO/$marca" >/dev/null 2>&1 || true
    exit 1
  fi
  cp -a "$SNAPSHOT_DIR/." "$trabajo/$nombre/elasticsearch/"
  # El repositorio queda vacío: el próximo snapshot vuelve a ser completo.
  es DELETE "/_snapshot/$REPO/$marca" >/dev/null
else
  echo "[AVISO] SIEM_RESPALDO_ES=false: este respaldo NO incluye los índices de Elasticsearch."
fi

if [[ -d "$AUDIT_DIR" ]]; then
  cp -a "$AUDIT_DIR" "$trabajo/$nombre/audit"
else
  echo "[ERROR] no existe el directorio de auditoría $AUDIT_DIR" >&2
  exit 1
fi

{
  echo "respaldo=$nombre"
  echo "creado_utc=$marca"
  echo "snapshot=$([[ "$CON_ES" == "true" ]] && echo "$marca" || echo "ninguno")"
  echo "indices=$INDICES"
  echo "# SHA-256 de cada archivo de auditoría al momento del respaldo"
  (cd "$trabajo/$nombre" && find audit -type f -print0 | sort -z | xargs -0 -r sha256sum)
} > "$trabajo/$nombre/MANIFIESTO.txt"

destino="$RESPALDO_DIR/$nombre.tar.gz.enc"
tar -C "$trabajo" -czf - "$nombre" \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:SIEM_RESPALDO_CLAVE -out "$destino.parcial"
mv "$destino.parcial" "$destino"
chmod 600 "$destino"
(cd "$RESPALDO_DIR" && sha256sum "$nombre.tar.gz.enc" > "$nombre.tar.gz.enc.sha256")

# Retención: los N más recientes (el nombre lleva la fecha, así que el orden
# alfabético es el cronológico).
mapfile -t viejos < <(find "$RESPALDO_DIR" -maxdepth 1 -name 'siem-respaldo-*.tar.gz.enc' -printf '%f\n' \
                       | sort -r | tail -n +"$((RETENCION + 1))")
for v in "${viejos[@]}"; do
  rm -f "$RESPALDO_DIR/$v" "$RESPALDO_DIR/$v.sha256"
done

echo "[respaldo] OK → $destino ($(du -h "$destino" | cut -f1)), sha256 $(cut -d' ' -f1 "$destino.sha256")"
