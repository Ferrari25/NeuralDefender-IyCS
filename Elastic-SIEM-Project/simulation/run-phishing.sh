#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Simulación de ataque: PHISHING / captura de credenciales (MITRE T1566)
#
# Simula que una víctima envía sus credenciales a una página de login falsa.
# Genera eventos NDJSON en network_logs/phishing.json (entrada network-traffic de
# Filebeat → Elasticsearch; también la lee el clasificador en modo offline).
#
# Modo:
#   ./run-phishing.sh                    → genera los logs y, si hay contenedores, hace el POST real
#   ./run-phishing.sh --offline          → solo genera los logs (no requiere Docker)
#   ./run-phishing.sh --offline --ip X   → usa X como IP del servidor de phishing
#
# `--ip` sirve para las demostraciones en vivo: con una IP distinta a la de las
# corridas anteriores, el incidente nuevo se distingue de un vistazo en el panel.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

OFFLINE=false
IP_PERSONALIZADA=""
while (( $# )); do
  case "$1" in
    --offline) OFFLINE=true; shift ;;
    --ip)      IP_PERSONALIZADA="${2:-}"; shift 2 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Nombre único por corrida — ver comentario equivalente en run-port-scan.sh: truncar y
# reescribir el mismo archivo puede dejar desincronizado el offset que Filebeat (filestream)
# guarda por inode, y la corrida siguiente no se ingiere.
OUT="$ROOT/network_logs/phishing-$(date -u +%s).json"
mkdir -p "$ROOT/network_logs"

VICTIM_IP="172.18.0.9"                              # la víctima que envía credenciales
PHISH_IP="${IP_PERSONALIZADA:-172.18.0.8}"          # el servidor de phishing (página falsa)
URL="/login"
USER="testuser"

echo "[*] Simulando phishing: víctima $VICTIM_IP -> página falsa $PHISH_IP$URL"

now_base=$(date -u +%s)

emit() { # ts_offset method credential
  ts=$(date -u -d "@$((now_base + $1))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)
  printf '{"@timestamp":"%s","event_type":"http_request","source_ip":"%s","dest_ip":"%s","http_method":"%s","url":"%s","username":"%s","credential_submission":%s,"user_agent":"curl/8.0","tags":["web","credential_submission"],"source_type":"network_traffic"}\n' \
    "$ts" "$VICTIM_IP" "$PHISH_IP" "$2" "$URL" "$USER" "$3" >> "$OUT"
}

# GET de la página falsa (visita) y luego POST con credenciales (captura).
emit 0 GET  false
emit 3 POST true

echo "[+] $(wc -l < "$OUT") eventos escritos en $OUT"

if ! $OFFLINE; then
  if command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -q simulated-user; then
    echo "[*] Ejecutando POST real desde simulated-user (best effort)..."
    docker exec simulated-user curl -s -X POST "http://$PHISH_IP$URL" \
      -d "username=$USER&password=fakepassword123" >/dev/null || \
      echo "[!] Servidor de phishing inalcanzable; los logs sintéticos ya sirven para la detección."
  else
    echo "[i] Contenedores de phishing (fake-login/simulated-user) no están corriendo; modo solo-logs."
  fi
fi

echo "[OK] Listo. Corré:  python3 siem_pipeline.py   y luego abrí el dashboard."
