#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Simulación de ataque: PORT SCAN (reconocimiento de red, MITRE T1046)
#
# Genera un evento NDJSON por puerto sondeado en network_logs/port-scan.json.
# Ese directorio es la entrada `network-traffic` de Filebeat → Elasticsearch, y
# también lo lee el clasificador en modo offline. Así el ataque es detectable
# con o sin el stack levantado.
#
# Modo:
#   ./run-port-scan.sh                    → genera los logs y, si hay contenedores, corre nmap real
#   ./run-port-scan.sh --offline          → solo genera los logs (no requiere Docker)
#   ./run-port-scan.sh --offline --ip X   → usa X como IP atacante
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
# Nombre único por corrida (no un archivo fijo que se trunca): el input `filestream` de Filebeat
# identifica archivos por inode, y truncar+reescribir el mismo archivo puede dejar el offset
# desincronizado y que la corrida siguiente no se ingiera. Con un nombre nuevo cada vez, no hay
# ambigüedad — y de paso se conserva el historial de corridas anteriores en network_logs/.
OUT="$ROOT/network_logs/port-scan-$(date -u +%s).json"
mkdir -p "$ROOT/network_logs"

ATTACKER_IP="${IP_PERSONALIZADA:-172.18.0.7}"
TARGET_IP="172.18.0.5"
PORTS=(21 22 23 25 53 80 110 135 139 143 443 445 993 995 1433 1521 2222 3306 3389 5432 5601 6379 8080 8443 9200 9300)

echo "[*] Simulando port scan: $ATTACKER_IP -> $TARGET_IP (${#PORTS[@]} puertos)"

now_base=$(date -u +%s)
i=0
for p in "${PORTS[@]}"; do
  ts=$(date -u -d "@$((now_base + i))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)
  printf '{"@timestamp":"%s","event_type":"network_flow","source_ip":"%s","dest_ip":"%s","dest_port":%s,"protocol":"tcp","action":"probe","tags":["network_traffic","port_scan"],"source_type":"network_traffic"}\n' \
    "$ts" "$ATTACKER_IP" "$TARGET_IP" "$p" >> "$OUT"
  i=$((i + 1))
done

echo "[+] $(wc -l < "$OUT") eventos escritos en $OUT"

if ! $OFFLINE; then
  if command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -q hydra-attacker; then
    echo "[*] Ejecutando nmap real desde hydra-attacker (best effort)..."
    docker exec hydra-attacker bash -c "command -v nmap >/dev/null || (apt-get update && apt-get install -y nmap)" || true
    docker exec hydra-attacker nmap -sT -p- --max-retries 1 "$TARGET_IP" || \
      echo "[!] nmap no disponible o objetivo inalcanzable; los logs sintéticos ya sirven para la detección."
  else
    echo "[i] Contenedor hydra-attacker no está corriendo; modo solo-logs."
  fi
fi

echo "[OK] Listo. Corré:  python3 src/siem_pipeline.py   y luego abrí el dashboard."
