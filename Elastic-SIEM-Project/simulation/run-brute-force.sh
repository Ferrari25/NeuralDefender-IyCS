#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Simulación de ataque: SSH BRUTE FORCE (fuerza bruta, MITRE T1110)
#
# Modo:
#   ./run-brute-force.sh                    → ataque REAL: Hydra (`hydra-attacker`)
#                                             contra el SSH de prueba (`ssh-target`)
#   ./run-brute-force.sh --offline          → solo genera los logs (no requiere Docker)
#   ./run-brute-force.sh --offline --ip X   → usa X como IP atacante
#
# Con contenedores, los intentos fallidos quedan en /var/log/auth.log dentro de
# `ssh-target`; Filebeat los recolecta y Logstash los normaliza hacia
# `filebeat-*` (mismo camino que un ataque real). Es lo que prueba la ingesta.
#
# `--offline` (RF-SIM-05 / RNF-MANT-05) escribe las MISMAS líneas de sshd en
# network_logs/brute-force-<epoch>.json, como port scan y phishing: el
# clasificador las lee de ahí sin el stack levantado. Con el stack arriba no se
# cuentan dos veces: Filebeat las indexa como `network_traffic`, y la consulta de
# auth fallida del collector solo toma ssh-target y los logs del sistema.
#
# Uso con contenedores:
#   docker compose --profile simulation up -d ssh-target hydra-attacker
#   bash simulation/run-brute-force.sh
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

# 24 contraseñas incorrectas + la real al final. El tamaño no es decorativo: el
# clasificador marca fuerza bruta a partir de BRUTE_FORCE_THRESHOLD = 20 fallos
# (services/classifier/classifier.py). Con un diccionario de 4, el ataque solo se clasificaba como
# tal si Kibana llegaba a disparar una alerta primero — y si el pipeline corría
# antes que la regla, el mismo ataque aparecía como "autenticación sospechosa".
# Con 24 fallos la detección se sostiene sola, sin depender del reloj del SIEM.
# testpassword es la password real del usuario testuser (ver docker-compose.yml)
# y va última: el ataque falla 24 veces y acierta en el intento 25, que es lo que
# dispara además la regla crítica "SSH Successful Login After Brute Force".
PASSWORDS=(password123 admin 123456 qwerty letmein welcome monkey dragon master sunshine
  princess football baseball trustno1 iloveyou starwars passw0rd abc123 login
  admin123 root toor changeme secret testpassword)

if $OFFLINE; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  # Nombre único por corrida: ver el comentario equivalente en run-port-scan.sh.
  OUT="$ROOT/network_logs/brute-force-$(date -u +%s).json"
  mkdir -p "$ROOT/network_logs"

  ATTACKER_IP="${IP_PERSONALIZADA:-172.18.0.3}"
  TARGET_IP="172.18.0.7"
  USUARIO="testuser"
  FALLOS=$(( ${#PASSWORDS[@]} - 1 ))   # la última es la correcta: no es un fallo

  echo "[*] Simulando fuerza bruta SSH: $ATTACKER_IP -> $TARGET_IP:2222 ($FALLOS fallos + 1 acierto)"
  now_base=$(date -u +%s)
  for (( i = 0; i < FALLOS; i++ )); do
    ts=$(date -u -d "@$((now_base + i))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)
    printf '{"@timestamp":"%s","event_type":"auth_failure","source_ip":"%s","dest_ip":"%s","dest_port":2222,"username":"%s","message":"Failed password for %s from %s port %s ssh2","tags":["auth","ssh","brute_force"],"source_type":"network_traffic"}\n' \
      "$ts" "$ATTACKER_IP" "$TARGET_IP" "$USUARIO" "$USUARIO" "$ATTACKER_IP" "$((40000 + i))" >> "$OUT"
  done
  ts=$(date -u -d "@$((now_base + FALLOS))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)
  printf '{"@timestamp":"%s","event_type":"auth_success","source_ip":"%s","dest_ip":"%s","dest_port":2222,"username":"%s","message":"Accepted password for %s from %s port %s ssh2","tags":["auth","ssh"],"source_type":"network_traffic"}\n' \
    "$ts" "$ATTACKER_IP" "$TARGET_IP" "$USUARIO" "$USUARIO" "$ATTACKER_IP" "$((40000 + FALLOS))" >> "$OUT"

  echo "[+] $(wc -l < "$OUT") eventos escritos en $OUT"
  echo "[OK] Listo. Corré:  ./scripts/siem.sh pipeline   y luego abrí el dashboard."
  exit 0
fi

require_container() { # nombre
  if ! docker ps --format '{{.Names}}' | grep -qx "$1"; then
    echo "[ERROR] El contenedor '$1' no está corriendo."
    echo "        Levantalo con: docker compose --profile simulation up -d ssh-target hydra-attacker"
    exit 1
  fi
}

require_container ssh-target
require_container hydra-attacker

echo "[*] Limpiando logs previos en ssh-target..."
docker exec ssh-target rm -f /var/log/auth.log

echo "[*] Preparando diccionario de contraseñas en hydra-attacker..."
docker exec hydra-attacker bash -c "printf '%s\n' ${PASSWORDS[*]} > /tmp/passwords.txt"

SSH_TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-target)
echo "[*] Target SSH Server IP: $SSH_TARGET_IP"

echo "[*] Iniciando ataque de fuerza bruta con Hydra..."
docker exec hydra-attacker hydra -l testuser -P /tmp/passwords.txt "$SSH_TARGET_IP" -s 2222 ssh -V -t 1 || true

echo "[+] Ataque simulado. Esperando 10s a que los logs lleguen a Elasticsearch..."
sleep 10

echo "[*] Contenido de auth.log en ssh-target:"
docker exec ssh-target cat /var/log/auth.log || echo "[!] No se encontró auth.log todavía."

echo "[OK] Listo. Corré:  ./scripts/siem.sh pipeline   y luego abrí el dashboard."
