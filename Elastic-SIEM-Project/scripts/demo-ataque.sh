#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# demo-ataque.sh — Lanza un ataque MIENTRAS el público mira el panel.
#
# POR QUÉ EXISTE
#
# `demo.sh` deja incidentes ya procesados: muestra un resultado. Este script
# muestra el PROCESO. Con el panel proyectado —se refresca solo cada 15 s— el
# incidente aparece delante de todos, y eso es lo que demuestra detección; un
# panel con datos preexistentes podría ser un archivo JSON cualquiera.
#
# Va narrado y con pausas, para que quien presenta pueda hablar mientras corre.
#
# ⚠️  QUÉ HACE Y QUÉ NO
#
# Genera eventos de ataque SIMULADOS contra el laboratorio del propio proyecto y
# corre el pipeline de detección. NO ejecuta ninguna acción de contención.
#
# Uso:
#   ./scripts/demo-ataque.sh                  escaneo de puertos (el más rápido)
#   ./scripts/demo-ataque.sh port-scan        ídem, explícito
#   ./scripts/demo-ataque.sh phishing         captura de credenciales
#   ./scripts/demo-ataque.sh fuerza-bruta     SSH real con Hydra (necesita Docker)
#   ./scripts/demo-ataque.sh campana          escaneo + fuerza bruta desde la MISMA IP
#
#   --rapido    sin pausas narrativas (para probarlo, no para presentar)
#   --ip X      IP del atacante (por defecto se genera una nueva cada vez)
#
# El tipo `campana` es el más interesante: demuestra la correlación entre
# incidentes, que de otro modo pasa desapercibida.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

TIPO="port-scan"
RAPIDO=false
IP_ATAQUE=""

while (( $# )); do
  case "$1" in
    port-scan|phishing|fuerza-bruta|campana) TIPO="$1"; shift ;;
    --rapido)  RAPIDO=true; shift ;;
    --ip)      IP_ATAQUE="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

# IP nueva en cada corrida, dentro del rango de documentación (RFC 5737), para
# que el incidente se distinga a simple vista de los que ya están en el panel.
if [[ -z "$IP_ATAQUE" ]]; then
  IP_ATAQUE="198.51.100.$(( (RANDOM % 200) + 20 ))"
fi

narrar() { printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
detalle() { printf '  %s\n' "$1"; }
ok()     { printf '  \033[32m✔\033[0m %s\n' "$1"; }
pausa()  { $RAPIDO || sleep "${1:-3}"; }

contar_incidentes() {
  python3 - <<'PY' 2>/dev/null || echo 0
import json
import pathlib
p = pathlib.Path("siem_incidents.json")
print(json.loads(p.read_text(encoding="utf-8"))["incident_count"] if p.exists() else 0)
PY
}

listar_incidentes() {
  python3 - <<'PY' 2>/dev/null
import json
import pathlib

p = pathlib.Path("siem_incidents.json")
if not p.exists():
    raise SystemExit

for i in json.loads(p.read_text(encoding="utf-8"))["incidents"]:
    c = i["classification"]
    # Se muestra el ATACANTE, no `source_ip`: en los incidentes de phishing ese
    # campo es la víctima que envió sus credenciales, y en una demostración
    # confunde ver una IP distinta de la del ataque que se acaba de lanzar.
    atacante = (i.get("attacker_ips") or [i.get("source_ip")])[0]
    campana = f"  \U0001f517 {i['campaign_id']}" if i.get("campaign_id") else ""
    print(f"      {c['attack_type']:22} {c['severity']:8} {i['event_count']:>4} ev   "
          f"{atacante:16}{campana}")
PY
}

# Cuántos incidentes involucran a la IP del ataque, como atacante.
incidentes_de() {
  IP_BUSCADA="$1" python3 - <<'PY' 2>/dev/null || echo 0
import json
import os
import pathlib

p = pathlib.Path("siem_incidents.json")
if not p.exists():
    print(0)
    raise SystemExit

ip = os.environ["IP_BUSCADA"]
print(sum(1 for i in json.loads(p.read_text(encoding="utf-8"))["incidents"]
          if ip in (i.get("attacker_ips") or []) or i.get("source_ip") == ip))
PY
}

# ─── Apertura ────────────────────────────────────────────────────────────────

printf '\n\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1m║  ATAQUE EN VIVO · %-42s ║\033[0m\n' "$TIPO"
printf '\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m\n'

ANTES=$(contar_incidentes)
narrar "Antes del ataque: $ANTES incidente(s) en el panel"
listar_incidentes
detalle ""
detalle "Dejá el panel a la vista. Se refresca solo cada 15 segundos."
pausa 4

# ─── El ataque ───────────────────────────────────────────────────────────────

case "$TIPO" in

  port-scan)
    narrar "Un atacante desde $IP_ATAQUE sondea 26 puertos del host 172.18.0.5"
    detalle "Es reconocimiento: busca qué servicios hay antes de elegir cuál atacar."
    detalle "MITRE ATT&CK T1046 · Network Service Discovery"
    pausa 3
    bash simulation/run-port-scan.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
      && ok "26 eventos de red generados" || { echo "  ✗ falló"; exit 1; }
    ;;

  phishing)
    narrar "Una víctima envía sus credenciales a una página falsa en $IP_ATAQUE"
    detalle "El usuario 'testuser' visita /login y manda usuario y contraseña."
    detalle "MITRE ATT&CK T1566 · Phishing"
    pausa 3
    bash simulation/run-phishing.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
      && ok "visita + envío de credenciales generados" || { echo "  ✗ falló"; exit 1; }
    ;;

  fuerza-bruta)
    narrar "Hydra ataca por SSH el contenedor ssh-target"
    detalle "25 contraseñas en serie contra el usuario 'testuser'. La última acierta."
    detalle "MITRE ATT&CK T1110 · Brute Force"
    detalle ""
    detalle "Este NO es sintético: los intentos pasan por"
    detalle "Filebeat → Logstash → Elasticsearch, la misma ruta que un ataque real."
    pausa 4
    docker compose --profile simulation up -d ssh-target hydra-attacker >/dev/null 2>&1
    for _ in $(seq 1 30); do
      docker exec hydra-attacker which hydra >/dev/null 2>&1 && break
      sleep 5
    done
    timeout 240 bash simulation/run-brute-force.sh >/dev/null 2>&1 \
      && ok "24 fallos de autenticación + 1 login exitoso" \
      || { echo "  ✗ no completó (¿están los contenedores de simulación?)"; exit 1; }
    detalle "Esperando a que Filebeat los envíe…"
    pausa 12
    ;;

  campana)
    narrar "Una MISMA IP ($IP_ATAQUE) ataca en dos frentes"
    detalle "Primero reconoce la red, después ataca el servicio que encontró."
    detalle "Es lo que hace un adversario real, y lo que un SIEM debería leer junto."
    pausa 4

    detalle ""
    detalle "Fase 1 — reconocimiento (T1046): sondeo de 26 puertos"
    bash simulation/run-port-scan.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
      && ok "escaneo generado" || { echo "  ✗ falló"; exit 1; }
    pausa 4

    detalle ""
    detalle "Fase 2 — explotación (T1566): captura de credenciales desde la misma IP"
    bash simulation/run-phishing.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
      && ok "captura de credenciales generada" || { echo "  ✗ falló"; exit 1; }
    ;;
esac

# ─── Detección ───────────────────────────────────────────────────────────────

narrar "El pipeline clasifica y analiza"
detalle "Agente 1 (determinístico) → Agente 2 (explicación) → panel"
pausa 2

if ! python3 src/siem_pipeline.py >/tmp/demo-ataque.log 2>&1; then
  echo "  ✗ el pipeline falló (ver /tmp/demo-ataque.log)"
  exit 1
fi

DESPUES=$(contar_incidentes)
ok "pipeline completo"

narrar "Después del ataque: $DESPUES incidente(s)"
listar_incidentes

# ─── Cierre ──────────────────────────────────────────────────────────────────

echo
if (( DESPUES > ANTES )); then
  printf '  \033[32m✔ %s incidente(s) nuevo(s)\033[0m — buscá la IP %s en el panel.\n' \
    "$(( DESPUES - ANTES ))" "$IP_ATAQUE"
else
  printf '  \033[33m•\033[0m El ataque se sumó a un incidente que ya existía.\n'
  printf '    Mirá cómo le subió el conteo de eventos: el incidente es la\n'
  printf '    agrupación (por IP atacante, o por víctima en phishing), no el\n'
  printf '    evento suelto. Para ver uno nuevo, corré ./scripts/demo.sh primero.\n'
fi

if [[ "$TIPO" == "campana" ]]; then
  echo
  N_CAMP=$(incidentes_de "$IP_ATAQUE")
  detalle "La IP $IP_ATAQUE aparece en $N_CAMP incidente(s), vinculados por el"
  detalle "mismo identificador de campaña (la columna 🔗 de arriba)."
  detalle ""
  detalle "Abrí cualquiera de los dos: el banner morado los cruza. El sistema lee"
  detalle "el reconocimiento y la explotación como UNA operación, no como dos"
  detalle "eventos sueltos — la severidad del conjunto es mayor que la de cada uno."
  detalle ""
  detalle "Nota: en el incidente de phishing, la IP del atacante es el servidor"
  detalle "de la página falsa; la que figura como origen es la víctima que envió"
  detalle "sus credenciales."
fi

echo
detalle "El panel se actualiza solo dentro de los próximos 15 segundos."
detalle "Ninguna acción se ejecutó: el sistema solo detectó y sugirió."
echo
