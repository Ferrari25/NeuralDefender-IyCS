#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# demo.sh — Deja el sistema listo para demostrarlo, con UN comando.
#
# POR QUÉ EXISTE
#
# El pipeline analiza una ventana de 24 horas. Si nadie corre una simulación
# antes, el panel se ve VACÍO con todo el stack perfectamente sano — es el
# riesgo más probable de una demostración en vivo (hallazgo F-06 de la
# auditoría). Y el guion manual son 14 comandos tipeados, que es donde se caen
# las demos.
#
# Este script hace todo eso solo, en orden, y verifica cada paso antes de seguir.
#
# ⚠️  QUÉ HACE Y QUÉ NO
#
# Genera ataques SIMULADOS contra el laboratorio del propio proyecto y corre el
# pipeline de detección. NO ejecuta ninguna acción de contención: el sistema
# sigue sin tocar firewalls, hosts ni servicios. La IA sugiere, el humano decide.
#
# Uso:
#   ./scripts/demo.sh                 preparar la demo (idempotente)
#   ./scripts/demo.sh --rapido        sin la fuerza bruta real (no usa Docker)
#   ./scripts/demo.sh --solo-guion    solo imprime el guion, no toca nada
#   ./scripts/demo.sh --estado        diagnóstico: qué falta para poder demostrar
#
# Correrlo dos veces no rompe nada: los usuarios ya creados se conservan y los
# ataques nuevos se suman.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

RAPIDO=false
SOLO_GUION=false
SOLO_ESTADO=false
for arg in "$@"; do
  case "$arg" in
    --rapido)     RAPIDO=true ;;
    --solo-guion) SOLO_GUION=true ;;
    --estado)     SOLO_ESTADO=true ;;
    -h|--help)    sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $arg"; exit 2 ;;
  esac
done

# Credenciales de demostración. Son de laboratorio y están a la vista a
# propósito: no protegen nada real y hacen falta para entrar al panel.
USUARIO_DEMO="analista"
PASSWORD_DEMO="Soc-Analista-2026"

azul()    { printf '\033[1;34m%s\033[0m\n' "$1"; }
verde()   { printf '  \033[32m✔\033[0m %s\n' "$1"; }
amarillo(){ printf '  \033[33m•\033[0m %s\n' "$1"; }
rojo()    { printf '  \033[31m✗\033[0m %s\n' "$1"; }

paso() { printf '\n\033[1m── %s ─────────────────────────────────\033[0m\n' "$1"; }

# ─── Diagnóstico ─────────────────────────────────────────────────────────────

incidentes_actuales() {
  python3 - <<'PY' 2>/dev/null || echo 0
import json
import pathlib
p = pathlib.Path("siem_incidents.json")
print(json.loads(p.read_text(encoding="utf-8"))["incident_count"] if p.exists() else 0)
PY
}

diagnostico() {
  local listo=true

  printf '  %-34s' "Stack Docker (Elasticsearch)"
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9200 2>/dev/null)" =~ ^(200|401)$ ]]; then
    printf '\033[32marriba\033[0m\n'
  else
    printf '\033[31mno responde\033[0m  → ./scripts/start.sh\n'; listo=false
  fi

  printf '  %-34s' "Kibana"
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5601/api/status 2>/dev/null)" == "200" ]]; then
    printf '\033[32marriba\033[0m\n'
  else
    printf '\033[33mno responde\033[0m (la demo funciona igual)\n'
  fi

  printf '  %-34s' "SECRET_KEY en .env"
  if grep -q '^SECRET_KEY=.\{32,\}' .env 2>/dev/null; then
    printf '\033[32mdefinida\033[0m\n'
  else
    printf '\033[31mfalta\033[0m  → el panel no arranca\n'; listo=false
  fi

  printf '  %-34s' "Usuarios del panel"
  local n_usuarios
  n_usuarios=$(python3 -c "
import json, os, pathlib
p = pathlib.Path(os.getenv('SIEM_USERS_FILE', 'users.json'))
print(len(json.loads(p.read_text())['usuarios']) if p.exists() else 0)" 2>/dev/null || echo 0)
  if (( n_usuarios > 0 )); then printf '\033[32m%s\033[0m\n' "$n_usuarios"
  else printf '\033[33mninguno\033[0m (se crean solos)\n'; fi

  printf '  %-34s' "Reglas de detección"
  local n_reglas
  n_reglas=$(ls rules/ndjson/*.ndjson 2>/dev/null | wc -l)
  printf '\033[32m%s versionadas\033[0m\n' "$n_reglas"

  printf '  %-34s' "Incidentes para mostrar"
  local n_inc
  n_inc=$(incidentes_actuales)
  if (( n_inc > 0 )); then printf '\033[32m%s\033[0m\n' "$n_inc"
  else printf '\033[33m0 — el panel se vería vacío\033[0m\n'; fi

  $listo
}

if $SOLO_ESTADO; then
  azul "Estado del entorno de demostración"
  diagnostico && echo && verde "Listo para demostrar." || { echo; rojo "Falta algo de lo de arriba."; exit 1; }
  exit 0
fi

# ─── Guion ───────────────────────────────────────────────────────────────────

imprimir_guion() {
  cat <<GUION

╔═══════════════════════════════════════════════════════════════════════╗
║                      GUION DE LA DEMOSTRACIÓN                          ║
╚═══════════════════════════════════════════════════════════════════════╝

  Panel:  http://127.0.0.1:5000/login
  Entrar: $USUARIO_DEMO / $PASSWORD_DEMO          (rol analyst: ve y decide)
          observador / Soc-Viewer-2026x   (rol viewer: NO puede decidir)
          auditor    / Soc-Auditor-2026   (rol auditor: verifica la cadena)

  ── 1 · El sistema exige identidad ──────────────────────────────────────
     Mostrar el login. Entrar con el analista.
     Contar: el campo 'analyst' del registro sale de la SESIÓN, no de una
     variable de entorno. La cadena de hash prueba que el registro no se
     alteró; la sesión prueba QUIÉN lo escribió.

  ── 2 · Triage ──────────────────────────────────────────────────────────
     Los incidentes detectados, con su severidad y el análisis en lenguaje
     claro. Señalar el distintivo 'Fallback determinístico' arriba a la
     derecha: la cuota del LLM está agotada y el sistema funciona igual
     (RNF-CONF-04, degradación garantizada — es un requisito cumplido, no
     una falla).

  ── 3 · La campaña ──────────────────────────────────────────────────────
     Abrir el incidente de escaneo de puertos. Banner morado 🔗: la MISMA IP
     escaneó y después atacó por SSH. El sistema lo trata como una campaña,
     no como dos incidentes sueltos.

  ── 4 · La evidencia y el porqué ────────────────────────────────────────
     Desplegar 'Evidencia'. Mostrar los factores: por qué esa severidad.
     No es una caja negra.

  ── 5 · La decisión ─────────────────────────────────────────────────────
     Aprobar una acción. Recargar: el estado persiste (replay del registro).
     Insistir: aprobar REGISTRA UNA INTENCIÓN. El comando lo ejecuta una
     persona, a mano, fuera del sistema.

  ── 6 · Los roles ───────────────────────────────────────────────────────
     Cerrar sesión, entrar como 'observador'. Los botones no están.
     (Y si lo intenta por API, el servidor responde 403.)

  ── 7 · Un ataque EN VIVO ───────────────────────────────────────────────
     Dejar el panel proyectado y correr en otra terminal:

         ./scripts/demo-ataque.sh campana

     Va narrado y con pausas, para poder hablar mientras corre. Usa una IP
     nueva cada vez (198.51.100.x), así el incidente se distingue de los que
     ya están en el panel. El panel se refresca solo cada 15 s: aparece
     mientras miran.

     El modo campana es el más interesante — una misma IP escanea y después ataca,
     y el sistema lo lee como UNA operación. Otros modos: port-scan,
     phishing, fuerza-bruta (este último necesita Docker).

  ── 8 · La auditoría es verificable ─────────────────────────────────────
         ./scripts/demo-auditoria.sh

     Altera una decisión ya registrada y muestra que el sistema lo detecta,
     con código de salida 1. Trabaja sobre una COPIA: el registro real no se
     toca, y el script lo prueba comparando su SHA-256 antes y después.

     No editar decisions.jsonl a mano para esto.

  ── 9 · Las pruebas encuentran cosas ────────────────────────────────────
         ./scripts/check.sh          (SAST + 724 pruebas)

     Y para mostrar que el análisis estático detecta de verdad, no que está
     de adorno, ver docs/auditoria/03-evidencia-para-la-catedra.md §1.

GUION
}

if $SOLO_GUION; then
  imprimir_guion
  exit 0
fi

# ─── Preparación ─────────────────────────────────────────────────────────────

azul "SIEM-IA · preparando la demostración"
echo
paso "1/5 · Diagnóstico"
if ! diagnostico; then
  echo
  rojo "Falta algo imprescindible. Corregilo y volvé a correr este script."
  exit 1
fi

paso "2/5 · Usuarios del panel"
crear_si_falta() { # usuario rol password
  if python3 -c "
import json, os, pathlib, sys
p = pathlib.Path(os.getenv('SIEM_USERS_FILE', 'users.json'))
usuarios = json.loads(p.read_text())['usuarios'] if p.exists() else []
sys.exit(0 if any(u['username'] == '$1' for u in usuarios) else 1)" 2>/dev/null; then
    amarillo "'$1' ya existe"
  else
    SIEM_NEW_PASSWORD="$3" python3 manage_users.py crear "$1" --rol "$2" >/dev/null 2>&1 \
      && verde "'$1' creado (rol $2)" || rojo "no se pudo crear '$1'"
  fi
}
crear_si_falta "$USUARIO_DEMO" analyst "$PASSWORD_DEMO"
crear_si_falta observador      viewer  "Soc-Viewer-2026x"
crear_si_falta auditor         auditor "Soc-Auditor-2026"

paso "3/5 · Reglas de detección"
if [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5601/api/status 2>/dev/null)" == "200" ]]; then
  if ./scripts/deploy-rules.sh >/tmp/demo-reglas.log 2>&1; then
    verde "$(grep -oE '[0-9]+ regla\(s\) en Kibana · [0-9]+ habilitada\(s\)' /tmp/demo-reglas.log | tail -1)"
  else
    amarillo "no se pudieron desplegar (ver /tmp/demo-reglas.log). La demo funciona igual."
  fi
else
  amarillo "Kibana no responde; se saltea el despliegue de reglas"
fi

paso "4/5 · Ataques simulados"
# Se limpian las corridas anteriores para que los conteos sean los del ataque de
# ahora. Son logs de simulación, regenerables; el registro de auditoría NO se
# toca (para eso está ./scripts/reset.sh, que lo archiva).
rm -f network_logs/*.json
amarillo "corridas anteriores de simulación limpiadas"

bash simulation/run-port-scan.sh --offline >/dev/null 2>&1 \
  && verde "escaneo de puertos  (T1046) · 26 puertos" || rojo "falló el port scan"
bash simulation/run-phishing.sh --offline >/dev/null 2>&1 \
  && verde "phishing            (T1566) · captura de credenciales" || rojo "falló el phishing"

if $RAPIDO; then
  amarillo "fuerza bruta SSH    (T1110) · omitida (--rapido)"
else
  if docker compose --profile simulation up -d ssh-target hydra-attacker >/dev/null 2>&1; then
    printf '  \033[33m•\033[0m fuerza bruta SSH    (T1110) · esperando a hydra'
    for _ in $(seq 1 30); do
      docker exec hydra-attacker which hydra >/dev/null 2>&1 && break
      printf '.'; sleep 5
    done
    printf '\r'
    if timeout 240 bash simulation/run-brute-force.sh >/dev/null 2>&1; then
      verde "fuerza bruta SSH    (T1110) · ingesta real vía Filebeat → Logstash → ES"
    else
      amarillo "fuerza bruta SSH    (T1110) · no completó; los otros dos alcanzan"
    fi
  else
    amarillo "fuerza bruta SSH    (T1110) · sin contenedores de simulación"
  fi
fi

paso "5/5 · Pipeline de detección"
# Antes de correr el pipeline se espera a que las reglas del SIEM disparen. Sin
# esta espera hay una carrera: el pipeline lee las alertas antes de que existan y
# el mismo ataque se clasifica con menos severidad de la que corresponde.
if [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5601/api/status 2>/dev/null)" == "200" ]]; then
  ES_PASS_DEMO=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2-)
  printf '  [33m•[0m esperando a que las reglas disparen'
  for _ in $(seq 1 12); do
    N_AL=$(curl -s -u "elastic:$ES_PASS_DEMO" -H 'Content-Type: application/json' \
      'http://127.0.0.1:9200/.alerts-security.alerts-default/_count' \
      -d '{"query":{"range":{"@timestamp":{"gte":"now-20m"}}}}' 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    (( ${N_AL:-0} >= 3 )) && break
    printf '.'; sleep 10
  done
  printf '\r'
  verde "alertas del SIEM disponibles: ${N_AL:-0}"
fi

if python3 siem_pipeline.py >/tmp/demo-pipeline.log 2>&1; then
  N=$(incidentes_actuales)
  verde "$N incidente(s) clasificado(s) y analizado(s)"
  python3 - <<'PY'
import json
import pathlib
d = json.loads(pathlib.Path("siem_incidents.json").read_text(encoding="utf-8"))
for i in d["incidents"]:
    c = i["classification"]
    campana = "  \U0001f517 campaña" if i.get("campaign_id") else ""
    print(f"      {c['attack_type']:22} {c['severity']:8} {i['event_count']:>4} ev{campana}")
PY
else
  rojo "el pipeline falló (ver /tmp/demo-pipeline.log)"
  exit 1
fi

# ─── Cierre ──────────────────────────────────────────────────────────────────

N_FINAL=$(incidentes_actuales)
echo
if (( N_FINAL == 0 )); then
  rojo "Quedaron 0 incidentes: el panel se vería vacío."
  amarillo "Revisá /tmp/demo-pipeline.log y volvé a correr el script."
  exit 1
fi

if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:5000/api/v1/healthz 2>/dev/null; then
  paso "Falta levantar el panel"
  echo "     python3 dashboard.py     → http://127.0.0.1:5000/login"
fi

imprimir_guion
verde "Todo listo: $N_FINAL incidente(s) esperando en el panel."
