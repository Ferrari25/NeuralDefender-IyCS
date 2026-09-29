#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# demo-desde-cero.sh — La demostración completa, arrancando de la nada.
#
# POR QUÉ EXISTE
#
# `demo.sh` deja el laboratorio presentable y `demo-ataque.sh` lanza un ataque en
# vivo. Los dos parten de un sistema que ya tiene datos. La pregunta que eso deja
# abierta —y que un evaluador va a hacer— es: «¿cómo sé que el panel no está
# mostrando un archivo guardado?».
#
# Este script responde esa pregunta poniendo TODO en cero delante del público y
# construyendo el resultado paso a paso: 0 reglas, 0 alertas, 0 documentos, 0
# incidentes → se despliegan las reglas → se ataca → se ve la ingesta → disparan
# las reglas → el pipeline clasifica → el panel se llena.
#
# ⚠️  QUÉ BORRA Y QUÉ NO
#
# Borra datos REGENERABLES: índices de Filebeat, alertas, reglas desplegadas y
# los artefactos locales del pipeline. No baja Docker: el stack sigue arriba, así
# que la limpieza tarda segundos y no minutos.
#
# El REGISTRO DE AUDITORÍA no se borra: se archiva en `audit/archive/`, igual que
# en `reset.sh` (hallazgo A-01). `decisions.jsonl` es la única prueba de que hubo
# supervisión humana; un script que la borre junto a los datos de demo convierte
# el registro en un archivo de trabajo.
#
# Tampoco toca la no-autonomía: despliega REGLAS DE DETECCIÓN y genera ataques
# simulados contra el laboratorio del propio proyecto. No ejecuta contención.
#
# Uso:
#   ./scripts/demo-desde-cero.sh             limpia y guía la demostración entera
#   ./scripts/demo-desde-cero.sh --limpiar   solo deja todo en cero y sale
#   ./scripts/demo-desde-cero.sh --estado    qué hay ahora, sin tocar nada
#   ./scripts/demo-desde-cero.sh --rapido    sin pausas narrativas (para probarlo)
#   ./scripts/demo-desde-cero.sh --sin-docker  omite la fuerza bruta con Hydra
#   ./scripts/demo-desde-cero.sh --si        no pregunta antes de limpiar
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

MODO=guiada
RAPIDO=false
SIN_DOCKER=false
SIN_CONFIRMAR=false

while (( $# )); do
  case "$1" in
    --limpiar)    MODO=limpiar; shift ;;
    --estado)     MODO=estado; shift ;;
    --rapido)     RAPIDO=true; shift ;;
    --sin-docker) SIN_DOCKER=true; shift ;;
    --si|--yes)   SIN_CONFIRMAR=true; shift ;;
    -h|--help)    sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

ES=http://127.0.0.1:9200
KIBANA=http://127.0.0.1:5601
ALERTAS=.alerts-security.alerts-default

# Las credenciales salen de .env y no se imprimen ni se pasan por línea de comandos
# (donde quedarían visibles en el listado de procesos).
if [[ ! -f .env ]]; then
  echo "[ERROR] Falta .env. Sin credenciales no se puede consultar Elasticsearch."
  exit 1
fi
ES_PASS=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2-)

# ─── Salida ──────────────────────────────────────────────────────────────────

paso()    { printf '\n\033[1;36m━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' "$1"; }
narrar()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
detalle() { printf '  %s\n' "$1"; }
ok()      { printf '  \033[32m✔\033[0m %s\n' "$1"; }
aviso()   { printf '  \033[33m•\033[0m %s\n' "$1"; }
mal()     { printf '  \033[31m✗\033[0m %s\n' "$1"; }
pausa()   { $RAPIDO || sleep "${1:-3}"; }

es()     { curl -s -u "elastic:$ES_PASS" "$@"; }
kbn()    { curl -s -u "elastic:$ES_PASS" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }

# ─── Los cuatro números que definen «estar en cero» ──────────────────────────

n_reglas()  { kbn "$KIBANA/api/detection_engine/rules/_find?per_page=200" 2>/dev/null \
                | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("data",[])))' 2>/dev/null || echo "?"; }
n_alertas() { es "$ES/$ALERTAS/_count" 2>/dev/null \
                | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo "?"; }
n_docs()    { es "$ES/filebeat-*/_count" 2>/dev/null \
                | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0; }
n_incidentes() { python3 - <<'PY' 2>/dev/null || echo 0
import json
import pathlib
p = pathlib.Path("siem_incidents.json")
print(json.loads(p.read_text(encoding="utf-8"))["incident_count"] if p.exists() else 0)
PY
}

# `prepare-for-ia.py` es una etapa TOLERABLE del pipeline: si Elasticsearch no
# responde, el orquestador sigue con los datos que haya y termina con código 0. Eso
# está bien para el modo offline, pero en una demostración desde cero es una trampa:
# se mostrarían datos de una captura anterior justo cuando se afirma que no hay
# ninguno. Acá se exige que la captura sea NUEVA.
captura_fresca() {
  python3 - <<'PY' 2>/dev/null
import json
import pathlib
from datetime import datetime, timedelta, timezone

p = pathlib.Path("siem_clean.json")
if not p.exists():
    print("FALTA")
    raise SystemExit

d = json.loads(p.read_text(encoding="utf-8"))
try:
    cuando = datetime.fromisoformat(d["generated_at"].replace("Z", "+00:00"))
except (KeyError, ValueError):
    print("SIN_FECHA")
    raise SystemExit

if datetime.now(timezone.utc) - cuando > timedelta(minutes=10):
    print(f"VIEJA {d['generated_at']}")
else:
    s = d.get("summary", {})
    print(f"OK {s.get('total_alerts', 0)} {s.get('total_auth_failures', len(d.get('auth_failure_logs', [])))}")
PY
}

tablero() {
  printf '      %-28s %s\n' "reglas de detección" "$(n_reglas)"
  printf '      %-28s %s\n' "alertas en Elasticsearch" "$(n_alertas)"
  printf '      %-28s %s\n' "documentos de Filebeat" "$(n_docs)"
  printf '      %-28s %s\n' "incidentes en el panel" "$(n_incidentes)"
}

# ─── --estado ────────────────────────────────────────────────────────────────

if [[ "$MODO" == "estado" ]]; then
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA/api/status" 2>/dev/null)" != "200" ]]; then
    mal "Kibana no responde en $KIBANA. Levantá el stack con ./scripts/start.sh"
    exit 1
  fi
  printf '\n\033[1mEstado actual\033[0m\n'
  tablero
  echo
  exit 0
fi

# ─── Comprobaciones previas ──────────────────────────────────────────────────

if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA/api/status" 2>/dev/null)" != "200" ]]; then
  mal "Kibana no responde en $KIBANA."
  detalle "Levantá el stack primero:  ./scripts/start.sh"
  exit 1
fi

printf '\n\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1m║  DEMOSTRACIÓN DESDE CERO                                     ║\033[0m\n'
printf '\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m\n'

narrar "Lo que hay ahora"
tablero

if ! $SIN_CONFIRMAR; then
  echo
  aviso "Se van a borrar las reglas desplegadas, las alertas, los índices de"
  aviso "Filebeat y los artefactos del pipeline. Todo eso es regenerable."
  aviso "El registro de auditoría NO se borra: se archiva en audit/archive/."
  read -r -p "  ¿Seguir? [y/N] " r
  [[ "$r" =~ ^[yY]$ ]] || { echo "  Cancelado."; exit 0; }
fi

# ─── 1 · Limpieza ────────────────────────────────────────────────────────────

paso "1/7 · Todo a cero"

# El registro de auditoría se ARCHIVA, nunca se borra (A-01). Mismo criterio que
# reset.sh: `mktemp -d` en vez del timestamp solo, porque dos corridas dentro del
# mismo segundo compartirían nombre y la segunda pisaría la evidencia de la primera.
HAY_AUDITORIA=false
for f in decisions.jsonl analysis_history.jsonl; do [[ -s "$f" ]] && HAY_AUDITORIA=true; done
if $HAY_AUDITORIA; then
  mkdir -p audit/archive
  DESTINO=$(mktemp -d "audit/archive/$(date -u +%Y%m%dT%H%M%SZ)-XXXX")
  for f in decisions.jsonl analysis_history.jsonl; do
    [[ -s "$f" ]] && mv "$f" "$DESTINO/"
  done
  chmod -R a-w "$DESTINO"
  ok "auditoría archivada en $DESTINO (solo lectura)"
else
  ok "no había auditoría que archivar"
fi

BORRADAS=$(kbn -X POST "$KIBANA/api/detection_engine/rules/_bulk_action" \
  -d '{"action":"delete","query":""}' 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("attributes",{}).get("summary",{}).get("succeeded","?"))' 2>/dev/null)
ok "reglas de detección borradas: ${BORRADAS:-0}"

ALERTAS_BORRADAS=$(es -X POST "$ES/$ALERTAS/_delete_by_query?refresh=true&conflicts=proceed" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("deleted",0))' 2>/dev/null)
ok "alertas borradas: ${ALERTAS_BORRADAS:-0}"

# Elasticsearch rechaza el borrado por comodín (`action.destructive_requires_name`),
# así que hay que enumerar los índices y borrarlos por nombre.
INDICES=$(es "$ES/_cat/indices/filebeat-*?h=index" 2>/dev/null | tr -d ' ' | paste -sd,)
if [[ -n "$INDICES" ]]; then
  es -X DELETE "$ES/$INDICES" >/dev/null 2>&1
  ok "índices de Filebeat borrados: $(echo "$INDICES" | tr ',' '\n' | wc -l)"
else
  ok "no había índices de Filebeat"
fi

rm -f siem_clean.json siem_incidents.json ai_report.json network_logs/*.json
ok "artefactos locales del pipeline limpiados"

narrar "Estado después de limpiar"
tablero

if [[ "$MODO" == "limpiar" ]]; then
  echo
  detalle "Listo. Todo en cero, el stack sigue arriba."
  detalle "Seguí a mano, o corré este script sin --limpiar para la guía completa."
  echo
  exit 0
fi

pausa 4

# ─── 2 · Mostrar el cero ─────────────────────────────────────────────────────

paso "2/7 · Mostrar que no hay nada"

detalle "Este es el momento de la demostración que hace falta que vean."
detalle ""
detalle "  Kibana → Security → Rules          0 reglas"
detalle "  Kibana → Security → Alerts         0 alertas"
detalle "  El panel en :5000                  vacío, con el mensaje de que no"
detalle "                                     hay incidentes en la ventana"
detalle ""
detalle "Lo que aparezca de acá en adelante se construye delante del público."
pausa 6

# ─── 3 · Desplegar las reglas ────────────────────────────────────────────────

paso "3/7 · Desplegar las reglas de detección"

detalle "Las 14 reglas viven versionadas en rules/ndjson/, como código."
detalle "Esto le enseña a Elastic QUÉ reconocer. No ejecuta nada sobre nadie."
pausa 3

if ./scripts/deploy-rules.sh >/tmp/desde-cero-reglas.log 2>&1; then
  ok "reglas desplegadas: $(n_reglas)"
  detalle "Volvé a Kibana → Security → Rules: estaban en 0."
else
  mal "falló el despliegue (ver /tmp/desde-cero-reglas.log)"
  exit 1
fi
pausa 5

# ─── 4 · Atacar ──────────────────────────────────────────────────────────────

paso "4/7 · Generar los ataques"

IP_ATAQUE="198.51.100.$(( (RANDOM % 200) + 20 ))"

detalle "Reconocimiento (T1046): sondeo de 26 puertos desde $IP_ATAQUE"
bash simulation/run-port-scan.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
  && ok "26 eventos de red" || { mal "falló el escaneo"; exit 1; }

detalle "Phishing (T1566): captura de credenciales hacia $IP_ATAQUE"
bash simulation/run-phishing.sh --offline --ip "$IP_ATAQUE" >/dev/null 2>&1 \
  && ok "visita + envío de credenciales" || { mal "falló el phishing"; exit 1; }

if $SIN_DOCKER; then
  aviso "fuerza bruta omitida (--sin-docker)"
else
  detalle ""
  detalle "Fuerza bruta SSH (T1110): Hydra real contra el contenedor ssh-target."
  detalle "Este no es sintético: los intentos pasan por Filebeat → Logstash →"
  detalle "Elasticsearch, la misma ruta que un ataque de verdad."
  docker compose --profile simulation up -d ssh-target hydra-attacker >/dev/null 2>&1
  for _ in $(seq 1 30); do
    docker exec hydra-attacker which hydra >/dev/null 2>&1 && break
    sleep 5
  done
  if timeout 300 bash simulation/run-brute-force.sh >/tmp/desde-cero-hydra.log 2>&1; then
    ok "24 fallos de autenticación + 1 login exitoso"
  else
    aviso "la fuerza bruta no completó; la demostración sigue con los otros dos"
  fi
fi

# ─── 5 · La ingesta ──────────────────────────────────────────────────────────

paso "5/7 · La ingesta, en vivo"

detalle "Filebeat recoge los logs, Logstash los normaliza, Elasticsearch los indexa."
printf '  esperando documentos'
for _ in $(seq 1 24); do
  D=$(n_docs)
  (( ${D:-0} > 0 )) && break
  printf '.'; sleep 5
done
printf '\r                          \r'
ok "documentos en Elasticsearch: $(n_docs)"
detalle "Hace un minuto el índice no existía."
pausa 4

# ─── 6 · Las reglas disparan ─────────────────────────────────────────────────

paso "6/7 · Las reglas disparan"

detalle "Cada regla corre en su intervalo (1 a 10 minutos). Cuando una encuentra"
detalle "su patrón, escribe una alerta. Esto es Elastic trabajando, no el proyecto."
printf '  esperando alertas'
for _ in $(seq 1 24); do
  A=$(n_alertas)
  (( ${A:-0} > 0 )) && break
  printf '.'; sleep 10
done
printf '\r                     \r'
N_AL=$(n_alertas)
if (( ${N_AL:-0} > 0 )); then
  ok "alertas generadas: $N_AL"
  detalle "Kibana → Security → Alerts: mirá el nombre de la regla que disparó."
else
  aviso "todavía no hay alertas (las reglas corren cada 1-10 min)"
  detalle "El pipeline igual detecta: el Agente 1 no depende del SIEM."
fi
pausa 4

# ─── 7 · Clasificar y supervisar ─────────────────────────────────────────────

paso "7/7 · Clasificación, análisis y panel"

detalle "Agente 1 (determinístico) → Agente 2 (explicación) → panel de supervisión"
if ! python3 siem_pipeline.py >/tmp/desde-cero-pipeline.log 2>&1; then
  mal "el pipeline falló (ver /tmp/desde-cero-pipeline.log)"
  exit 1
fi
ok "pipeline completo"

CAPTURA=$(captura_fresca)
case "$CAPTURA" in
  OK*)
    read -r _ N_ALERTAS_CAP N_LOGS_CAP <<<"$CAPTURA"
    ok "captura del SIEM: $N_ALERTAS_CAP alerta(s), $N_LOGS_CAP log(s) de autenticación"
    ;;
  *)
    echo
    mal "LA CAPTURA DE ELASTICSEARCH NO SE RENOVÓ ($CAPTURA)"
    detalle "El pipeline siguió con los datos que había —es una etapa tolerable— y"
    detalle "terminó bien, pero lo que vas a ver NO sale de esta corrida."
    detalle ""
    detalle "No presentes así: la demostración afirma justamente lo contrario."
    detalle "Revisá /tmp/desde-cero-pipeline.log; suele ser Elasticsearch devolviendo"
    detalle "400 en una consulta (ver D-12 en docs/12 §4.20)."
    exit 1
    ;;
esac

echo
python3 - <<'PY' 2>/dev/null
import json
import pathlib

p = pathlib.Path("siem_incidents.json")
if not p.exists():
    raise SystemExit

datos = json.loads(p.read_text(encoding="utf-8"))
print(f"      {'tipo':22} {'sev':7} {'ev':>4}  procedencia de la detección")
print("      " + "─" * 78)
for i in datos["incidents"]:
    c = i["classification"]
    if i.get("detection_source") == "elastic" and i.get("rule_name"):
        origen = f"Elastic SIEM · {i['rule_name']}"
    else:
        origen = "Agente 1 · determinística (sin pasar por Kibana)"
    print(f"      {c['attack_type']:22} {c['severity']:7} {i['event_count']:>4}  {origen}")
PY

narrar "Lo que acaba de pasar"
tablero

echo
detalle "Los cuatro números empezaron en cero. Nada de esto estaba guardado."
detalle ""
detalle "Y la última columna dice algo que conviene señalar: hay DOS caminos de"
detalle "detección. Los incidentes que dicen «Elastic SIEM» los encontró una de"
detalle "las reglas que acabás de desplegar. Los que dicen «Agente 1» los detectó"
detalle "el clasificador determinístico leyendo los logs de red, sin pasar por"
detalle "Kibana — y aparecerían igual aunque el SIEM estuviera caído."
detalle ""
detalle "Eso no es una carencia: es que la detección no depende de un solo motor."
echo
detalle "Abrí el panel: http://127.0.0.1:5000/login"
detalle "Ninguna acción se ejecutó. El sistema detectó, explicó y sugirió."
echo
