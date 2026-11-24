#!/bin/bash
# Verifica, contra la malla aislada que esté corriendo, cuatro cosas del plan de pruebas:
#   A. Que los servicios internos se alcanzan desde el equipo (y por tanto desde Postman de escritorio).
#   B. DELETE /api/v1/decisions: ¿405?                         (CP-SERV-32, RF-AUD-03)
#   C. Título de documento de 121 caracteres: ¿400?            (CP-SERV-41, límite 120)
#   D. El CSV del reporte neutraliza las fórmulas: ¿RF-REP-03? (CP-SERV-39)
#
# ESCRIBE en la malla (una decisión por prefijo y dos documentos), así que después hay que
# volver al estado inicial:   ./entregables/2-servicios/postman/malla.sh reiniciar
# No toca el sistema real. Uso: ./entregables/2-servicios/postman/verificar_malla.sh
set -u
GW=http://127.0.0.1:18080
TOK="token-interno-de-prueba-malla-postman-2026-0001"
PASS="PruebaMalla#2026"
J="$(mktemp)"; trap 'rm -f "$J" /tmp/csv-malla.txt' EXIT
CT='Content-Type: application/json'

linea() { printf '%-58s %s\n' "$1" "$2"; }

echo "##### A. Servicios internos, desde el equipo (sin Docker)"
for s in "auth 18001 GET /v1/users-summary" "audit 18002 GET /v1/decisions/verify" \
         "collector 18003 GET /v1/snapshots/latest" "classifier 18004 POST /v1/classify" \
         "analyst 18005 POST /v1/analyze" "pipeline 18006 GET /v1/incidents" \
         "knowledge 18007 GET /v1/documents"; do
  set -- $s; svc=$1; port=$2; metodo=$3; ruta=$4
  cuerpo='{}'; [ "$svc" = analyst ] && cuerpo='{"incidents":[]}'
  salud=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/v1/healthz")
  sin=$(curl -s -m 8 -o /dev/null -w '%{http_code}' -X "$metodo" -H "$CT" -d "$cuerpo" "http://127.0.0.1:$port$ruta")
  con=$(curl -s -m 8 -o /dev/null -w '%{http_code}' -X "$metodo" -H "$CT" -H "X-Internal-Token: $TOK" -d "$cuerpo" "http://127.0.0.1:$port$ruta")
  linea "$svc (puerto $port)  $metodo $ruta" "salud=$salud  sin_token=$sin  con_token=$con"
done
echo "(collector con token da 404 porque la malla todavía no tiene ninguna captura: el token SÍ se aceptó)"

echo; echo "##### Inicio de sesión como analista00 y como auditor00"
r=$(curl -s -c "$J" -b "$J" -H "$CT" -d "{\"username\":\"analista00\",\"password\":\"$PASS\"}" -w '|%{http_code}' "$GW/api/v1/login")
codigo=${r##*|}; CSRF=$(printf '%s' "${r%|*}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')
echo "login analista00: HTTP $codigo"
H="X-CSRFToken: $CSRF"
INC=$(curl -s -b "$J" "$GW/api/v1/incidents" | python3 -c 'import json,sys; d=json.load(sys.stdin); i=d["incidents"][0]; print(i["incident_id"], i["recommended_actions"][0]["action_id"])')
set -- $INC; INC_ID=$1; ACT_ID=$2
echo "incidente y acción usados: $INC_ID  $ACT_ID"

echo; echo "##### B. DELETE /api/v1/decisions (no debe existir forma de borrar decisiones)"
linea "GET    /api/v1/decisions (la ruta existe)" "HTTP $(curl -s -o /dev/null -w '%{http_code}' -b "$J" "$GW/api/v1/decisions")"
linea "DELETE /api/v1/decisions con sesión de analista + CSRF" "HTTP $(curl -s -o /tmp/b-del -w '%{http_code}' -X DELETE -b "$J" -H "$H" "$GW/api/v1/decisions")  $(head -c 90 /tmp/b-del)"
linea "DELETE /api/v1/decisions con sesión, sin CSRF" "HTTP $(curl -s -o /dev/null -w '%{http_code}' -X DELETE -b "$J" "$GW/api/v1/decisions")"
linea "DELETE /api/v1/decisions sin sesión" "HTTP $(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$GW/api/v1/decisions")"
linea "DELETE /v1/decisions en audit (con token)" "HTTP $(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Internal-Token: $TOK" http://127.0.0.1:18002/v1/decisions)"
rm -f /tmp/b-del

echo; echo "##### C. Título de documento (límite 120 caracteres)"
for n in 120 121 0; do
  t=$(head -c "$n" /dev/zero | tr '\0' 'T')
  linea "POST /api/v1/memoria/documentos, titulo de $n caracteres" "HTTP $(curl -s -o /tmp/b-doc -w '%{http_code}' -b "$J" -H "$H" -H "$CT" -d "{\"titulo\":\"$t\",\"contenido\":\"contenido de prueba\"}" "$GW/api/v1/memoria/documentos")  $(head -c 80 /tmp/b-doc | cut -c1-80)"
done
rm -f /tmp/b-doc

echo; echo "##### D. Neutralización de fórmulas en el CSV del reporte (RF-REP-03)"
echo "-- Notas que se mandan por el gateway (el gateway recorta espacios y tabuladores del inicio):"
for nota in '=HYPERLINK(\"x\")' '+1+1' '-2+3' '@SUM(A1)' 'texto normal'; do
  c=$(curl -s -o /dev/null -w '%{http_code}' -b "$J" -H "$H" -H "$CT" -d "{\"incident_id\":\"$INC_ID\",\"action_id\":\"$ACT_ID\",\"decision\":\"approved\",\"note\":\"$nota\"}" "$GW/api/v1/decision")
  linea "  POST /api/v1/decision note=$nota" "HTTP $c"
done
echo "-- Notas con tabulador o retorno de carro al inicio (solo se pueden mandar directo al servicio audit):"
for nota in '\t=cmd' '\r=cmd'; do
  c=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Internal-Token: $TOK" -H "$CT" -d "{\"incident_id\":\"$INC_ID\",\"action_id\":\"$ACT_ID\",\"decision\":\"approved\",\"analyst\":\"verificacion\",\"note\":\"$nota\"}" http://127.0.0.1:18002/v1/decisions)
  linea "  POST /v1/decisions (audit) note=$nota" "HTTP $c"
done
curl -s -b "$J" "$GW/api/v1/reportes?formato=csv" -D /tmp/cab-csv -o /tmp/csv-malla.txt
echo "-- GET /api/v1/reportes?formato=csv: $(head -1 /tmp/cab-csv | tr -d '\r') | $(grep -i '^content-type' /tmp/cab-csv | tr -d '\r') | $(grep -i '^content-disposition' /tmp/cab-csv | tr -d '\r')"
rm -f /tmp/cab-csv
echo "-- Columna 'detalle' (la nota) de cada fila de decisión, tal como la leería Excel:"
python3 - <<'PY'
import csv, io
filas = [f for f in csv.DictReader(io.StringIO(open("/tmp/csv-malla.txt", encoding="utf-8", newline="").read()))
         if f["registro"] == "decision"]
peligrosas = 0
for f in filas:
    celda = f["detalle"]
    empieza_con_formula = celda[:1] in ("=", "+", "-", "@", "\t", "\r")
    peligrosas += empieza_con_formula
    print(f"  {celda!r:<28} empieza con caracter de formula: {'SI' if empieza_con_formula else 'no'}")
print(f"-- Filas de decision: {len(filas)} | celdas de nota que empiezan con =, +, -, @, tab o CR: {peligrosas}")
PY
echo "-- Texto crudo de las primeras líneas del CSV:"
grep -n "HYPERLINK\|,cmd\|SUM(A1)" /tmp/csv-malla.txt | cut -c1-40,150-260 | head -6
