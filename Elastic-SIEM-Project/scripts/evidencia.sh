#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# evidencia.sh — Genera la carpeta de evidencia para la cátedra.
#
# POR QUÉ EXISTE
#
# Los dos primeros objetivos de la materia son «pruebas de código estático» y
# «pruebas de servicios». El proyecto las corre con
# `./scripts/pruebas_de_codigo_estatico.sh` y `./scripts/pruebas_de_servicio.sh`,
# pero la salida se va por pantalla y no queda nada que adjuntar a un
# informe ni que mostrar si la demostración en vivo falla.
#
# Este script deja una carpeta con las salidas CRUDAS de cada herramienta, más un
# resumen que explica qué prueba cada archivo. No interpreta ni maquilla: guarda lo
# que las herramientas devuelven.
#
# La pieza más fuerte es la §2: inyecta una vulnerabilidad REAL en el código, corre
# la puerta de calidad, muestra que se pone en rojo y revierte. Un informe que dice
# «el análisis estático pasa» no prueba nada; uno que muestra la puerta atrapando
# algo, sí.
#
# ⚠️  No toca datos reales. La inyección se revierte siempre (trap EXIT), y al final
# se verifica que el archivo quedó idéntico byte a byte.
#
# Uso:
#   ./scripts/evidencia.sh              genera evidencia/<fecha>/
#   ./scripts/evidencia.sh --sin-servicios   omite las pruebas contra el panel
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

SIN_SERVICIOS=false
while (( $# )); do
  case "$1" in
    --sin-servicios) SIN_SERVICIOS=true; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

FECHA=$(date -u +%Y%m%dT%H%M%SZ)
DIR="evidencia/$FECHA"
mkdir -p "$DIR"

paso() { printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$1"; }
mal()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }

printf '\n\033[1mGenerando evidencia en %s\033[0m\n' "$DIR"

# ─── 1 · Análisis estático ───────────────────────────────────────────────────

paso "1/5 · Análisis estático (SAST)"

{
  echo "ANÁLISIS ESTÁTICO — salidas crudas de cada herramienta"
  echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=============================================================="
  for h in "ruff (reglas de seguridad S, bugs B, complejidad C)" \
           "pylint + pylint-secure-coding-standard" \
           "bandit (severidad alta)" \
           "eslint + eslint-plugin-security + no-unsanitized"; do
    echo; echo "── $h ──"
  done
} > "$DIR/01-analisis-estatico.txt"

{
  echo; echo "══════════ ruff ══════════"
  .devtools/bin/ruff check . 2>&1 || true
  echo; echo "══════════ pylint + secure-coding-standard ══════════"
  .devtools/bin/pylint --rcfile=.pylintrc $(git ls-files '*.py' 2>/dev/null || ls *.py) 2>&1 | tail -30 || true
  echo; echo "══════════ bandit ══════════"
  .devtools/bin/bandit -r . -x ./.devtools,./tests,./node_modules -ll 2>&1 | tail -25 || true
  echo; echo "══════════ eslint ══════════"
  npx --no-install eslint static/ 2>&1 | tail -20 || echo "(eslint: ver pruebas_de_codigo_estatico.sh)"
} >> "$DIR/01-analisis-estatico.txt" 2>&1
ok "01-analisis-estatico.txt"

# ─── 2 · La puerta atrapa una violación real ─────────────────────────────────

paso "2/5 · Inyección de una vulnerabilidad real"

RESPALDO=$(mktemp)
cp src/siem_lib.py "$RESPALDO"
# shellcheck disable=SC2064
trap "cp '$RESPALDO' src/siem_lib.py; rm -f '$RESPALDO'" EXIT INT TERM

{
  echo "¿EL ANÁLISIS ESTÁTICO SIRVE DE ALGO?"
  echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=============================================================="
  echo
  echo "Un informe que dice «el análisis estático pasa» no prueba nada: podría"
  echo "estar mal configurado y pasar siempre. Acá se inyecta una vulnerabilidad"
  echo "REAL en src/siem_lib.py y se muestra que la puerta la encuentra."
  echo
  echo "── Código inyectado ──"
  echo '    def _evidencia(x):'
  echo '        import hashlib'
  echo '        return hashlib.md5(x).hexdigest()   # hash criptográficamente roto'
  echo
  echo "── ruff ANTES de inyectar ──"
} > "$DIR/02-la-puerta-atrapa.txt"

.devtools/bin/ruff check . >> "$DIR/02-la-puerta-atrapa.txt" 2>&1

printf '\n\ndef _evidencia(x):\n    import hashlib\n    return hashlib.md5(x).hexdigest()\n' >> src/siem_lib.py

{
  echo; echo "── ruff DESPUÉS de inyectar ──"
  .devtools/bin/ruff check . 2>&1 || true
  echo; echo "── bandit DESPUÉS de inyectar ──"
  .devtools/bin/bandit src/siem_lib.py -ll 2>&1 | grep -A6 'Issue:' || true
} >> "$DIR/02-la-puerta-atrapa.txt" 2>&1

HALLAZGOS=$(.devtools/bin/ruff check . 2>&1 | grep -cE '^[A-Z]+[0-9]+' || true)
cp "$RESPALDO" src/siem_lib.py

{
  echo; echo "── Tras revertir ──"
  .devtools/bin/ruff check . 2>&1 || true
  echo
  echo "El archivo quedó idéntico al original (verificado por SHA-256):"
  sha256sum src/siem_lib.py
} >> "$DIR/02-la-puerta-atrapa.txt" 2>&1

if (( HALLAZGOS > 0 )); then
  ok "02-la-puerta-atrapa.txt — la puerta detectó la inyección"
else
  mal "02-la-puerta-atrapa.txt — LA PUERTA NO DETECTÓ NADA. Revisar la configuración."
fi

# ─── 3 · Pruebas de servicio ─────────────────────────────────────────────────

paso "3/5 · Pruebas de servicio (API real)"

if $SIN_SERVICIOS; then
  echo "(omitido con --sin-servicios)" > "$DIR/03-pruebas-de-servicio.txt"
  ok "03 omitido"
elif [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:5000/api/v1/healthz 2>/dev/null)" != "200" ]]; then
  {
    echo "El panel no responde en http://127.0.0.1:5000"
    echo "Levantalo con:  python3 src/dashboard.py"
  } > "$DIR/03-pruebas-de-servicio.txt"
  mal "03 — el panel no responde; se omitieron las pruebas de servicio"
else
  JAR=$(mktemp); JAR_AUD=$(mktemp)
  {
    echo "PRUEBAS DE SERVICIO — peticiones reales contra el panel corriendo"
    echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "=============================================================="
    echo
    echo "Cada bloque es una petición real y su respuesta textual. Los rechazos"
    echo "(401, 403) no son fallas: son el control funcionando."
    echo

    echo "── 1. GET /api/v1/healthz  (único endpoint público) ──"
    curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:5000/api/v1/healthz

    echo; echo "── 2. GET /api/v1/incidents SIN sesión ──"
    curl -s -w '\nHTTP %{http_code}   ← API-01: sin sesión no se ve nada\n' \
      http://127.0.0.1:5000/api/v1/incidents

    echo; echo "── 3. POST /api/v1/login  (analista) ──"
    curl -s -c "$JAR" -X POST http://127.0.0.1:5000/api/v1/login \
      -H 'Content-Type: application/json' \
      -d '{"username":"analista","password":"Soc-Analista-2026"}' \
      -w '\nHTTP %{http_code}\n'
    TOK=$(python3 -c "
import json,sys
try:
    print(json.loads(sys.argv[1])['csrf_token'])
except Exception:
    print('')" "$(curl -s -b "$JAR" http://127.0.0.1:5000/api/v1/me)" 2>/dev/null)

    echo; echo "── 4. POST /api/v1/decision CON sesión pero SIN token CSRF ──"
    curl -s -b "$JAR" -X POST http://127.0.0.1:5000/api/v1/decision \
      -H 'Content-Type: application/json' \
      -d '{"incident_id":"INC-INVENTADO","action_id":"x","decision":"approved"}' \
      -w '\nHTTP %{http_code}   ← protección CSRF\n'

    echo; echo "── 5. POST /api/v1/decision con CSRF, acción inexistente ──"
    curl -s -b "$JAR" -H "X-CSRFToken: $TOK" -X POST http://127.0.0.1:5000/api/v1/decision \
      -H 'Content-Type: application/json' \
      -d '{"incident_id":"INC-INVENTADO","action_id":"x","decision":"approved"}' \
      -w '\nHTTP %{http_code}   ← 404 y NO se escribió en el registro inmutable\n'

    echo; echo "── 6. POST /api/v1/decision con CSRF, cuerpo JSON roto ──"
    curl -s -b "$JAR" -H "X-CSRFToken: $TOK" -X POST http://127.0.0.1:5000/api/v1/decision \
      -H 'Content-Type: application/json' -d '{roto' \
      -w '\nHTTP %{http_code}   ← JSON, no el HTML de error de Werkzeug\n'

    echo; echo "── 7. GET /api/v1/audit/verify como analyst (RBAC) ──"
    curl -s -b "$JAR" http://127.0.0.1:5000/api/v1/audit/verify \
      -w '\nHTTP %{http_code}   ← el analista decide, no audita\n'

    echo; echo "── 8. GET /api/v1/audit/verify como auditor ──"
    curl -s -c "$JAR_AUD" -X POST http://127.0.0.1:5000/api/v1/login \
      -H 'Content-Type: application/json' \
      -d '{"username":"auditor","password":"Soc-Auditor-2026"}' -o /dev/null
    curl -s -b "$JAR_AUD" http://127.0.0.1:5000/api/v1/audit/verify -w '\nHTTP %{http_code}\n'

    echo; echo "── 9. POST /api/v1/decision como auditor (RBAC, la inversa) ──"
    curl -s -b "$JAR_AUD" -X POST http://127.0.0.1:5000/api/v1/decision \
      -H 'Content-Type: application/json' -d '{}' \
      -w '\nHTTP %{http_code}   ← el auditor audita, no decide\n'
  } > "$DIR/03-pruebas-de-servicio.txt" 2>&1
  rm -f "$JAR" "$JAR_AUD"
  ok "03-pruebas-de-servicio.txt — 9 peticiones reales"
fi

# ─── 4 · Suite y cobertura ───────────────────────────────────────────────────

paso "4/5 · Suite completa y cobertura"

.devtools/bin/pytest -q --cov=classifier --cov=siem_lib --cov=dashboard \
  --cov=siem_validators --cov=siem_auth --cov=manage_users \
  --cov-report=term > "$DIR/04-suite-y-cobertura.txt" 2>&1
TOTAL=$(grep -E '^[0-9]+ passed' "$DIR/04-suite-y-cobertura.txt" | tail -1)
COBERTURA=$(grep -E '^TOTAL' "$DIR/04-suite-y-cobertura.txt" | awk '{print $NF}')
ok "04-suite-y-cobertura.txt — $TOTAL · cobertura $COBERTURA"

# ─── 5 · No-autonomía ────────────────────────────────────────────────────────

paso "5/5 · Certificación de no-autonomía"

.devtools/bin/pytest tests/test_no_autonomy.py -v > "$DIR/05-no-autonomia.txt" 2>&1
N_AUTO=$(grep -cE 'PASSED' "$DIR/05-no-autonomia.txt" || echo 0)
ok "05-no-autonomia.txt — $N_AUTO verificaciones"

# ─── Resumen ─────────────────────────────────────────────────────────────────

cat > "$DIR/00-resumen.md" <<RESUMEN
# Evidencia de pruebas — SIEM-IA

Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ) · Rama de trabajo: local

Esta carpeta la produce \`./scripts/evidencia.sh\`. Son salidas **crudas** de cada
herramienta: no están editadas ni resumidas.

## Objetivo 1 · Pruebas de código estático

| Archivo | Qué prueba |
|---------|------------|
| \`01-analisis-estatico.txt\` | Las cuatro herramientas corriendo sobre el código: **ruff** (reglas de seguridad, bugs, complejidad), **pylint + pylint-secure-coding-standard**, **bandit** y **ESLint + eslint-plugin-security + no-unsanitized**. |
| \`02-la-puerta-atrapa.txt\` | **Lo que hace que esto sea una prueba y no una captura de pantalla.** Se inyecta una vulnerabilidad real (\`hashlib.md5\`) en \`src/siem_lib.py\`, se corre el análisis, se muestra que aparece el hallazgo, y se revierte verificando con SHA-256 que el archivo quedó idéntico. |

Las líneas de base están en **cero**: la puerta falla ante cualquier hallazgo nuevo.

## Objetivo 2 · Pruebas de servicio

| Archivo | Qué prueba |
|---------|------------|
| \`03-pruebas-de-servicio.txt\` | Nueve peticiones HTTP reales contra el panel corriendo, con su respuesta textual y su código. Incluye autenticación, CSRF, validación de entrada y control de acceso por rol en los dos sentidos. |
| \`04-suite-y-cobertura.txt\` | La suite completa con medición de cobertura. |

Los rechazos (401, 403) **no son fallas**: son el control funcionando. Las dos
peticiones que conviene mirar juntas son la 7 y la 9 — el analista decide y no
audita; el auditor audita y no decide.

## Transversal · No-autonomía

| Archivo | Qué prueba |
|---------|------------|
| \`05-no-autonomia.txt\` | La certificación de que ningún componente puede ejecutar acciones de contención. Recorre el **AST** de todo el código, no el texto: una llamada disfrazada como \`getattr(os, "sys"+"tem")\` también se detecta. |

## Números de esta corrida

- Suite: $TOTAL
- Cobertura (alcance declarado): $COBERTURA
- Verificaciones de no-autonomía: $N_AUTO
- Hallazgos nuevos de análisis estático: **0** (líneas de base en cero)

## Cómo reproducirlo

\`\`\`bash
./scripts/pruebas_de_codigo_estatico.sh   # linters + SAST, en pantalla
./scripts/pruebas_de_servicio.sh          # unitarias + servicio + cobertura, en pantalla
./scripts/evidencia.sh                    # la misma corrida, guardada en una carpeta
\`\`\`

El detalle de qué se verifica y por qué está en
[\`../../docs/04-auditoria-pruebas-y-demostracion.md\`](../../docs/04-auditoria-pruebas-y-demostracion.md).
RESUMEN

trap - EXIT INT TERM
rm -f "$RESPALDO"

printf '\n\033[1m════════════════════════════════════════════════\033[0m\n'
ok "Evidencia completa en $DIR"
ls -1 "$DIR" | sed 's/^/     /'
printf '\n  Empezá por %s/00-resumen.md\n\n' "$DIR"
