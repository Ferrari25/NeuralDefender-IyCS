#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# check.sh — Puerta de calidad completa (SAST + pruebas).
#
# Es lo que va a correr CI en la Fase 2. Hoy se corre a mano:
#
#   ./scripts/check.sh              todo
#   ./scripts/check.sh --sast       solo análisis estático
#   ./scripts/check.sh --tests      solo pruebas
#
# Requiere las dependencias de desarrollo:
#   python3 -m pip install --target=.devtools -r requirements-dev.txt
#   npm install
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"
BIN=".devtools/bin"
EXCLUIR='./.devtools,./.venv,./node_modules,./tests,./elasticsearch'

MODO="${1:-todo}"
FALLOS=0

# Categorías separadas a propósito (pedido de demo): "análisis estático" no es
# una sola cosa — un LINTER busca estilo/prolijidad (ruff, eslint) y el SAST de
# seguridad busca vulnerabilidades conocidas (bandit, pylint+secure-coding-
# standard). Las pruebas, además, distinguen UNITARIA (una función aislada) de
# SERVICIO (el contrato real: API, scripts, un Kibana simulado) de ESTÁTICO
# (una certificación por AST, no una ejecución). Ver docs/12-registro-de-pruebas.md §2.
declare -A CAT_FALLOS CAT_COLOR
ORDEN_CATEGORIAS=()
CATEGORIA_ACTUAL=""

titulo() { # color(36/35/33/34/96/1)  etiqueta  nombre
  local color="$1" etiqueta="$2" nombre="$3"
  printf '\n\033[1;%sm▶ %-9s\033[0m \033[1m%s\033[0m\n' "$color" "$etiqueta" "$nombre"
  CATEGORIA_ACTUAL="$etiqueta $nombre"
  ORDEN_CATEGORIAS+=("$CATEGORIA_ACTUAL")
  CAT_FALLOS["$CATEGORIA_ACTUAL"]=0
  CAT_COLOR["$CATEGORIA_ACTUAL"]="$color"
}

registrar_fallo() {
  FALLOS=$((FALLOS + 1))
  [[ -n "$CATEGORIA_ACTUAL" ]] && CAT_FALLOS["$CATEGORIA_ACTUAL"]=$((CAT_FALLOS["$CATEGORIA_ACTUAL"] + 1))
}

# Línea de base de la Fase 0: hallazgos preexistentes, ya documentados en
# docs/11-reporte-fase-0.md y agendados para las Fases 1 y 2. La puerta falla
# ante CUALQUIER hallazgo NUEVO; estos números solo pueden BAJAR.
# Estado al cierre de la Fase 2: ambos en CERO.
#   ruff    0 → los 12 de estilo/imports se corrigieron con los refactors R-01..R-04
#   bandit  0 → los 2 B324 (sha1) pasaron a sha256 con usedforsecurity=False.
#              Quedan 2 LOW (B404/B603) en siem_pipeline.py, justificados por la
#              allowlist de no-autonomía; la puerta solo cuenta severidad alta.
BASE_RUFF=0
BASE_BANDIT_ALTOS=0

linea_base() { # nombre  esperado  cantidad_actual  pista
  local nombre="$1" esperado="$2" actual="$3" pista="$4"
  printf '    %-32s' "$nombre"
  if (( actual > esperado )); then
    printf '\033[31mFALLA\033[0m  %d hallazgos (línea de base: %d) — hay %d nuevo(s)\n' \
      "$actual" "$esperado" "$((actual - esperado))"
    echo "        $pista"
    registrar_fallo
  elif (( actual < esperado )); then
    printf '\033[32mMEJORA\033[0m %d hallazgos (línea de base era %d) — bajá BASE_* en este script\n' \
      "$actual" "$esperado"
  else
    printf '\033[33mBASE\033[0m   %d hallazgo(s) conocido(s), sin regresiones\n' "$actual"
  fi
}
paso()   { # nombre  comando...
  local nombre="$1"; shift
  printf '    %-32s' "$nombre"
  if salida=$("$@" 2>&1); then
    # Si es una corrida de pytest, mostrar el conteo real ("N passed en X.XXs")
    # en vez de un OK a secas — más convincente en vivo que una etiqueta fija,
    # y no queda obsoleto cuando se agregan pruebas.
    ultima=$(echo "$salida" | grep -oE '[0-9]+ passed[a-záéíóúñ, 0-9.]*' | tail -1)
    if [[ -n "$ultima" ]]; then
      printf '\033[32m✔ OK\033[0m  \033[2m(%s)\033[0m\n' "$ultima"
    else
      printf '\033[32m✔ OK\033[0m\n'
    fi
  else
    printf '\033[31m✘ FALLA\033[0m\n'
    echo "$salida" | sed 's/^/        /' | tail -25
    registrar_fallo
  fi
}

if [[ "$MODO" == "todo" || "$MODO" == "--sast" ]]; then
  titulo 36 "LINTERS" "— estilo y prolijidad, no buscan vulnerabilidades"
  # El código nuevo (tests/) tiene que estar impecable: sin línea de base.
  paso "ruff · tests/"                  $BIN/ruff check tests/
  # El código del proyecto arrastra hallazgos conocidos: se mide contra la base.
  n_ruff=$($BIN/ruff check . --output-format=concise 2>/dev/null | grep -cE '^[^ ]+\.py:[0-9]+' )
  linea_base "ruff · proyecto" "$BASE_RUFF" "${n_ruff:-99}" "Ver: .devtools/bin/ruff check ."
  if [[ -d node_modules ]]; then
    paso "eslint (static/app.js)"       node_modules/.bin/eslint \
         --no-error-on-unmatched-pattern 'static/**/*.js'
  else
    printf '    %-32s\033[33mOMITIDO\033[0m (falta npm install)\n' "eslint (static/app.js)"
  fi

  titulo 35 "SAST" "— seguridad: vulnerabilidades conocidas, no ejecuta nada"
  paso "pylint + secure-coding-standard" $BIN/pylint --fail-under=9.0 \
       classifier.py siem_lib.py dashboard.py siem_agent.py siem_pipeline.py \
       siem_validators.py siem_auth.py manage_users.py audit_verify.py \
       get-logs.py prepare-for-ia.py verify-cobertura.py

  n_bandit=$($BIN/bandit -r . -x "$EXCLUIR" -f json -q 2>/dev/null \
    | python3 -c 'import json,sys; print(sum(1 for r in json.load(sys.stdin)["results"] if r["issue_severity"]=="HIGH"))' 2>/dev/null)
  linea_base "bandit · severidad alta" "$BASE_BANDIT_ALTOS" "${n_bandit:-99}" \
    "Ver: .devtools/bin/bandit -r . -x '$EXCLUIR' -lll"
  printf '    %-32s\033[36mnota\033[0m: eslint-plugin-security / no-unsanitized ya corrieron arriba, dentro de eslint\n' " "
fi

if [[ "$MODO" == "todo" || "$MODO" == "--tests" ]]; then
  titulo 33 "ESTÁTICO" "— certificación por AST (no ejecuta el sistema)"
  paso "no-autonomía (AST)"             $BIN/pytest -q tests/test_no_autonomy.py

  titulo 34 "UNITARIAS" "— una función o módulo aislado (tests/unit/)"
  paso "pytest tests/unit"              $BIN/pytest -q tests/unit

  titulo 96 "SERVICIO" "— contrato real: API, deploy-rules.sh, reset.sh (tests/integration/)"
  paso "pytest tests/integration"       $BIN/pytest -q tests/integration

  titulo 1 "COBERTURA" "— ≥ 80% sobre el alcance declarado (§4.1)"
  paso "6 módulos del alcance §4.1"     $BIN/pytest -q \
       --cov=classifier --cov=siem_lib --cov=dashboard \
       --cov=siem_validators --cov=siem_auth --cov=manage_users \
       --cov-fail-under=80 --cov-report=
fi

printf '\n\033[1m════════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1m  RESUMEN\033[0m\n'
printf '\033[1m════════════════════════════════════════════════════════════\033[0m\n'
for cat in "${ORDEN_CATEGORIAS[@]}"; do
  color="${CAT_COLOR[$cat]}"
  if (( CAT_FALLOS["$cat"] == 0 )); then
    printf '  \033[1;%sm%-55s\033[0m \033[32m✔\033[0m\n' "$color" "$cat"
  else
    printf '  \033[1;%sm%-55s\033[0m \033[31m✘ (%d)\033[0m\n' "$color" "$cat" "${CAT_FALLOS[$cat]}"
  fi
done
echo
if (( FALLOS == 0 )); then
  echo "  ✅ Todo en verde."
else
  echo "  ❌ $FALLOS etapa(s) con fallos."
fi
exit $(( FALLOS > 0 ))
