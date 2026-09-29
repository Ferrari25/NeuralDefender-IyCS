#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# pruebas_de_codigo_estatico.sh — Linters + SAST. Nada de esto EJECUTA el
# sistema: todo lee el código fuente y busca problemas antes de correrlo.
#
# Dos categorías, con un objetivo distinto cada una:
#   LINTERS — estilo y prolijidad (ruff, eslint). No buscan vulnerabilidades.
#   SAST    — seguridad: vulnerabilidades conocidas (bandit, pylint +
#             pylint-secure-coding-standard). No ejecutan nada tampoco.
#
# Uso:  ./scripts/pruebas_de_codigo_estatico.sh
#
# Requiere las dependencias de desarrollo instaladas (una sola vez):
#   python3 -m pip install --target=.devtools -r requirements-dev.txt
#   npm install
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"
BIN=".devtools/bin"
EXCLUIR='./.devtools,./.venv,./node_modules,./tests,./elasticsearch'
FALLOS=0

declare -A CAT_FALLOS CAT_COLOR
ORDEN_CATEGORIAS=()
CATEGORIA_ACTUAL=""

titulo() { # color  etiqueta  descripcion
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

# Línea de base: hallazgos preexistentes documentados en
# docs/04-auditoria-pruebas-y-demostracion.md. La puerta falla ante CUALQUIER hallazgo
# NUEVO; estos números solo pueden bajar, nunca subir sin justificar por qué.
BASE_RUFF=0
BASE_BANDIT_ALTOS=0

linea_base() { # nombre  esperado  actual  pista
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

paso() { # nombre  comando...
  local nombre="$1"; shift
  printf '    %-32s' "$nombre"
  if salida=$("$@" 2>&1); then
    printf '\033[32m✔ OK\033[0m\n'
  else
    printf '\033[31m✘ FALLA\033[0m\n'
    echo "$salida" | sed 's/^/        /' | tail -25
    registrar_fallo
  fi
}

titulo 36 "LINTERS" "— estilo y prolijidad, no buscan vulnerabilidades"
# El código nuevo (tests/) tiene que estar impecable: sin línea de base.
paso "ruff · tests/"                  $BIN/ruff check tests/
# El código del proyecto arrastra hallazgos conocidos: se mide contra la base.
n_ruff=$($BIN/ruff check . --output-format=concise 2>/dev/null | grep -cE '^[^ ]+\.py:[0-9]+')
linea_base "ruff · proyecto" "$BASE_RUFF" "${n_ruff:-99}" "Ver: .devtools/bin/ruff check ."
if [[ -d node_modules ]]; then
  paso "eslint (static/app.js)"       node_modules/.bin/eslint \
       --no-error-on-unmatched-pattern 'static/**/*.js'
else
  printf '    %-32s\033[33mOMITIDO\033[0m (falta npm install)\n' "eslint (static/app.js)"
fi

titulo 35 "SAST" "— seguridad: vulnerabilidades conocidas, no ejecuta nada"
paso "pylint + secure-coding-standard" $BIN/pylint --fail-under=9.0 \
     src/classifier.py src/siem_lib.py src/dashboard.py src/siem_agent.py src/siem_pipeline.py \
     src/siem_validators.py src/siem_auth.py src/manage_users.py src/audit_verify.py \
     src/get-logs.py src/prepare-for-ia.py src/verify-cobertura.py

n_bandit=$($BIN/bandit -r . -x "$EXCLUIR" -f json -q 2>/dev/null \
  | python3 -c 'import json,sys; print(sum(1 for r in json.load(sys.stdin)["results"] if r["issue_severity"]=="HIGH"))' 2>/dev/null)
linea_base "bandit · severidad alta" "$BASE_BANDIT_ALTOS" "${n_bandit:-99}" \
  "Ver: .devtools/bin/bandit -r . -x '$EXCLUIR' -lll"
printf '    %-32s\033[36mnota\033[0m: eslint-plugin-security / no-unsanitized ya corrieron arriba, dentro de eslint\n' " "

printf '\n\033[1m════════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1m  RESUMEN — CÓDIGO ESTÁTICO\033[0m\n'
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
