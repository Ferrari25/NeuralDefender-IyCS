#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# pruebas_de_servicio.sh — Todo lo que EJECUTA el sistema (a diferencia de
# pruebas_de_codigo_estatico.sh, que solo lee el código).
#
# Cuatro categorías, cada una verificando algo distinto:
#   ESTÁTICO   — certificación por AST de que nada ejecuta comandos (no
#                corre el sistema, pero vive acá por ser una prueba pytest).
#   UNITARIAS  — una función o módulo aislado (tests/unit/).
#   SERVICIO   — el contrato real: API HTTP, deploy-rules.sh contra un Kibana
#                simulado, reset.sh contra un sandbox real (tests/integration/).
#                Le da nombre al script porque es la parte que de verdad
#                ejercita un servicio corriendo, no una función suelta.
#   COBERTURA  — ≥ 80% sobre el alcance declarado, corriendo unitarias +
#                servicio juntas.
#
# Uso:  ./scripts/pruebas_de_servicio.sh
#
# Requiere las dependencias de desarrollo instaladas (una sola vez):
#   python3 -m pip install --target=.devtools -r requirements-dev.txt
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"
BIN=".devtools/bin"
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

paso() { # nombre  comando...
  local nombre="$1"; shift
  printf '    %-32s' "$nombre"
  if salida=$("$@" 2>&1); then
    # Mostrar el conteo real de pytest ("N passed in X.XXs") en vez de un OK a
    # secas — más convincente en vivo, y no queda obsoleto al agregar pruebas.
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

titulo 33 "ESTÁTICO" "— certificación por AST (no ejecuta el sistema)"
paso "no-autonomía (AST)"             $BIN/pytest -q tests/test_no_autonomy.py

titulo 34 "UNITARIAS" "— una función o módulo aislado (tests/unit/)"
paso "pytest tests/unit"              $BIN/pytest -q tests/unit

titulo 96 "SERVICIO" "— contrato real: API, deploy-rules.sh, reset.sh (tests/integration/)"
paso "pytest tests/integration"       $BIN/pytest -q tests/integration

titulo 1 "COBERTURA" "— ≥ 80% sobre el alcance declarado"
paso "6 módulos del alcance"          $BIN/pytest -q \
     --cov=classifier --cov=siem_lib --cov=dashboard \
     --cov=siem_validators --cov=siem_auth --cov=manage_users \
     --cov-fail-under=80 --cov-report=

printf '\n\033[1m════════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1m  RESUMEN — PRUEBAS\033[0m\n'
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
