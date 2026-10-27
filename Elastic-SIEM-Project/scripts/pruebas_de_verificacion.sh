#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# pruebas_de_verificacion.sh — ¿Las pruebas detectan errores de verdad?
#
# Un "todo en verde" no prueba nada por sí solo: también saldría verde si las
# herramientas no miraran ningún archivo. Este script corre 25 casos:
#
#   20 casos SANOS (80 %)   — el código tal como está. Cada uno corre un grupo
#                             de linters o de pruebas. TIENEN que pasar.
#    5 casos MUTANTES (20 %) — se inyecta un defecto real (una vulnerabilidad,
#                             un permiso borrado, una lección sin aprobar) y se
#                             corre la herramienta que lo cuida. TIENEN que fallar.
#
# La verificación es correcta solo si salen exactamente 20 ✔ y 5 ✘, cada uno
# donde se esperaba. Un sano que falla es un error del código; un mutante que
# pasa es una prueba que no está mirando.
#
# Todo corre sobre una COPIA temporal del proyecto: el repositorio real nunca
# se modifica, ni siquiera durante la corrida, y la copia se borra al terminar.
#
# Uso:  ./scripts/pruebas_de_verificacion.sh        (~2 min)
#
# Requiere las dependencias de desarrollo (ver pruebas_de_linters.md §2).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."
ORIGEN="$PWD"

if [[ ! -x .devtools/bin/pytest || ! -x .devtools/bin/ruff ]]; then
  echo "Faltan las herramientas en .devtools/bin. Instalalas con:"
  echo "  python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt"
  exit 1
fi

# ─── Copia de trabajo ────────────────────────────────────────────────────────
COPIA=$(mktemp -d "${TMPDIR:-/tmp}/siem-verificacion.XXXXXX")
# La auditoría archivada es de solo lectura a propósito (A-01): devolverle
# permiso de escritura dentro de la copia para poder borrarla.
trap 'chmod -R u+w "$COPIA" 2>/dev/null; rm -rf "$COPIA"' EXIT
tar -C "$ORIGEN" --exclude=./.devtools --exclude=./node_modules --exclude=./.git \
    --exclude='*/__pycache__' --exclude=./.pytest_cache --exclude=./.ruff_cache -cf - . \
  | tar -C "$COPIA" -xf -
ln -s "$ORIGEN/.devtools" "$COPIA/.devtools"
[[ -d "$ORIGEN/node_modules" ]] && ln -s "$ORIGEN/node_modules" "$COPIA/node_modules"
cd "$COPIA"

export PYTHONPATH="$PWD/.devtools"
BIN=".devtools/bin"
PYTEST=("$BIN/pytest" -q -p no:cacheprovider)

TOTAL=0; PASARON=0; FALLARON=0; INESPERADOS=0

# caso  ESPERADO(pasa|falla)  descripcion  comando...
caso() {
  local esperado="$1" nombre="$2"; shift 2
  TOTAL=$((TOTAL + 1))
  printf '  %2d. %-58s' "$TOTAL" "$nombre"
  local salida resultado
  if salida=$("$@" 2>&1); then resultado="pasa"; else resultado="falla"; fi
  if [[ $resultado == "pasa" ]]; then PASARON=$((PASARON + 1)); else FALLARON=$((FALLARON + 1)); fi

  if [[ $resultado == "$esperado" && $resultado == "pasa" ]]; then
    printf '\033[32m✔ pasa\033[0m\n'
  elif [[ $resultado == "$esperado" ]]; then
    printf '\033[33m✘ falla\033[0m \033[2m(esperado: detectó el defecto)\033[0m\n'
  else
    INESPERADOS=$((INESPERADOS + 1))
    if [[ $resultado == "pasa" ]]; then
      printf '\033[31m✔ pasa — INESPERADO: la prueba no detectó el defecto\033[0m\n'
    else
      printf '\033[31m✘ falla — INESPERADO\033[0m\n'
      echo "$salida" | tail -15 | sed 's/^/        /'
    fi
  fi
}

# Reemplaza un fragmento exacto en un archivo de la copia. Si el fragmento no
# está (alguien cambió el código), lo dice y corta: un mutante que no se aplicó
# "pasaría" y daría una verificación falsa.
mutar() { # archivo  original  reemplazo
  python3 - "$1" "$2" "$3" <<'EOF' || exit 2
import sys
ruta, viejo, nuevo = sys.argv[1:4]
texto = open(ruta, encoding="utf-8").read()
if viejo not in texto:
    sys.exit(f"\n  No se pudo aplicar la mutación en {ruta}: el código cambió. "
             "Actualizá scripts/pruebas_de_verificacion.sh.")
open(ruta, "w", encoding="utf-8").write(texto.replace(viejo, nuevo, 1))
EOF
}

bandit_altos() { # cuenta hallazgos de severidad alta; falla si hay alguno
  local n
  n=$($BIN/bandit -r . -x './.devtools,./.venv,./node_modules,./tests,./elasticsearch' -f json -q 2>/dev/null \
    | python3 -c 'import json,sys; print(sum(r["issue_severity"]=="HIGH" for r in json.load(sys.stdin)["results"]))')
  echo "hallazgos de severidad alta: ${n:-?}"
  [[ "${n:-1}" == "0" ]]
}

pylint_producto() {
  mapfile -t CODIGO < <(find libs services -name '*.py' -not -path '*/__pycache__/*' | sort)
  $BIN/pylint --fail-under=9.0 \
    --init-hook="import sys, glob; sys.path[:0] = ['libs', *sorted(glob.glob('services/*'))]" "${CODIGO[@]}"
}

eslint_panel() {
  [[ -x node_modules/.bin/eslint ]] || { echo "falta npm install"; return 1; }
  node_modules/.bin/eslint --no-error-on-unmatched-pattern 'services/gateway/static/**/*.js'
}

U=tests/unit; I=tests/integration

printf '\n\033[1m▶ CASOS SANOS — el código tal como está: tienen que PASAR (80 %%)\033[0m\n'
caso pasa "Linter · ruff (estilo, imports, reglas S)"         $BIN/ruff check .
caso pasa "Linter · eslint (JS del panel, XSS, eval)"         eslint_panel
caso pasa "SAST · pylint + secure-coding-standard (≥ 9.0)"    pylint_producto
caso pasa "SAST · bandit (0 hallazgos de severidad alta)"     bandit_altos
caso pasa "AST · no-autonomía (nada ejecuta comandos)"        "${PYTEST[@]}" tests/test_no_autonomy.py
caso pasa "Unit · validadores e inyección de comandos (S-01)" "${PYTEST[@]}" $U/test_validators.py $U/test_s01_inyeccion_comandos.py
caso pasa "Unit · XSS en el panel (S-02)"                     "${PYTEST[@]}" $U/test_s02_xss_dashboard.py
caso pasa "Unit · Agente 1: clasificación y procedencia"      "${PYTEST[@]}" $U/test_classifier_caracterizacion.py \
     $U/test_procedencia_de_la_deteccion.py $U/test_l01_l02_identidad_y_conteo.py $U/test_rol_del_valor_agrupado.py \
     $U/test_alertas_por_regla.py $U/test_modo_de_solucion.py $U/test_resultado_simulado.py
caso pasa "Unit · Agente 2: severidad e interruptor del LLM"  "${PYTEST[@]}" $U/test_severidad_del_agente.py $U/test_interruptor_del_llm.py
caso pasa "Unit · reglas de detección como código"            "${PYTEST[@]}" $U/test_reglas_como_codigo.py $U/test_agregaciones_keyword.py
caso pasa "Unit · robustez del acceso a datos"                "${PYTEST[@]}" $U/test_b0x_robustez_y_formatos.py $U/test_siem_lib_caracterizacion.py
caso pasa "Unit · interfaz (contraste, tokens, iconos, UX)"   "${PYTEST[@]}" $U/test_contraste_de_la_interfaz.py \
     $U/test_tokens_de_diseno.py $U/test_iconos.py $U/test_estado_y_accion.py $U/test_resumen.py \
     $U/test_resuelto.py $U/test_historial_agrupado.py $U/test_motivo_de_descarte.py
caso pasa "Unit · usuarios: almacén, Argon2id y CLI"          "${PYTEST[@]}" $U/test_gestion_usuarios.py
caso pasa "Servicio · login, roles, CSRF, fuerza bruta"       "${PYTEST[@]}" $I/test_api01_autenticacion.py
caso pasa "Servicio · contrato de la API /api/v1"             "${PYTEST[@]}" $I/test_api_v1.py $I/test_api_caracterizacion.py
caso pasa "Servicio · malla de microservicios y pipeline auto" "${PYTEST[@]}" $I/test_microservicios.py \
     $I/test_pipeline_programado.py
caso pasa "Servicio · auditoría append-only e integridad"     "${PYTEST[@]}" $I/test_a02_a04_integridad.py \
     $I/test_auditoria_append_only.py $I/test_a01_reset_preserva_auditoria.py
caso pasa "Servicio · memoria del agente (Gem) y reportes"    "${PYTEST[@]}" $I/test_memoria_del_agente.py $I/test_reportes.py
caso pasa "Servicio · despliegue: reglas, compose y demos"    "${PYTEST[@]}" $I/test_despliegue_de_reglas.py \
     $I/test_scripts_de_demostracion.py $U/test_despliegue_compose.py
caso pasa "Pentest · ataques evasivos sin regresiones"        "${PYTEST[@]}" $I/test_pentest.py

printf '\n\033[1m▶ CASOS MUTANTES — defecto inyectado: tienen que FALLAR (20 %%)\033[0m\n'

# M1 · SAST: una shell con datos externos.
cat > services/collector/mutante.py <<'EOF'
import subprocess


def ejecutar(cmd):
    subprocess.run(cmd, shell=True)
EOF
caso falla "M1 · subprocess(shell=True) → bandit lo frena"   bandit_altos
rm services/collector/mutante.py

# M2 · Linter JS: XSS por innerHTML con un dato del incidente.
cat > services/gateway/static/mutante.js <<'EOF'
function pintar(evento) {
  document.getElementById("x").innerHTML = evento.mensaje;
}
pintar(window.dato);
EOF
caso falla "M2 · innerHTML con dato del log → eslint lo frena" eslint_panel
rm services/gateway/static/mutante.js

# M3 · No-autonomía: un servicio que ejecuta un comando del sistema.
mutar services/classifier/classifier_service.py "import os" 'import os
os.system("iptables -F")'
caso falla "M3 · os.system en un servicio → AST no-autonomía" "${PYTEST[@]}" tests/test_no_autonomy.py
cp "$ORIGEN/services/classifier/classifier_service.py" services/classifier/classifier_service.py

# M4 · Control de acceso: la ruta de decisión pierde su permiso.
mutar services/gateway/dashboard.py '@app.route("/api/v1/decision", methods=["POST"])
@requiere_permiso("decidir")' '@app.route("/api/v1/decision", methods=["POST"])
@login_required'
caso falla "M4 · un viewer puede decidir → pruebas de API-01"  "${PYTEST[@]}" $I/test_api01_autenticacion.py
cp "$ORIGEN/services/gateway/dashboard.py" services/gateway/dashboard.py

# M5 · Gem: el agente usa lecciones que ningún analista aprobó.
mutar services/knowledge/memoria.py 'if lec.get("estado") == "aprobada"' 'if lec.get("estado") != "rechazada"'
caso falla "M5 · lección sin aprobar se usa → pruebas de memoria" "${PYTEST[@]}" $I/test_memoria_del_agente.py
cp "$ORIGEN/services/knowledge/memoria.py" services/knowledge/memoria.py

# ─── Resumen ─────────────────────────────────────────────────────────────────
pct() { python3 -c "print(round(100 * $1 / $2))"; }
printf '\n\033[1m════════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1m  RESUMEN — VERIFICACIÓN DE LAS PRUEBAS\033[0m\n'
printf '\033[1m════════════════════════════════════════════════════════════\033[0m\n'
printf '  Casos corridos     : %d\n' "$TOTAL"
printf '  Pasaron            : %d  (%s %%)  — esperado: 20 sanos (80 %%)\n' "$PASARON" "$(pct "$PASARON" "$TOTAL")"
printf '  Fallaron           : %d  (%s %%)  — esperado: 5 mutantes (20 %%)\n' "$FALLARON" "$(pct "$FALLARON" "$TOTAL")"
printf '  Resultados inesperados: %d\n\n' "$INESPERADOS"
if (( INESPERADOS == 0 )); then
  echo "  ✅ Verificación correcta: el código sano pasa y cada defecto inyectado es detectado."
else
  echo "  ❌ $INESPERADOS caso(s) no dieron lo esperado — revisar arriba."
fi
exit $(( INESPERADOS > 0 ))
