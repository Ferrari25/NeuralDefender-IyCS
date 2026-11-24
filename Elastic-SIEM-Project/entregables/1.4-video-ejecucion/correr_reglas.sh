#!/bin/bash
# correr_reglas.sh - Corre, de punta a punta, todas las reglas del documento 1.1 para el video
# del entregable 1.4. En cada bloque explica QUE va a pasar, muestra DE DONDE SALEN LAS REGLAS
# (las lineas reales de los archivos de configuracion) y explica QUE SIGNIFICA el resultado.
#
#   Parte 1: el codigo del producto SUPERA las reglas (todo debe dar PASA).
#   Parte 2: las reglas DETECTAN violaciones (se corren sobre los ejemplos del entregable 1.3).
#
# Uso (desde cualquier carpeta):
#   ./entregables/1.4-video-ejecucion/correr_reglas.sh            # con pausas para narrar
#   PAUSA=0 ./entregables/1.4-video-ejecucion/correr_reglas.sh    # de corrido, sin pausas
#   EXPLICAR=0 ./entregables/1.4-video-ejecucion/correr_reglas.sh # sin los textos explicativos
#
# No modifica nada: solo lee el codigo y escribe en la terminal.
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"                  # Elastic-SIEM-Project
cd "$RAIZ" || exit 1
export PYTHONPATH="$RAIZ/.devtools${PYTHONPATH:+:$PYTHONPATH}"
BIN=".devtools/bin"
PAUSA="${PAUSA:-1}"
EXPLICAR="${EXPLICAR:-1}"
TIEMPOS="${TIEMPOS:-$AQUI/tiempos.log}"      # registro de la hora de cada evento (sirve para sincronizar subtitulos y audio)
marca() { printf '%s\t%s\t%s\n' "$(date +%H:%M:%S.%3N)" "$1" "${2:-}" >> "$TIEMPOS"; }
EJ="entregables/1.3-evidencia-reglas/prueba-de-reglas"
PYEJ="$EJ/python/ejemplo_violaciones_python.py.txt"
HOOK="import sys, glob; sys.path[:0] = ['libs', *sorted(glob.glob('services/*'))]"

N=$'\033[0m'; NEG=$'\033[1m'; VERDE=$'\033[32m'; ROJO=$'\033[31m'; AZUL=$'\033[36m'; GRIS=$'\033[90m'; AMARILLO=$'\033[33m'
NOMBRES=(); ESTADOS=(); FALLOS=0
B_QUE=""; B_NOTA=""; B_SIG=""; B_REGLAS=(); B_VIOL=(); B_PANELES=()   # datos del bloque que se va a mostrar

pausa() { [[ "$PAUSA" == "1" ]] && read -r -p "   [Enter para ${1:-continuar}] " _ ; echo; }
linea() { printf '%s\n' "------------------------------------------------------------------------"; }
titulo() { echo; linea; printf '%s%s%s\n' "$NEG$AZUL" "$1" "$N"; linea; }
texto() { printf '%s\n' "$1" | fold -s -w 92 | sed 's/^/    /'; }
# Muestra las lineas a-b de un archivo, numeradas. Formato: archivo:a-b
mostrar() {
  local f="${1%%:*}" r="${1##*:}"; local a="${r%-*}" b="${r#*-}"
  printf '    %s%s%s  (lineas %s a %s)\n' "$NEG" "$f" "$N" "$a" "$b"
  awk -v a="$a" -v b="$b" -v g="$GRIS" -v n="$N" 'NR>=a && NR<=b { printf "      %s%4d |%s %s\n", g, NR, n, $0 }' "$f"
}
registra() { NOMBRES+=("$1"); ESTADOS+=("$2"); }
limpia() { B_QUE=""; B_NOTA=""; B_SIG=""; B_REGLAS=(); B_VIOL=(); B_PANELES=(); }

# Cabecera de un bloque: titulo, regla del 1.1, config, comando, y las explicaciones.
presenta() { # nombre  regla  configuracion  comando-texto
  marca BLOQUE "$1"
  echo; printf '%s[%s]%s\n' "$NEG" "$1" "$N"
  printf '  Regla del documento 1.1 : %s\n' "$2"
  printf '  Configuración           : %s\n' "$3"
  printf '  Comando                 : %s%s%s\n\n' "$GRIS" "$4" "$N"
  [[ "$EXPLICAR" == "1" ]] || return 0
  if [[ -n "$B_QUE" ]]; then printf '  %sQUÉ VA A PASAR%s\n' "$NEG$AMARILLO" "$N"; texto "$B_QUE"; echo; fi
  if (( ${#B_VIOL[@]} )); then
    printf '  %sVIOLACIÓN INTENCIONAL (archivo de ejemplo)%s\n' "$NEG$AMARILLO" "$N"
    for s in "${B_VIOL[@]}"; do mostrar "$s"; done; echo
  fi
  if (( ${#B_PANELES[@]} )); then
    local panel titulo nota specs
    for panel in "${B_PANELES[@]}"; do          # formato: titulo|nota|spec1;spec2;...
      titulo="${panel%%|*}"; nota="${panel#*|}"; specs="${nota#*|}"; nota="${nota%%|*}"
      marca PANEL "$titulo"
      printf '  %sDE DÓNDE SALEN LAS REGLAS - %s%s\n' "$NEG$AMARILLO" "$titulo" "$N"
      local IFS=';'; for s in $specs; do mostrar "$s"; done; IFS=$' \t\n'
      texto "$nota"; echo
      pausa "ver la siguiente herramienta"
    done
  fi
  if (( ${#B_REGLAS[@]} )) || [[ -n "$B_NOTA" ]]; then
    printf '  %sDE DÓNDE SALEN LAS REGLAS%s\n' "$NEG$AMARILLO" "$N"
    for s in "${B_REGLAS[@]}"; do mostrar "$s"; done
    [[ -n "$B_NOTA" ]] && texto "$B_NOTA"
    echo
  fi
}
significa() { [[ "$EXPLICAR" == "1" && -n "$B_SIG" ]] && { printf '  %sQUÉ SIGNIFICA%s\n' "$NEG$AMARILLO" "$N"; texto "$B_SIG"; echo; }; }

# Parte 1: el comando debe terminar en 0.
supera() { # nombre  regla  config  texto-del-comando  --  comando...
  local nombre="$1" regla="$2" config="$3" texto="$4"; shift 5
  presenta "$nombre" "$regla" "$config" "$texto"; pausa "ejecutar"; marca EJECUTA "$nombre"
  "$@"; local rc=$?; echo
  marca SALIDA "$nombre"
  significa
  if (( rc == 0 )); then printf '  %s>>> PASA%s (código de salida 0)\n' "$VERDE$NEG" "$N"; registra "$nombre" "PASA"
  else printf '  %s>>> FALLA%s (código de salida %s)\n' "$ROJO$NEG" "$N" "$rc"; registra "$nombre" "FALLA"; FALLOS=$((FALLOS+1)); fi
  limpia; pausa
}

# Parte 2: el comando debe terminar distinto de 0 (la regla detecto la violacion).
detecta() { # nombre  regla  config  texto-del-comando  --  comando...
  local nombre="$1" regla="$2" config="$3" texto="$4"; shift 5
  presenta "$nombre" "$regla" "$config" "$texto"; pausa "ejecutar"; marca EJECUTA "$nombre"
  local tmp; tmp="$(mktemp)"
  "$@" > "$tmp" 2>&1; local rc=$?
  local total; total=$(wc -l < "$tmp")
  sed 's/\x1b\[[0-9;]*m//g' "$tmp" | head -n 14
  (( total > 14 )) && printf '  %s... (%s líneas de salida en total)%s\n' "$GRIS" "$total" "$N"
  rm -f "$tmp"; echo
  marca SALIDA "$nombre"
  significa
  if (( rc != 0 )); then printf '  %s>>> DETECTÓ la violación%s (código de salida %s)\n' "$VERDE$NEG" "$N" "$rc"; registra "$nombre" "DETECTO"
  else printf '  %s>>> NO DETECTÓ nada%s (código de salida 0)\n' "$ROJO$NEG" "$N"; registra "$nombre" "NO DETECTO"; FALLOS=$((FALLOS+1)); fi
  limpia; pausa
}

# ---------------------------------------------------------------- comprobaciones previas
faltan=()
for h in ruff pylint bandit shellcheck yamllint pytest; do [[ -x "$BIN/$h" ]] || faltan+=("$BIN/$h"); done
[[ -x node_modules/.bin/eslint ]] || faltan+=("node_modules/.bin/eslint")
command -v docker >/dev/null 2>&1 || faltan+=("docker")
docker image inspect hadolint/hadolint:v2.15.1 >/dev/null 2>&1 || faltan+=("imagen docker hadolint/hadolint:v2.15.1")
if (( ${#faltan[@]} )); then
  echo "${ROJO}Faltan herramientas:${N} ${faltan[*]}"
  echo "Instalación (una sola vez):"
  echo "  python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt yamllint shellcheck-py"
  echo "  npm install      y      docker pull hadolint/hadolint:v2.15.1"
  exit 2
fi
if [[ -e libs/zz_demo_violaciones.py || -e services/gateway/static/zz_demo_violaciones.js ]]; then
  echo "${ROJO}Hay archivos de demo del IDE sin limpiar.${N} Ejecutá primero: ./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh"
  exit 2
fi

# ---------------------------------------------------------------- portada
clear 2>/dev/null
marca INICIO_SCRIPT "$(date +%F)"
titulo "NeuralDefender - Evaluación estática de código (documento 1.1)"
echo "  Fecha     : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Carpeta   : $RAIZ"
echo "  Rama git  : $(git rev-parse --abbrev-ref HEAD 2>/dev/null) ($(git rev-parse --short HEAD 2>/dev/null))"
echo
echo "  Versiones de las herramientas:"
printf '    %-12s %s\n' "ruff"      "$($BIN/ruff --version)"
printf '    %-12s %s\n' "pylint"    "$($BIN/pylint --version | head -1) + $(python3 -c 'import importlib.metadata as i;print("secure-coding-standard", i.version("pylint-secure-coding-standard"))')"
printf '    %-12s %s\n' "bandit"    "$($BIN/bandit --version 2>&1 | head -1)"
printf '    %-12s %s\n' "eslint"    "$(node_modules/.bin/eslint --version)"
printf '    %-12s %s\n' "shellcheck" "$($BIN/shellcheck --version | grep '^version')"
printf '    %-12s %s\n' "hadolint"  "$(docker run --rm hadolint/hadolint:v2.15.1 hadolint --version)"
printf '    %-12s %s\n' "yamllint"  "$($BIN/yamllint --version)"
printf '    %-12s %s\n' "pytest"    "$($BIN/pytest --version 2>&1 | head -1)"
if [[ "$EXPLICAR" == "1" ]]; then
  echo
  printf '  %sCÓMO LEER ESTA CORRIDA%s\n' "$NEG$AMARILLO" "$N"
  texto "Cada bloque muestra cuatro cosas: (1) qué va a pasar, (2) de dónde salen las reglas, es decir las líneas reales de los archivos de configuración del proyecto, (3) la salida de la herramienta, y (4) qué significa el resultado. Las herramientas no traen reglas escondidas: todo lo que aplican sale de esos archivos o del catálogo oficial de cada herramienta, y en cada caso se indica cuál."
fi
pausa

# ================================================================ PARTE 1
titulo "PARTE 1 - El código del producto SUPERA las reglas"
if [[ "$EXPLICAR" == "1" ]]; then texto "Aquí se analiza el código real del producto. Lo esperado es que cada bloque termine en PASA: ningún hallazgo nuevo."; fi
pausa

B_QUE="El script del proyecto encadena cuatro herramientas sobre el código real: ruff (estilo, seguridad y complejidad de Python), eslint (JavaScript del panel, incluido XSS), pylint con el plugin de seguridad (Python) y bandit (seguridad de Python). Ninguna regla está escrita en el script: cada herramienta lee su propio archivo de configuración, que se muestra abajo."
B_PANELES=(
 "ruff (archivo ruff.toml)|Línea 10: las familias de reglas activas. La S es la de seguridad (contraseñas en el código, eval, exec, pickle, shell=True) y C901 la de complejidad. Línea 15: la complejidad máxima permitida es 10. Línea 29: las únicas excepciones, y solo para la carpeta tests/.|ruff.toml:9-15;ruff.toml:29-29"
 "pylint (archivo .pylintrc)|Línea 8: carga el plugin de seguridad, que aporta reglas contra os.system, os.popen, pickle, marshal y shelve. Líneas 16 a 18: permisos máximos de archivos, directorios y fifos. Línea 30: largo de línea 100. Líneas 35 a 38: límites de variables locales, ramas, sentencias y argumentos por función.|.pylintrc:7-8;.pylintrc:16-18;.pylintrc:30-30;.pylintrc:35-38"
 "eslint (archivo eslint.config.js)|Líneas 66 y 67: las reglas contra XSS (no asignar a innerHTML un dato sin sanear). Líneas 70 a 75: ejecución de código (eval, new Function, child_process). Líneas 78 a 80: expresiones regulares peligrosas. Las de nivel error bloquean; las de nivel warn se revisan.|eslint.config.js:66-67;eslint.config.js:70-75;eslint.config.js:78-80;eslint.config.js:83-84"
 "bandit (archivo .bandit)|El archivo .bandit no lista pruebas: bandit ejecuta TODAS las que trae incorporadas (B101 assert, B113 requests sin timeout, B301 pickle, B324 hash débil, B602 shell=True, B608 SQL concatenado, entre otras). Las carpetas excluidas están en el script de la compuerta, línea 22, porque la opción exclude_dirs de .bandit no se aplica en modo recursivo.|.bandit:11-12;scripts/pruebas_de_codigo_estatico.sh:22-22"
 "Criterios de aprobación (script de la compuerta)|Línea 59: BASE_RUFF=5 son los 5 hallazgos de complejidad ya declarados: la compuerta falla ante cualquier hallazgo nuevo. Línea 108: pylint exige un puntaje mínimo de 9,0 sobre 10.|scripts/pruebas_de_codigo_estatico.sh:59-60;scripts/pruebas_de_codigo_estatico.sh:108-110"
)
B_SIG="PASA significa que las cuatro herramientas terminaron sin hallazgos nuevos. 'OK' es cero hallazgos. 'BASE 5' en ruff son los 5 hallazgos de complejidad conocidos y declarados en la línea 59: no hay regresiones, o sea nada nuevo respecto de la línea de base. 'BASE 0' en bandit es cero hallazgos de severidad alta."
supera "1. Compuerta oficial del proyecto" \
  "ruff (calidad + seguridad S + complejidad C901), eslint (JS + seguridad), pylint + secure-coding-standard, bandit" \
  "ruff.toml, eslint.config.js, .pylintrc, .bandit y los límites de scripts/pruebas_de_codigo_estatico.sh" \
  "./scripts/pruebas_de_codigo_estatico.sh" -- ./scripts/pruebas_de_codigo_estatico.sh

B_QUE="Se pide a ruff que liste los hallazgos de complejidad ciclomática (regla C901) que la compuerta del paso anterior tolera como línea de base."
B_REGLAS=("ruff.toml:13-15" "scripts/pruebas_de_codigo_estatico.sh:59-59")
B_NOTA="La regla C901 se activa en la línea 10 de ruff.toml y su límite (10) está en la línea 15."
B_SIG="Cada línea es una función cuya complejidad supera el límite de 10: por ejemplo detect_auth_incidents tiene 25. Son deuda técnica DECLARADA, no ocultada: la compuerta tolera exactamente estos 5 y falla ante cualquier otro nuevo. Este bloque es informativo: no cuenta como PASA ni FALLA."
presenta "1b. (informativo) Los 5 C901 conocidos de ruff" "C901 complejidad ciclomática mayor a 10" "ruff.toml líneas 10 y 15; línea de base BASE_RUFF=5 en scripts/pruebas_de_codigo_estatico.sh:59" "$BIN/ruff check . --output-format=concise"
pausa "ejecutar"; marca EJECUTA "1b"; "$BIN/ruff" check . --output-format=concise; echo; marca SALIDA "1b"; significa; limpia; pausa

mapfile -t SH < <(find scripts simulation backup -name '*.sh' | sort)
B_QUE="shellcheck lee los ${#SH[@]} scripts de bash sin ejecutarlos y busca errores típicos: variables sin comillas (SC2086), globs peligrosos (SC2035) y cd sin control de error (SC2164)."
B_REGLAS=(".shellcheckrc:1-5")
B_NOTA="Las reglas SC2086, SC2035 y SC2164 no están escritas en ningún archivo del proyecto: vienen incluidas en shellcheck y están activas por defecto. El archivo .shellcheckrc solo fija el dialecto (línea 4: shell=bash). Catálogo oficial: https://www.shellcheck.net/wiki/SC2086"
B_SIG="Que no aparezca ninguna línea de salida y el código sea 0 significa que ninguno de los ${#SH[@]} scripts tiene esos problemas."
supera "2. shellcheck (${#SH[@]} scripts)" \
  "SC2086 variables sin comillas, SC2035 globbing, SC2164 cd sin control" "'.shellcheckrc' (shell=bash)" \
  "$BIN/shellcheck scripts/*.sh simulation/*.sh backup/*.sh" -- "$BIN/shellcheck" "${SH[@]}"

sintaxis() { local n=0; for f in "${SH[@]}"; do bash -n "$f" || n=$((n+1)); done; echo "scripts con error de sintaxis: $n de ${#SH[@]}"; return $n; }
B_QUE="bash lee cada script y comprueba que su sintaxis sea válida, sin ejecutarlo. Detecta, por ejemplo, un if sin su fi."
B_NOTA="Acá no hay archivo de reglas: la regla es la gramática del propio lenguaje bash."
B_SIG="'0 de ${#SH[@]}' significa que ningún script tiene un error de sintaxis."
supera "3. bash -n (sintaxis de los ${#SH[@]} scripts)" "bash -n: detecta errores de sintaxis sin ejecutar" "(comando de bash, sin archivo)" \
  "for f in scripts/*.sh simulation/*.sh backup/*.sh; do bash -n \$f; done" -- sintaxis

B_QUE="hadolint lee los 9 Dockerfile (8 microservicios y el de respaldo) y busca malas prácticas: imagen base sin versión, contenedor corriendo como root, ADD en lugar de COPY, pip sin --no-cache-dir."
B_REGLAS=(".hadolint.yaml:1-4")
B_NOTA="Las reglas DL3006, DL3007, DL3002, DL3020 y DL3042 vienen incluidas en hadolint y están activas por defecto. El archivo solo fija el umbral (línea 4: fallar desde el nivel warning). Catálogo oficial: https://github.com/hadolint/hadolint:v2.15.1/wiki/DL3006"
B_SIG="Sin ninguna línea de salida y código 0 significa que ningún Dockerfile infringe esas reglas: las imágenes tienen versión fija y corren con usuario sin privilegios."
supera "4. hadolint (9 Dockerfile)" \
  "DL3006/DL3007 imagen con versión, DL3002 sin root, DL3020 COPY en vez de ADD, DL3042 pip --no-cache-dir" ".hadolint.yaml" \
  "docker run --rm -v \$PWD:/w -w /w hadolint/hadolint:v2.15.1 hadolint services/*/Dockerfile backup/Dockerfile" -- \
  docker run --rm -v "$RAIZ:/w" -w /w hadolint/hadolint:v2.15.1 hadolint services/*/Dockerfile backup/Dockerfile

YML=(docker-compose.yml elasticsearch/elasticsearch.yml kibana/kibana.yml filebeat/filebeat.yml logstash/config/logstash.yml)
B_QUE="yamllint lee los 5 archivos de configuración YAML (compose, Elasticsearch, Kibana, Filebeat y Logstash) y comprueba sintaxis, sangría y claves repetidas."
B_REGLAS=(".yamllint:1-11")
B_NOTA="La línea 2 (extends: default) significa 'usar el conjunto estándar de reglas de yamllint', que incluye syntax, indentation y key-duplicates. Las líneas 5 a 10 solo relajan tres reglas que no aplican a estos archivos."
B_SIG="Sin salida y código 0 significa que los 5 YAML están bien formados, con sangría consistente y sin claves repetidas."
supera "5. yamllint (5 archivos YAML)" "syntax, indentation, key-duplicates" ".yamllint" \
  "$BIN/yamllint ${YML[*]}" -- "$BIN/yamllint" "${YML[@]}"

B_QUE="Docker Compose lee docker-compose.yml, lo valida contra su esquema y comprueba que el proyecto sea desplegable. La opción -q hace que no imprima nada si todo está bien."
B_NOTA="Acá la regla es el esquema de Docker Compose, no un archivo del proyecto."
B_SIG="Sin salida y código 0 significa que la configuración de despliegue es válida."
supera "6. docker compose config -q" "Validez del compose: el despliegue no falla por configuración" "(comando de Docker Compose)" \
  "docker compose config -q" -- docker compose config -q

PROPIAS=(tests/test_no_autonomy.py tests/unit/test_s01_inyeccion_comandos.py tests/unit/test_validators.py tests/unit/test_s02_xss_dashboard.py tests/unit/test_reglas_como_codigo.py tests/unit/test_despliegue_compose.py tests/unit/test_agregaciones_keyword.py tests/unit/test_tokens_de_diseno.py tests/unit/test_contraste_de_la_interfaz.py)
B_QUE="Son reglas propias de NeuralDefender que ninguna herramienta genérica puede comprobar. Cada archivo de prueba lee el código fuente (sin ejecutar el sistema) y falla si se viola una propiedad del sistema: por ejemplo, recorre el árbol sintáctico de los 35 archivos Python y falla si aparece subprocess, shell o una conexión remota."
B_REGLAS=("tests/test_no_autonomy.py:76-76" "tests/test_no_autonomy.py:134-136" "pytest.ini:1-3")
B_NOTA="En este caso las reglas no están en un archivo de configuración: SON las pruebas. test_no_autonomy.py línea 135 es la regla 'ningún componente ejecuta procesos'; la línea 76 define qué carpetas no se analizan. pytest.ini indica dónde están las pruebas. Los otros 8 archivos cubren la lista blanca de IP y usuario, el XSS del panel, las reglas de detección sin acciones automáticas, los límites del compose, las consultas con .keyword, los tokens de diseño CSS y el contraste WCAG."
B_SIG="'577 passed' son las comprobaciones que se cumplieron y 0 fallaron. Las 5 'SKIPPED' son reglas de detección que no documentan un umbral numérico: se omiten a propósito. El cartel 'Certificación de no-autonomía' resume el resultado: 35 archivos analizados, sin subprocess, sin rutas HTTP que ejecuten nada."
supera "7. Reglas propias del sistema (9 archivos de prueba)" \
  "No-autonomía (AST), lista blanca de IP/usuario, XSS, reglas de detección sin acciones, compose, .keyword, tokens CSS, contraste WCAG" \
  "tests/ (pytest.ini)" "$BIN/pytest -q ${PROPIAS[*]##*/}" -- "$BIN/pytest" -q -p no:cacheprovider --no-header "${PROPIAS[@]}"

# ================================================================ PARTE 2
titulo "PARTE 2 - Las reglas DETECTAN violaciones (prueba de que se ejecutan)"
if [[ "$EXPLICAR" == "1" ]]; then
  texto "Que un análisis dé cero hallazgos podría significar que la herramienta no hace nada. Para descartarlo, ahora se les pasa código con violaciones intencionales (los ejemplos del entregable 1.3) y se espera lo contrario: que cada herramienta ENCUENTRE el problema. Para cada bloque se muestra la violación, la regla y el hallazgo."
  texto "Los ejemplos de Python y JavaScript se leen por entrada estándar: no se crea ningún archivo dentro del producto."
fi
pausa

B_QUE="Se le pasa a ruff el archivo de ejemplo con violaciones de seguridad y de calidad. La opción --stdin-filename libs/demo.py le dice que lo trate como si fuera código del producto, para que aplique las reglas del producto y no las excepciones de tests/."
B_VIOL=("$PYEJ:17-29")
B_REGLAS=("ruff.toml:10-10")
B_NOTA="Las reglas que detectan esto son las familias de la línea 10 de ruff.toml: S (seguridad: contraseña en el código, eval, exec, pickle, shell=True), B, F, UP, SIM, C4 y C901. Cada hallazgo muestra su código, por ejemplo S105 (contraseña) o S102 (exec)."
B_SIG="Cada línea de salida tiene archivo, línea, código de la regla y qué encontró, por ejemplo 'S105 Possible hardcoded password' en la línea 17. El código de salida 1 significa que ruff encontró problemas, que es lo esperado."
detecta "8. ruff sobre el ejemplo de Python" "Familia S (seguridad), C901, B, F, UP, SIM..." "ruff.toml" \
  "ruff check --stdin-filename libs/demo.py - < ejemplo_violaciones_python.py.txt" -- \
  bash -c "$BIN/ruff check --output-format=concise --stdin-filename libs/demo.py - < $PYEJ"

B_QUE="Se le pasa a pylint el mismo archivo de ejemplo. pylint carga un plugin de seguridad y se muestran solo los mensajes de seguridad (E80xx, W80xx, C80xx y W1510)."
B_VIOL=("$PYEJ:21-29")
B_REGLAS=(".pylintrc:7-8" ".pylintrc:14-18")
B_NOTA="El plugin se carga en la línea 8 de .pylintrc (load-plugins). Las reglas de os.system, os.popen, pickle, marshal y shelve vienen incluidas en el plugin y están siempre activas. Las líneas 16 a 18 configuran los permisos máximos de archivos, directorios y fifos."
B_SIG="E8002 es 'no usar os.system', E8013 'no usar pickle', E8001 'no usar eval/exec', y así cada código. Los números a la izquierda son las líneas del ejemplo que se mostraron arriba (21 a 29). El código de salida 1 significa que pylint encontró problemas."
detecta "9. pylint + secure-coding-standard sobre el ejemplo" "os.system, os.popen, pickle, marshal, shelve, shell=True, permisos de archivos" ".pylintrc" \
  "pylint --from-stdin libs/demo.py < ejemplo_violaciones_python.py.txt" -- \
  bash -c "$BIN/pylint --init-hook=\"$HOOK\" --from-stdin libs/demo.py < $PYEJ | grep -E 'E80|W80|C80|W1510'; [ \${PIPESTATUS[1]} -ne 0 ]"

B_QUE="Se le pasa a bandit el mismo archivo de ejemplo y se listan sus hallazgos de seguridad."
B_VIOL=("$PYEJ:21-37")
B_REGLAS=(".bandit:11-12")
B_NOTA="El archivo .bandit no define una lista de pruebas, así que bandit ejecuta todas las que trae (la lista completa está en entregables/1.3-evidencia-reglas/configuracion-efectiva/bandit--pruebas-activas.txt). Cada hallazgo tiene un código B: B101 assert, B113 requests sin timeout, B301 pickle, B324 hash débil, B602 shell=True, B608 SQL concatenado."
B_SIG="Cada línea es un hallazgo con su código B y su descripción. Se ven, entre otros, B605 (proceso con shell), B602 (shell=True), B307 (eval), B102 (exec) y B301 (pickle). El código de salida 1 significa que bandit encontró problemas."
detecta "10. bandit sobre el ejemplo" "B101, B113, B301, B324, B404, B602, B603, B605, B506, B608, B108" ".bandit (todas las pruebas activas)" \
  "bandit -f txt - < ejemplo_violaciones_python.py.txt" -- \
  bash -c "$BIN/bandit -f txt - < $PYEJ 2>&1 | grep -E '^>> Issue'; [ \${PIPESTATUS[1]} -ne 0 ]"

B_QUE="Se le pasa a eslint un archivo JavaScript con violaciones de seguridad. La opción --stdin-filename le dice que lo trate como si estuviera en services/gateway/static/ (el JavaScript del panel), para que aplique las mismas reglas que a app.js."
B_VIOL=("$EJ/javascript/ejemplo_violaciones_js.js:9-20")
B_REGLAS=("eslint.config.js:66-67" "eslint.config.js:70-75" "eslint.config.js:78-80")
B_NOTA="Las líneas 66 y 67 son las reglas contra XSS: no-unsanitized prohíbe asignar a innerHTML un dato no controlado. Las líneas 70 a 75 son las de ejecución de código (eval, new Function, child_process) y las 78 a 80 las de expresiones regulares peligrosas."
B_SIG="El hallazgo de la línea 9 'Unsafe assignment to innerHTML' es exactamente el vector de XSS que preocupa en el panel. Los 'error' bloquean y los 'warning' se revisan. El código de salida 1 significa que hay al menos un error."
detecta "11. eslint sobre el ejemplo de JavaScript" "no-unsanitized (XSS), no-eval, no-new-func, security/*" "eslint.config.js" \
  "eslint --stdin --stdin-filename services/gateway/static/demo.js < ejemplo_violaciones_js.js" -- \
  bash -c "node_modules/.bin/eslint --stdin --stdin-filename services/gateway/static/demo.js -f stylish < $EJ/javascript/ejemplo_violaciones_js.js"

B_QUE="Se le pasa a shellcheck un script con tres problemas típicos: variable sin comillas, glob peligroso y cd sin control de error."
B_VIOL=("$EJ/shell/ejemplo_violaciones_shell.sh:4-10")
B_REGLAS=(".shellcheckrc:1-5")
B_NOTA="Las reglas SC2086, SC2035 y SC2164 vienen incluidas en shellcheck. El archivo .shellcheckrc solo fija el dialecto bash."
B_SIG="SC2086 (línea 5) es la variable sin comillas, SC2164 (línea 6) el cd sin control y SC2035 (línea 7) el glob. shellcheck no ejecutó nada: solo leyó el archivo."
detecta "12. shellcheck sobre el ejemplo de shell" "SC2086, SC2035, SC2164" ".shellcheckrc" \
  "shellcheck -f gcc ejemplo_violaciones_shell.sh" -- "$BIN/shellcheck" -f gcc "$EJ/shell/ejemplo_violaciones_shell.sh"

B_QUE="bash -n lee un script que tiene un if sin su fi y comprueba su sintaxis."
B_VIOL=("$EJ/shell/ejemplo_sintaxis_invalida.sh:1-5")
B_NOTA="La regla es la gramática de bash: no hay archivo de configuración."
B_SIG="'unexpected end of file' significa que bash llegó al final del archivo y le faltaba cerrar el if. Un script así fallaría al ejecutarse, y se detectó sin ejecutarlo."
detecta "13. bash -n sobre un script con sintaxis inválida" "Sintaxis" "(comando de bash)" \
  "bash -n ejemplo_sintaxis_invalida.sh" -- bash -n "$EJ/shell/ejemplo_sintaxis_invalida.sh"

B_QUE="Se le pasa a hadolint un Dockerfile con cinco malas prácticas: imagen sin versión, etiqueta latest, ADD en lugar de COPY, pip sin --no-cache-dir y usuario root."
B_VIOL=("$EJ/dockerfile/Dockerfile.violaciones:2-6")
B_REGLAS=(".hadolint.yaml:1-4")
B_NOTA="Las reglas DL3006, DL3007, DL3020, DL3042 y DL3002 vienen incluidas en hadolint. El archivo fija el umbral de falla (línea 4)."
B_SIG="DL3006 es 'imagen sin etiqueta' (línea 2), DL3007 'etiqueta latest' (línea 3), DL3020 'ADD en lugar de COPY' (línea 4), DL3042 'pip sin --no-cache-dir' (línea 5) y DL3002 'último USER es root' (línea 6)."
detecta "14. hadolint sobre un Dockerfile con violaciones" "DL3006, DL3007, DL3002, DL3020, DL3042" ".hadolint.yaml" \
  "hadolint Dockerfile.violaciones" -- docker run --rm -v "$RAIZ:/w" -w /w hadolint/hadolint:v2.15.1 hadolint "$EJ/dockerfile/Dockerfile.violaciones"

B_QUE="Se le pasa a yamllint un YAML con una clave repetida, una sangría inconsistente y espacios de más dentro de llaves."
B_VIOL=("$EJ/yaml/ejemplo_violaciones.yml:2-10")
B_REGLAS=(".yamllint:1-3")
B_NOTA="La línea 2 (extends: default) incluye las reglas key-duplicates, indentation y braces, entre otras."
B_SIG="key-duplicates (línea 4) indica que la clave 'puerto' aparece dos veces: YAML se quedaría con la última sin avisar. indentation (línea 9) indica que se esperaban 2 espacios y hay 4."
detecta "15. yamllint sobre un YAML con violaciones" "key-duplicates, indentation, braces" ".yamllint" \
  "yamllint -f parsable ejemplo_violaciones.yml" -- "$BIN/yamllint" -f parsable "$EJ/yaml/ejemplo_violaciones.yml"

B_QUE="Se le pasa a Docker Compose un archivo en el que un servicio no tiene ni image ni build."
B_VIOL=("$EJ/yaml/ejemplo_compose_invalido.yml:2-4")
B_NOTA="La regla es el esquema de Docker Compose."
B_SIG="Docker informa que el servicio 'web' no sabe de dónde sacar su imagen y rechaza el proyecto: un despliegue con este archivo habría fallado."
detecta "16. docker compose config sobre un compose inválido" "Validez del compose" "(comando de Docker Compose)" \
  "docker compose -f ejemplo_compose_invalido.yml config -q" -- docker compose -f "$EJ/yaml/ejemplo_compose_invalido.yml" config -q

# ================================================================ RESUMEN
marca RESUMEN
titulo "RESUMEN"
printf '  %-62s %s\n' "Bloque" "Resultado"; printf '  %-62s %s\n' "------" "---------"
for i in "${!NOMBRES[@]}"; do
  e="${ESTADOS[$i]}"; c="$VERDE"; [[ "$e" == "FALLA" || "$e" == "NO DETECTO" ]] && c="$ROJO"
  printf '  %-62s %s%s%s\n' "${NOMBRES[$i]}" "$c$NEG" "$e" "$N"
done
echo
if (( FALLOS == 0 )); then printf '  %sTodo en orden:%s el código supera las reglas y las reglas detectan las violaciones.\n' "$VERDE$NEG" "$N"
else printf '  %s%s bloque(s) con problemas.%s Revisar arriba.\n' "$ROJO$NEG" "$FALLOS" "$N"; fi

if [[ "$EXPLICAR" == "1" ]]; then
  echo; printf '  %sMAPA: DE DÓNDE SALE CADA REGLA%s\n' "$NEG$AMARILLO" "$N"
  printf '    %-11s %-24s %s\n' "Herramienta" "Archivo de reglas" "Qué hay ahí"
  printf '    %-11s %-24s %s\n' "-----------" "-----------------" "-----------"
  printf '    %-11s %-24s %s\n' "ruff"       "ruff.toml"        "familias activas (línea 10), complejidad máxima (15), excepciones de tests (29)"
  printf '    %-11s %-24s %s\n' "pylint"     ".pylintrc"        "plugin de seguridad (8), permisos (16-18), límites de tamaño (35-38)"
  printf '    %-11s %-24s %s\n' "bandit"     ".bandit"          "sin lista de pruebas: aplica todas las de bandit"
  printf '    %-11s %-24s %s\n' "eslint"     "eslint.config.js" "reglas de seguridad y XSS (66-80), calidad (83-84)"
  printf '    %-11s %-24s %s\n' "shellcheck" ".shellcheckrc"    "dialecto bash; las reglas SC vienen con la herramienta"
  printf '    %-11s %-24s %s\n' "hadolint"   ".hadolint.yaml"   "umbral de falla; las reglas DL vienen con la herramienta"
  printf '    %-11s %-24s %s\n' "yamllint"   ".yamllint"        "conjunto estándar (extends: default) con 3 ajustes"
  printf '    %-11s %-24s %s\n' "propias"    "tests/*.py"       "cada archivo de prueba ES una regla del sistema"
  printf '    %-11s %-24s %s\n' "compuerta"  "scripts/pruebas_de_codigo_estatico.sh" "puntaje mínimo (108), carpetas excluidas (22), línea de base (59)"
fi
marca FIN_SCRIPT "fallos=$FALLOS"
exit $(( FALLOS > 0 ))
