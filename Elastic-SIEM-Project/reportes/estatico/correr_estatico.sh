#!/bin/bash
# Corre cada herramienta del plan por separado y guarda la salida cruda.
# Uso: correr_estatico.sh <carpeta_de_salida>   (desde la raíz de Elastic-SIEM-Project)
set -u
OUT="$1"; mkdir -p "$OUT"
export PYTHONPATH="$PWD/.devtools"
V="$PWD/.devtools/bin"
EXCL='./.devtools,./.venv,./node_modules,./tests,./elasticsearch,./reportes'
: > "$OUT/codigos-de-salida.txt"
reg() { echo "$1 $2" >> "$OUT/codigos-de-salida.txt"; }

# 1. ruff (todo el proyecto, incluye tests/) — calidad + seguridad (S) + complejidad (C901)
$V/ruff check . --output-format=concise > "$OUT/ruff.txt" 2>&1;   reg ruff $?
$V/ruff check . --output-format=json   > "$OUT/ruff.json" 2>/dev/null

# 2. pylint (+ pylint-secure-coding-standard) sobre libs/ y services/
mapfile -t COD < <(find libs services -name '*.py' -not -path '*/__pycache__/*' | sort)
HOOK="import sys, glob; sys.path[:0] = ['libs', *sorted(glob.glob('services/*'))]"
$V/pylint --fail-under=9.0 --init-hook="$HOOK" "${COD[@]}" > "$OUT/pylint.txt" 2>&1; reg pylint $?
$V/pylint --init-hook="$HOOK" --output-format=json "${COD[@]}" > "$OUT/pylint.json" 2>/dev/null

# 3. bandit
$V/bandit -r . -x "$EXCL" -f txt  -q > "$OUT/bandit.txt"  2>&1;  reg bandit $?
$V/bandit -r . -x "$EXCL" -f json -q > "$OUT/bandit.json" 2>/dev/null

# 4. eslint (JavaScript del panel)
node_modules/.bin/eslint 'services/gateway/static/**/*.js' -f stylish > "$OUT/eslint.txt" 2>&1; reg eslint $?
node_modules/.bin/eslint 'services/gateway/static/**/*.js' -f json > "$OUT/eslint.json" 2>/dev/null

# 5. shellcheck y bash -n
mapfile -t SH < <(find scripts simulation backup -name '*.sh' | sort)
$V/shellcheck -f gcc  "${SH[@]}" > "$OUT/shellcheck.txt"  2>&1; reg shellcheck $?
$V/shellcheck -f json "${SH[@]}" > "$OUT/shellcheck.json" 2>/dev/null
: > "$OUT/bash-n.txt"; n=0
for f in "${SH[@]}"; do bash -n "$f" >> "$OUT/bash-n.txt" 2>&1 || n=$((n+1)); done
echo "scripts con error de sintaxis: $n de ${#SH[@]}" >> "$OUT/bash-n.txt"; reg bash-n $n

# 6. hadolint (en contenedor)
docker run --rm -v "$PWD:/w" -w /w hadolint/hadolint:v2.15.1 hadolint services/*/Dockerfile backup/Dockerfile > "$OUT/hadolint.txt" 2>&1; reg hadolint $?
docker run --rm -v "$PWD:/w" -w /w hadolint/hadolint:v2.15.1 hadolint -f json services/*/Dockerfile backup/Dockerfile > "$OUT/hadolint.json" 2>/dev/null

# 7. yamllint y docker compose config
YML=(docker-compose.yml elasticsearch/elasticsearch.yml kibana/kibana.yml filebeat/filebeat.yml logstash/config/logstash.yml)
$V/yamllint -f parsable "${YML[@]}" > "$OUT/yamllint.txt" 2>&1; reg yamllint $?
docker compose config -q > "$OUT/compose-config.txt" 2>&1; reg compose-config $?

# 8. Reglas propias (sección 6 del documento)
$V/pytest -q -p no:cacheprovider --no-header \
  tests/test_no_autonomy.py tests/unit/test_s01_inyeccion_comandos.py tests/unit/test_validators.py \
  tests/unit/test_s02_xss_dashboard.py tests/unit/test_reglas_como_codigo.py \
  tests/unit/test_despliegue_compose.py tests/unit/test_agregaciones_keyword.py \
  tests/unit/test_tokens_de_diseno.py tests/unit/test_contraste_de_la_interfaz.py \
  > "$OUT/reglas-propias.txt" 2>&1; reg reglas-propias $?
cat "$OUT/codigos-de-salida.txt"
