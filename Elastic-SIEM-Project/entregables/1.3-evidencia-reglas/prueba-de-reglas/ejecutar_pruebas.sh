#!/bin/bash
# Corre cada herramienta sobre su archivo de ejemplo con violaciones intencionales y guarda
# la salida cruda (con el codigo de salida) en <lenguaje>/salidas/.
#
# Uso (desde cualquier carpeta):
#   VENV=/ruta/al/venv/bin ./ejecutar_pruebas.sh
#
# VENV es la carpeta bin del entorno donde estan ruff, pylint, bandit, shellcheck y yamllint.
# eslint se toma de node_modules/ del proyecto y hadolint de la imagen Docker hadolint/hadolint.
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../../.." && pwd)"          # Elastic-SIEM-Project
VENV="${VENV:?definir VENV con la carpeta bin del entorno de herramientas}"
cd "$RAIZ" || exit 1
REL="entregables/1.3-evidencia-reglas/prueba-de-reglas"
mkdir -p "$REL"/{python,javascript,shell,dockerfile,yaml}/salidas

# Ejecuta un comando, guarda comando, salida y codigo de salida en un archivo.
corre() { # archivo_de_salida  comando...
  local salida="$1"; shift
  { echo "# Comando: $*"; "$@" 2>&1; echo "# Codigo de salida: $?"; } | sed 's/\x1b\[[0-9;]*m//g' > "$salida"
}

# --- Python ----------------------------------------------------------------
# El ejemplo se guarda como .py.txt para que ni ruff, ni bandit, ni test_no_autonomy lo recorran.
# Se crea una copia .py temporal solo mientras corren las herramientas.
PY="$REL/python/ejemplo_violaciones_python.py"
cp "$PY.txt" "$PY"; trap 'rm -f "$PY"' EXIT
HOOK="import sys, glob; sys.path[:0] = ['libs', *sorted(glob.glob('services/*'))]"
corre "$REL/python/salidas/ruff.txt"    "$VENV/ruff" check --output-format=concise "$PY"
corre "$REL/python/salidas/pylint.txt"  "$VENV/pylint" --fail-under=9.0 --init-hook="$HOOK" "$PY"
corre "$REL/python/salidas/bandit.txt"  "$VENV/bandit" -f txt "$PY"
rm -f "$PY"

# --- JavaScript ------------------------------------------------------------
# --stdin-filename hace que eslint aplique la configuracion de services/gateway/static/**
# como si el archivo estuviera ahi, sin copiarlo dentro del producto.
corre "$REL/javascript/salidas/eslint.txt" bash -c \
  "node_modules/.bin/eslint --stdin --stdin-filename services/gateway/static/ejemplo_violaciones_js.js -f stylish < '$REL/javascript/ejemplo_violaciones_js.js'"

corre "$REL/javascript/salidas/eslint-solo-advertencias.txt" bash -c \
  "node_modules/.bin/eslint --stdin --stdin-filename services/gateway/static/ejemplo_solo_advertencias.js -f stylish < '$REL/javascript/ejemplo_solo_advertencias.js'"

# --- Shell -----------------------------------------------------------------
corre "$REL/shell/salidas/shellcheck.txt" "$VENV/shellcheck" -f gcc "$REL/shell/ejemplo_violaciones_shell.sh"
corre "$REL/shell/salidas/bash-n.txt"     bash -n "$REL/shell/ejemplo_sintaxis_invalida.sh"
# "set -euo pipefail" no lo verifica shellcheck: se lista que scripts del producto no declaran set -e.
corre "$REL/shell/salidas/set-e-en-el-producto.txt" bash -c \
  "grep -L -E '^set -[a-zA-Z]*e' scripts/*.sh simulation/*.sh backup/*.sh; echo '(arriba: scripts del producto sin set -e)'; echo; echo 'Ejemplo de prueba:'; grep -L -E '^set -[a-zA-Z]*e' $REL/shell/ejemplo_violaciones_shell.sh"

# --- Dockerfile ------------------------------------------------------------
corre "$REL/dockerfile/salidas/hadolint.txt" docker run --rm -v "$RAIZ:/w" -w /w hadolint/hadolint hadolint "$REL/dockerfile/Dockerfile.violaciones"

# --- YAML ------------------------------------------------------------------
corre "$REL/yaml/salidas/yamllint-estilo.txt"   "$VENV/yamllint" -f parsable "$REL/yaml/ejemplo_violaciones.yml"
corre "$REL/yaml/salidas/yamllint-sintaxis.txt" "$VENV/yamllint" -f parsable "$REL/yaml/ejemplo_sintaxis_invalida.yml"
corre "$REL/yaml/salidas/compose-config.txt"    docker compose -f "$REL/yaml/ejemplo_compose_invalido.yml" config -q
echo "Listo. Salidas en $REL/*/salidas/"
