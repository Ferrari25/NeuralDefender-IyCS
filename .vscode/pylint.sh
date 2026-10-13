#!/bin/bash
# Lanza el pylint de Elastic-SIEM-Project/.devtools con el mismo PYTHONPATH,
# .pylintrc e --init-hook que usa scripts/pruebas_de_codigo_estatico.sh.
P="$(cd "$(dirname "$0")/../Elastic-SIEM-Project" && pwd)"
export PYTHONPATH="$P/.devtools${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 -m pylint --rcfile="$P/.pylintrc" \
  --init-hook="import sys, glob; sys.path[:0] = ['$P/libs', *sorted(glob.glob('$P/services/*'))]" "$@"
