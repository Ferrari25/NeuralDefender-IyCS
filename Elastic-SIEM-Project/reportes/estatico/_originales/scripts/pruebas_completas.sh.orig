#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# pruebas_completas.sh — Corre pruebas_de_codigo_estatico.sh y
# pruebas_de_servicio.sh, en ese orden. Es lo que correría CI: la puerta de
# calidad completa con un solo comando.
#
# Uso:  ./scripts/pruebas_completas.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

FALLOS=0
./scripts/pruebas_de_codigo_estatico.sh || FALLOS=$((FALLOS + 1))
./scripts/pruebas_de_servicio.sh        || FALLOS=$((FALLOS + 1))

echo
if (( FALLOS == 0 )); then
  echo "✅ Puerta de calidad completa: todo en verde."
else
  echo "❌ $FALLOS de los 2 grupos tuvo fallos — revisar arriba."
fi
exit $(( FALLOS > 0 ))
