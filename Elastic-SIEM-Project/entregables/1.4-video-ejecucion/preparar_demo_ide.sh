#!/bin/bash
# Copia los ejemplos con violaciones del entregable 1.3 dentro del producto, SOLO para que el
# IDE los marque en el video (el IDE solo aplica las reglas a archivos que esten en su alcance).
# AL TERMINAR HAY QUE EJECUTAR limpiar_demo_ide.sh: mientras existan, la compuerta oficial y la
# prueba de no-autonomia fallan a proposito.
set -eu
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
EJ="$RAIZ/entregables/1.3-evidencia-reglas/prueba-de-reglas"
cp "$EJ/python/ejemplo_violaciones_python.py.txt" "$RAIZ/libs/zz_demo_violaciones.py"
cp "$EJ/javascript/ejemplo_violaciones_js.js"     "$RAIZ/services/gateway/static/zz_demo_violaciones.js"
echo "Archivos de demo creados:"
echo "  libs/zz_demo_violaciones.py"
echo "  services/gateway/static/zz_demo_violaciones.js"
echo "Abrelos en el IDE. AL TERMINAR: ./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh"
printf '%s\t%s\t%s\n' "$(date +%H:%M:%S.%3N)" "PREPARAR_DEMO" "" >> "$(dirname "$0")/tiempos.log"
