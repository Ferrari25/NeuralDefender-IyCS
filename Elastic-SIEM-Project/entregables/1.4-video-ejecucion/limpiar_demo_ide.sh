#!/bin/bash
# Borra los archivos de demo del IDE y verifica que el producto quedo como antes.
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
rm -f "$RAIZ/libs/zz_demo_violaciones.py" "$RAIZ/services/gateway/static/zz_demo_violaciones.js"
cd "$RAIZ" || exit 1
if find . -name 'zz_demo_violaciones*' -not -path './node_modules/*' -not -path './.devtools/*' | grep -q .; then
  echo "ATENCION: quedan archivos de demo:"; find . -name 'zz_demo_violaciones*' -not -path './node_modules/*' -not -path './.devtools/*'; exit 1
fi
echo "Limpio: no queda ningun archivo zz_demo_violaciones*."
printf '%s\t%s\t%s\n' "$(date +%H:%M:%S.%3N)" "LIMPIAR_DEMO" "" >> "$RAIZ/entregables/1.4-video-ejecucion/tiempos.log"
