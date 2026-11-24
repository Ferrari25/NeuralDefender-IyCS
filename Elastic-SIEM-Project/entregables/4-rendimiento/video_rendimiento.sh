#!/bin/bash
# Video del entregable 4: corrida de CARGA completa, sin acelerar y sin pausas (unos 5 minutos).
#
#   ./entregables/4-rendimiento/video_rendimiento.sh
#
# Corre el escenario de carga de tests/performance/k6_api_test.js con las duraciones reales: los 5 grupos de endpoints
# en paralelo, cada uno con su tasa real (lecturas, decisiones, login, auditoría y sonda de salud), con el panel web de k6
# en vivo (http://127.0.0.1:5665, se abre solo). Al terminar muestra el p95 de la meseta de cada endpoint frente a su umbral.
# Solo hay una pausa, al principio, para presentar el perfil de uso; después corre de corrido hasta el final.
#   PAUSA=0  sin la pausa inicial      ABRIR=0  no abre el navegador
# No toca nada del proyecto: lo que genera va a una carpeta temporal. Al terminar deja la malla en su estado normal.
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
cd "$RAIZ" || exit 1
PAUSA="${PAUSA:-1}"; ABRIR="${ABRIR:-1}"
T="$(mktemp -d /tmp/k6vivo.XXXXXX)"   # carpeta propia (una que haya creado Docker quedaría de root)
MALLA="$RAIZ/entregables/2-servicios/postman/malla.sh"
abrir() { [[ "$ABRIR" == 1 ]] && command -v xdg-open >/dev/null && (xdg-open "$1" >/dev/null 2>&1 &); }
titulo() { printf '\n------------------------------------------------------------------------\n%s\n------------------------------------------------------------------------\n' "$1"; }

cp tests/performance/k6_api_test.js tests/performance/generate_report.py "$T/" || { echo "No pude preparar $T"; exit 1; }

titulo "PASO 1 - Perfil de uso: cada grupo de endpoints con su propia carga (20 analistas)"
cat <<'E'
  Grupo                       Frecuencia real                              Tasa en la prueba
  --------------------------  -------------------------------------------  ------------------------------
  Lecturas del panel          3 pedidos cada 15 s por analista (app.js)    20 iteraciones cada 15 s
  Registro de decisiones      200 por analista por día (ERS)               500 por hora
  Inicio de sesión            1 por sesión: ráfaga de inicio de turno      3 ráfagas de 20 simultáneos
  Auditoría: informes         1 por analista por hora (supuesto)           20 por hora
  Auditoría: verificación     1 cada 10 min con 2 auditores (supuesto)     12 por hora
  Sonda de salud              1 cada 10 s (healthcheck de Docker)          6 por minuto

  Etapas: subida de 30 s y meseta de 240 s (4 minutos). Duración total: 4 min 30 s.
  Datos: 100 incidentes, 20 analistas y 1.400 decisiones (7 días de uso).
  Umbrales: incidentes p95 < 2 s (RNF-RD-01); decisión p95 < 500 ms (RNF-RD-04); demás lecturas p95 < 500 ms (RNF-RD-09);
            login e informes p95 < 2 s (interno); errores < 1 %; sonda < 2 s (RNF-COMP-01).
E
[[ "$PAUSA" == 0 ]] || read -r -p "   [Enter para iniciar la corrida completa] " _

titulo "PASO 2 - Carga completa con k6 (panel en vivo en http://127.0.0.1:5665)"
"$MALLA" reiniciar --incidentes 100 --analistas 20 --decisiones 1400 | grep -E "incidentes:|no arrancó|en uso"
( sleep 5; abrir http://127.0.0.1:5665 ) &
inicio=$SECONDS
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$T:/repo/tests/performance" -w /repo \
  -e ESCENARIO=carga -e BASE_URL=http://127.0.0.1:18080 -e K6_CLAVE='PruebaMalla#2026' \
  -e K6_WEB_DASHBOARD=true grafana/k6:1.3.0 run tests/performance/k6_api_test.js
codigo=$?
echo
echo "  k6 terminó con código $codigo (0 = todos los umbrales se cumplieron; 99 = alguno no) en $((SECONDS - inicio)) s."

titulo "PASO 3 - Resultado: p95 de la meseta de cada endpoint frente a su umbral"
python3 "$T/generate_report.py" > /dev/null 2>&1
sed -n '/^### 3.1/,/^Umbrales:/p' "$T/INFORME_RESULTADOS_RENDIMIENTO.md" | sed '$d' | sed 's/^/  /'
echo "  (n < 30: pocas muestras a la tasa real; el p95 es orientativo)"

titulo "CIERRE"
echo "  Cada grupo de endpoints se midió con su propio perfil de uso. El informe completo, con el estrés de cada grupo, está en entregables/4-rendimiento/."
"$MALLA" reiniciar > /dev/null 2>&1
echo "  (malla restaurada a su estado normal)"
