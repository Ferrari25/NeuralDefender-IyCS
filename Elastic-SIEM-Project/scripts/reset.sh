#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# reset.sh — Apaga TODO y borra los datos regenerables (reset a cero).
#
# Detiene y elimina todos los contenedores del proyecto (incluida la simulación),
# borra el volumen de datos de Elasticsearch (se pierden índices y alertas) y
# limpia los artefactos locales del pipeline para que el dashboard arranque vacío.
#
# ⚠️  EL REGISTRO DE AUDITORÍA NO SE BORRA (hallazgo A-01).
#
# `data/audit/decisions.jsonl` y `data/audit/analysis_history.jsonl` (el volumen
# del servicio de auditoría) son append-only e inmutables: son
# la única prueba de que hubo supervisión humana sobre cada acción sugerida. Un
# registro que un script del propio repo borra junto a los datos de demo no es un
# registro de auditoría, es un archivo de trabajo. Acá se ARCHIVAN (`mv`), nunca
# se eliminan.
#
# La MEMORIA DEL AGENTE (`data/knowledge/`: documentos, casos y lecciones
# aprobadas) tampoco se toca: no es regenerable, es lo que el sistema aprendió
# de los analistas. Para empezar de cero, borrarla a mano a conciencia.
#
# Uso:  ./scripts/reset.sh            (pide confirmación)
#       ./scripts/reset.sh --yes      (sin confirmar)
#       ./scripts/reset.sh --wipe-audit   (además ELIMINA la auditoría archivada;
#                                          pide una confirmación aparte y explícita)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

WIPE_AUDIT=false
SIN_CONFIRMAR=false
for arg in "$@"; do
  case "$arg" in
    --yes)        SIN_CONFIRMAR=true ;;
    --wipe-audit) WIPE_AUDIT=true ;;
    *) echo "[ERROR] Opción desconocida: $arg"; exit 2 ;;
  esac
done

if ! $SIN_CONFIRMAR; then
  echo "⚠️  Esto BORRA el volumen de datos de Elasticsearch (índices + alertas)."
  echo "    El registro de auditoría NO se borra: se archiva en data/audit/archivo/."
  read -r -p "¿Seguro? [y/N] " ans
  [[ "$ans" =~ ^[yY]$ ]] || { echo "Cancelado."; exit 0; }
fi

echo "🧹 Apagando contenedores y borrando volúmenes..."
docker compose --profile simulation down -v --remove-orphans

# Artefactos REGENERABLES: se borran sin más, el pipeline los vuelve a crear.
echo "🧹 Limpiando artefactos locales del pipeline..."
# (Cada uno vive en el volumen del servicio que lo genera.)
rm -f data/collector/siem_clean.json data/pipeline/siem_incidents.json data/ai_report.json
rm -f network_logs/*.json

# Registro de AUDITORÍA: se archiva, nunca se borra (A-01).
ALGO_QUE_ARCHIVAR=false
for f in data/audit/decisions.jsonl data/audit/analysis_history.jsonl data/audit/actividad.jsonl; do
  [[ -s "$f" ]] && ALGO_QUE_ARCHIVAR=true
done

if $ALGO_QUE_ARCHIVAR; then
  mkdir -p data/audit/archivo
  # `mktemp -d` en vez de solo el timestamp: dos resets dentro del mismo segundo
  # compartirían nombre y el segundo pisaría el archivo del primero — es decir,
  # perdería evidencia de auditoría, justo lo que este cambio busca evitar.
  ARCHIVO_AUDITORIA=$(mktemp -d "data/audit/archivo/$(date -u +%Y%m%dT%H%M%SZ)-XXXX")
  for f in data/audit/decisions.jsonl data/audit/analysis_history.jsonl data/audit/actividad.jsonl; do
    [[ -s "$f" ]] && mv "$f" "$ARCHIVO_AUDITORIA/"
  done
  chmod -R a-w "$ARCHIVO_AUDITORIA"
  echo "🔒 Auditoría archivada en $ARCHIVO_AUDITORIA (solo lectura)."
else
  echo "🔒 No había auditoría que archivar."
fi

if $WIPE_AUDIT; then
  echo
  echo "⚠️  --wipe-audit ELIMINA TODA la auditoría archivada en data/audit/archivo/."
  echo "    Esto destruye la evidencia de la supervisión humana. No se puede deshacer."
  read -r -p "    Escribí BORRAR AUDITORIA para confirmar: " confirmacion
  if [[ "$confirmacion" == "BORRAR AUDITORIA" ]]; then
    chmod -R u+w data/audit/archivo 2>/dev/null || true
    rm -rf data/audit/archivo
    echo "🗑️  Auditoría archivada eliminada."
  else
    echo "    Cancelado: la auditoría archivada se conserva."
  fi
fi

echo "✅ Reset completo. Datos en cero, auditoría preservada."
echo "   Levantá de nuevo con:  ./scripts/start.sh"
