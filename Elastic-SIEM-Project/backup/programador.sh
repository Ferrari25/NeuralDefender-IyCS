#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# programador.sh — Proceso principal del contenedor `backup`: corre
# respaldo.sh todos los días a las $SIEM_RESPALDO_HORA (03:00 por defecto, ERS
# 7.9.2), en la zona horaria $TZ.
#
# Un respaldo que falla no detiene al programador: se registra y se reintenta al
# día siguiente (el último respaldo bueno sigue en su lugar). `docker logs
# siem-backup` muestra el resultado de cada corrida.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

HORA="${SIEM_RESPALDO_HORA:-03:00}"
[[ "$HORA" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] \
  || { echo "[programador] SIEM_RESPALDO_HORA inválida: $HORA (formato HH:MM)" >&2; exit 2; }

echo "[programador] respaldo diario a las $HORA ($TZ)"
while true; do
  ahora=$(date +%s)
  proximo=$(date -d "today $HORA" +%s)
  (( proximo <= ahora )) && proximo=$(date -d "tomorrow $HORA" +%s)
  echo "[programador] próximo respaldo: $(date -d "@$proximo" '+%F %R %Z')"
  sleep $(( proximo - ahora ))
  /backup/respaldo.sh || echo "[programador] el respaldo FALLÓ; se reintenta mañana a las $HORA" >&2
done
