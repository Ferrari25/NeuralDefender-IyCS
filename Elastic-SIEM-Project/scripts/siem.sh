#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# siem.sh — Atajos para operar la capa IA (microservicios) desde el host.
#
# Antes cada herramienta se corría con `python3 src/<script>.py` en el host,
# leyendo y escribiendo los archivos de `data/` directamente. Ahora cada
# herramienta corre DENTRO del contenedor del servicio dueño de esos datos:
#
#   ./scripts/siem.sh pipeline             corre un ciclo de análisis
#                                          (collector → classifier → analyst → audit)
#   ./scripts/siem.sh usuarios <args>      gestión de usuarios del panel (servicio auth)
#                                          ej.: usuarios crear ana --rol analyst
#   ./scripts/siem.sh auditoria [args]     verifica la cadena de hashes (servicio audit)
#   ./scripts/siem.sh reporte [args]       reporte de decisiones y actividad → reportes/
#                                          ej.: reporte --formato csv --desde 2026-10-01
#   ./scripts/siem.sh cobertura [args]     todo lo que disparó en el SIEM llegó al panel
#                                          (servicio collector)
#   ./scripts/siem.sh logs-es              inspección ad-hoc de Elasticsearch (collector)
#   ./scripts/siem.sh estado               estado de los contenedores de la capa IA
#   ./scripts/siem.sh respaldo             respaldo cifrado YA (además del diario de las 03:00)
#   ./scripts/siem.sh restaurar <archivo> [--renombrar]
#                                          restaura un respaldo (servicio backup)
#
# Para automatizar el alta de un usuario sin prompt: SIEM_NEW_PASSWORD=... ./scripts/siem.sh usuarios crear ...
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

SERVICIOS_IA=(auth audit collector classifier knowledge analyst pipeline gateway)

uso() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

# Con una terminal interactiva se asigna TTY (lo necesita el prompt de
# contraseña de `usuarios crear`); desde otro script, no.
TTY=(-T)
[[ -t 0 && -t 1 ]] && TTY=()

ejecutar() { # servicio  comando...
  local servicio="$1"; shift
  local entorno=()
  [[ -n "${SIEM_NEW_PASSWORD:-}" ]] && entorno=(-e SIEM_NEW_PASSWORD)
  docker compose exec "${TTY[@]}" "${entorno[@]}" "$servicio" "$@"
}

comando="${1:-}"
[[ $# -gt 0 ]] && shift
case "$comando" in
  pipeline)  ejecutar pipeline  python siem_pipeline.py "$@" ;;
  usuarios)  ejecutar auth      python manage_users.py "$@" ;;
  auditoria) ejecutar audit     python audit_verify.py "$@" ;;
  reporte)
    # Sin TTY a propósito: con TTY, docker convierte los saltos de línea a CRLF
    # y el archivo guardado no sería el mismo que devuelve el servicio.
    # La extensión del archivo sigue al --formato pedido (json por defecto).
    formato=json
    anterior=""
    for arg in "$@"; do
      if [[ "$anterior" == "--formato" ]]; then formato="$arg"; fi
      if [[ "$arg" == --formato=* ]]; then formato="${arg#--formato=}"; fi
      anterior="$arg"
    done
    mkdir -p reportes
    destino="reportes/reporte-$(date -u +%Y%m%dT%H%M%SZ).${formato}"
    docker compose exec -T audit python reportes.py "$@" > "$destino" \
      || { rm -f "$destino"; echo "[ERROR] No se pudo generar el reporte."; exit 1; }
    echo "📄 Reporte guardado en $destino"
    ;;
  cobertura) ejecutar collector python verify-cobertura.py "$@" ;;
  logs-es)   ejecutar collector python get-logs.py "$@" ;;
  estado)    docker compose ps "${SERVICIOS_IA[@]}" ;;
  respaldo)  ejecutar backup    /backup/respaldo.sh ;;
  restaurar) ejecutar backup    /backup/restaurar.sh "$@" ;;
  -h|--help|"") uso ;;
  *) echo "[ERROR] Comando desconocido: $comando"; uso; exit 2 ;;
esac
