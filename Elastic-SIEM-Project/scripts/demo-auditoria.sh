#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# demo-auditoria.sh — Rompe la cadena de auditoría en vivo y la muestra detectada.
#
# POR QUÉ EXISTE
#
# "El registro es inmutable" es una afirmación. Nadie tiene por qué creerla. Esto
# la convierte en una demostración: se altera una decisión ya registrada y el
# verificador del proyecto —el mismo que corre en la puerta de calidad— señala la
# línea exacta y termina con código 1.
#
# El punto no es que el archivo no se pueda editar: cualquiera con permisos puede.
# El punto es que editarlo es DETECTABLE, y eso es lo que lo hace servir como
# evidencia.
#
# ⚠️  EL REGISTRO REAL NO SE TOCA
#
# `decisions.jsonl` son datos del equipo. Todo ocurre sobre una COPIA en un
# directorio temporal, y el script imprime el SHA-256 del archivo real antes y
# después para probar que no cambió.
#
# Uso:
#   ./scripts/demo-auditoria.sh              narrado, con pausas
#   ./scripts/demo-auditoria.sh --rapido     sin pausas (para probarlo)
#   ./scripts/demo-auditoria.sh --json       solo el antes/después, en JSON
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD/.devtools${PYTHONPATH:+:$PYTHONPATH}"

RAPIDO=false
SOLO_JSON=false

while (( $# )); do
  case "$1" in
    --rapido)  RAPIDO=true; shift ;;
    --json)    SOLO_JSON=true; RAPIDO=true; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

REGISTRO="data/decisions.jsonl"

narrar()  { $SOLO_JSON || printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
detalle() { $SOLO_JSON || printf '  %s\n' "$1"; }
ok()      { $SOLO_JSON || printf '  \033[32m✔\033[0m %s\n' "$1"; }
mal()     { $SOLO_JSON || printf '  \033[31m✗\033[0m %s\n' "$1"; }
pausa()   { $RAPIDO || sleep "${1:-3}"; }

if [[ ! -f "$REGISTRO" ]]; then
  echo "[ERROR] No existe $REGISTRO: todavía no se registró ninguna decisión."
  echo "        Corré ./scripts/demo.sh, entrá al panel y aprobá o descartá una acción."
  exit 1
fi

# Testigo de que el archivo real no se modifica. Se compara al final.
HASH_ANTES=$(sha256sum "$REGISTRO" | cut -d' ' -f1)

TALLER=$(mktemp -d)
# shellcheck disable=SC2064  # se expande ahora a propósito: la ruta no cambia
trap "rm -rf '$TALLER'" EXIT INT TERM

COPIA="$TALLER/decisions.jsonl"
cp "$REGISTRO" "$COPIA"
LINEAS_REALES=$(wc -l < "$COPIA")

$SOLO_JSON || {
printf '\n\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1m║  LA AUDITORÍA ES VERIFICABLE · ruptura en vivo                ║\033[0m\n'
printf '\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m\n'
}

narrar "Se trabaja sobre una copia de $REGISTRO ($LINEAS_REALES registros)"
detalle "El archivo real son datos del equipo y no se toca. Al final se compara"
detalle "su SHA-256 para probarlo."
pausa 3

# ─── Por qué hacen falta registros posteriores ───────────────────────────────
#
# Cada registro lleva el SHA-256 del anterior. Alterar el ÚLTIMO no rompe nada
# porque no hay ningún registro que apunte a él: la protección la da el eslabón
# siguiente. Es una propiedad real del mecanismo, no una limitación de esta demo,
# y conviene decirla en voz alta antes de que la pregunten.

narrar "Se agregan dos decisiones nuevas a la copia"
detalle "Un encadenado protege un registro a través del SIGUIENTE: el último"
detalle "eslabón de cualquier cadena queda expuesto hasta que otro lo cubre."
detalle "Se usa el append_jsonl real del proyecto, no un JSON escrito a mano."

TALLER="$TALLER" python3 - <<'PY'
import os
import pathlib
import sys

sys.path.insert(0, os.path.join(os.getcwd(), "src"))
from siem_lib import append_jsonl  # noqa: E402

copia = pathlib.Path(os.environ["TALLER"]) / "decisions.jsonl"
for n in (1, 2):
    append_jsonl(copia, {
        "ts": f"2026-09-25T18:0{n}:00.000000+00:00",
        "incident_id": "INC-DEMO-198.51.100.10-demo",
        "action_id": f"INC-DEMO-198.51.100.10-demo-a{n}",
        "decision": "approved",
        "analyst": "analista",
        "analyst_rol": "analyst",
        "note": "decision de demostracion",
        "source_ip": "198.51.100.10",
        "attacker_ips": ["198.51.100.10"],
    })
PY
[[ $? -eq 0 ]] || { mal "no se pudo sembrar la copia"; exit 1; }
ok "$(wc -l < "$COPIA") registros en la copia"

# El estado al que se vuelve en el paso 4. Restaurar desde el archivo real daría
# 28 registros donde el paso 1 mostró 30, y eso se nota en la proyección.
PRISTINA="$TALLER/decisions.pristina.jsonl"
cp "$COPIA" "$PRISTINA"
pausa 3

# ─── 1 · La cadena está intacta ──────────────────────────────────────────────

narrar "1 · Se verifica la copia tal como está"
detalle "python3 src/audit_verify.py $COPIA"
pausa 2

SALIDA_TEXTO=$(python3 src/audit_verify.py "$COPIA" 2>&1)
$SOLO_JSON || printf '%s\n' "$SALIDA_TEXTO" | sed 's/^/     /'
$SOLO_JSON && ANTES_JSON=$(python3 src/audit_verify.py --json "$COPIA" 2>/dev/null)
pausa 3

# ─── 2 · Se altera una decisión ya registrada ────────────────────────────────

narrar "2 · Alguien cambia una decisión que ya estaba registrada"
detalle "Se toma el registro $LINEAS_REALES —una decisión real, aprobada— y se lo"
detalle "da vuelta a 'descartada', como para tapar que se aprobó algo."
detalle "No se toca ningún hash: solo el contenido, que es lo que haría alguien"
detalle "que quiere reescribir la historia."
pausa 4

# Con --json la salida tiene que ser JSON parseable y nada mas, asi que el
# detalle del cambio se guarda y se imprime solo en el modo narrado.
CAMBIO=$(COPIA="$COPIA" LINEA="$LINEAS_REALES" python3 - <<'PY'
import json
import os
import pathlib

copia = pathlib.Path(os.environ["COPIA"])
linea = int(os.environ["LINEA"])

lineas = copia.read_text(encoding="utf-8").splitlines()
r = json.loads(lineas[linea - 1])
antes = r.get("decision")
r["decision"] = "dismissed" if antes == "approved" else "approved"
lineas[linea - 1] = json.dumps(r, ensure_ascii=False)
copia.write_text("\n".join(lineas) + "\n", encoding="utf-8")
print(f"registro {linea}: decision  {antes}  ->  {r['decision']}")
PY
) || { mal "no se pudo alterar la copia"; exit 1; }
detalle ""
detalle "     $CAMBIO"
pausa 3

# ─── 3 · El verificador lo encuentra ─────────────────────────────────────────

narrar "3 · Se vuelve a verificar, sin decirle nada al verificador"
pausa 2

SALIDA_TEXTO=$(python3 src/audit_verify.py "$COPIA" 2>&1)
SALIDA=$?
$SOLO_JSON || printf '%s\n' "$SALIDA_TEXTO" | sed 's/^/     /'
$SOLO_JSON && DESPUES_JSON=$(python3 src/audit_verify.py --json "$COPIA" 2>/dev/null)

echo
if (( SALIDA == 1 )); then
  ok "código de salida 1 — la manipulación se detectó"
  detalle "Ese 1 es lo que hace fallar la puerta de calidad y lo que haría"
  detalle "fallar a CI. No depende de que alguien lea la pantalla."
else
  mal "código de salida $SALIDA — SE ESPERABA 1. La detección no funcionó."
  exit 1
fi
pausa 4

# ─── 4 · Se restaura ─────────────────────────────────────────────────────────

narrar "4 · Se restaura la copia y se verifica otra vez"
cp "$PRISTINA" "$COPIA"
$SOLO_JSON || python3 src/audit_verify.py "$COPIA" | sed -n '3,5p' | sed 's/^/     /'
pausa 2

# ─── 5 · El archivo real no cambió ───────────────────────────────────────────

HASH_DESPUES=$(sha256sum "$REGISTRO" | cut -d' ' -f1)

narrar "5 · El registro real, antes y después de todo esto"
detalle "antes:   ${HASH_ANTES:0:32}…"
detalle "después: ${HASH_DESPUES:0:32}…"

if [[ "$HASH_ANTES" == "$HASH_DESPUES" ]]; then
  ok "idéntico — la demostración no tocó los datos del equipo"
else
  mal "EL REGISTRO REAL CAMBIÓ. Esto es un defecto de este script, reportalo."
  exit 1
fi

if $SOLO_JSON; then
  ANTES_JSON="$ANTES_JSON" DESPUES_JSON="$DESPUES_JSON" python3 - <<'PY'
import json
import os

def resumen(bruto):
    d = json.loads(bruto)[0]
    return {k: d.get(k) for k in ("estado", "chain_ok", "records", "first_broken", "reason")}

print(json.dumps({"antes": resumen(os.environ["ANTES_JSON"]),
                  "despues": resumen(os.environ["DESPUES_JSON"])},
                 ensure_ascii=False, indent=2))
PY
  exit 0
fi

# ─── Cierre ──────────────────────────────────────────────────────────────────

echo
detalle "Lo que hay que decir:"
detalle ""
detalle "  El registro no es imposible de editar — cualquiera con permisos puede."
detalle "  Es DETECTABLE, y por eso sirve como evidencia. Cada línea lleva el"
detalle "  SHA-256 de la anterior, así que cambiar una decisión del medio obliga a"
detalle "  recalcular todas las que vienen después."
detalle ""
detalle "  Y lo que se registra no es solo la decisión: queda el analista, su rol,"
detalle "  el identificador de sesión y el momento. Quién decidió qué, y cuándo."
echo
