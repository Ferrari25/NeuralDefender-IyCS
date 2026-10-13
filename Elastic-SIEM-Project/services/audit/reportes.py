#!/usr/bin/env python3
"""Reportes de la supervisión humana, armados desde los registros de auditoría.

Fuentes (las dos append-only y encadenadas por hash, en el volumen de audit):

  - `decisions.jsonl` — cada aprobación/descarte de una acción sugerida, con el
    contexto del incidente al momento de decidir (tipo de ataque, severidad,
    falso positivo, IP).
  - `actividad.jsonl` — lo que los analistas hicieron con la memoria del
    Agente 2: documentos cargados y lecciones propuestas/aprobadas/rechazadas.

El reporte NO es una fuente nueva: es una vista de esos dos registros, con la
verificación de su cadena incluida. Si la cadena está rota, el reporte lo dice
en vez de presentar como confiables datos que pudieron haberse alterado.

Uso como herramienta (dentro del contenedor de audit; desde el host,
`./scripts/siem.sh reporte`, que lo guarda en `reportes/`):
    python reportes.py                              # JSON, todo el período
    python reportes.py --formato csv --desde 2026-10-01 --hasta 2026-10-31

Solo lectura: no escribe ni modifica ningún registro.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from datetime import date

from cadena import read_jsonl, verificar_cadena
from siem_lib import now_iso

DECISIONS_FILE = "data/decisions.jsonl"
ACTIVIDAD_FILE = "data/actividad.jsonl"

FORMATOS = ("json", "csv")

COLUMNAS_CSV = ("ts", "registro", "analista", "rol", "evento", "incident_id", "action_id",
                "accion", "attack_type", "severidad", "falso_positivo", "ip", "detalle")

# Una celda que empieza con estos caracteres la interpreta como fórmula una
# planilla (Excel, LibreOffice, Sheets). La nota de un analista o un usuario
# objetivo salido de un log podrían empezar así: se neutraliza con un apóstrofo.
_INICIO_DE_FORMULA = ("=", "+", "-", "@", "\t", "\r")


class PeriodoInvalido(ValueError):
    """`desde`/`hasta` no son fechas AAAA-MM-DD, o están invertidas."""


def _fecha(valor: str | None, campo: str) -> str | None:
    if not valor:
        return None
    try:
        return date.fromisoformat(valor).isoformat()
    except ValueError as e:
        raise PeriodoInvalido(f"'{campo}' debe ser una fecha AAAA-MM-DD") from e


def _en_periodo(ts: str | None, desde: str | None, hasta: str | None) -> bool:
    dia = (ts or "")[:10]
    return (desde is None or dia >= desde) and (hasta is None or dia <= hasta)


def _contar(registros: list[dict], campo: str) -> dict[str, int]:
    return dict(Counter(str(r.get(campo) or "—") for r in registros).most_common())


def armar_reporte(desde: str | None = None, hasta: str | None = None) -> dict:
    """Reporte del período `[desde, hasta]` (fechas inclusive, UTC)."""
    desde, hasta = _fecha(desde, "desde"), _fecha(hasta, "hasta")
    if desde and hasta and desde > hasta:
        raise PeriodoInvalido("'desde' es posterior a 'hasta'")

    decisiones = [d for d in read_jsonl(DECISIONS_FILE, tolerante=True)
                  if _en_periodo(d.get("ts"), desde, hasta)]
    actividad = [a for a in read_jsonl(ACTIVIDAD_FILE, tolerante=True)
                 if _en_periodo(a.get("ts"), desde, hasta)]

    # Una misma acción puede decidirse más de una vez (el registro es
    # append-only): el estado vigente es la última, y las anteriores cuentan
    # como revisiones — ambas cosas le importan a quien audita.
    por_accion = Counter(d.get("action_id") for d in decisiones)
    vigentes = {d.get("action_id"): d for d in sorted(decisiones, key=lambda d: d.get("ts") or "")}

    return {
        "generado_en": now_iso(),
        "periodo": {"desde": desde, "hasta": hasta},
        "integridad": {
            "decisiones": verificar_cadena(DECISIONS_FILE),
            "actividad": verificar_cadena(ACTIVIDAD_FILE),
        },
        "resumen": {
            "decisiones_registradas": len(decisiones),
            "acciones_decididas": len(vigentes),
            "acciones_revisadas_mas_de_una_vez": sum(1 for n in por_accion.values() if n > 1),
            "estado_vigente": _contar(list(vigentes.values()), "decision"),
            "por_analista": _contar(decisiones, "analyst"),
            "por_tipo_de_ataque": _contar(decisiones, "attack_type"),
            "por_severidad": _contar(decisiones, "severidad"),
            "incidentes_con_decisiones": len({d.get("incident_id") for d in decisiones}),
            "actividad_de_memoria": _contar(actividad, "evento"),
        },
        "decisiones": decisiones,
        "actividad": actividad,
    }


def _celda(valor: object) -> str:
    if isinstance(valor, list):
        valor = ", ".join(str(v) for v in valor)
    texto = "" if valor is None else str(valor)
    return "'" + texto if texto.startswith(_INICIO_DE_FORMULA) else texto


def a_csv(reporte: dict) -> str:
    """Una fila por evento (decisiones y actividad juntas, en orden cronológico)."""
    filas = [{
        "ts": d.get("ts"), "registro": "decision", "analista": d.get("analyst"),
        "rol": d.get("analyst_rol"), "evento": d.get("decision"),
        "incident_id": d.get("incident_id"), "action_id": d.get("action_id"),
        "accion": d.get("accion"), "attack_type": d.get("attack_type"),
        "severidad": d.get("severidad"), "falso_positivo": d.get("falso_positivo"),
        "ip": d.get("attacker_ips") or d.get("source_ip"), "detalle": d.get("note"),
    } for d in reporte["decisiones"]] + [{
        "ts": a.get("ts"), "registro": "memoria", "analista": a.get("actor"),
        "rol": a.get("actor_rol"), "evento": a.get("evento"),
        "incident_id": None, "action_id": a.get("leccion_id") or a.get("doc_id"),
        "accion": None, "attack_type": a.get("attack_type"), "severidad": None,
        "falso_positivo": None, "ip": a.get("ip"), "detalle": a.get("detalle"),
    } for a in reporte["actividad"]]
    filas.sort(key=lambda f: f["ts"] or "")

    salida = io.StringIO()
    escritor = csv.DictWriter(salida, fieldnames=COLUMNAS_CSV, lineterminator="\n")
    escritor.writeheader()
    for fila in filas:
        escritor.writerow({k: _celda(v) for k, v in fila.items()})
    return salida.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reporte de la supervisión humana (solo lectura).")
    parser.add_argument("--desde", help="fecha inicial AAAA-MM-DD (inclusive)")
    parser.add_argument("--hasta", help="fecha final AAAA-MM-DD (inclusive)")
    parser.add_argument("--formato", choices=FORMATOS, default="json")
    args = parser.parse_args(argv)
    try:
        reporte = armar_reporte(args.desde, args.hasta)
    except PeriodoInvalido as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    if args.formato == "csv":
        sys.stdout.write(a_csv(reporte))
    else:
        print(json.dumps(reporte, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
