#!/usr/bin/env python3
"""
Demuestra que todo lo que disparó en el SIEM está representado en el panel.

`prepare-for-ia.py` usa `alerts_query_por_regla` (tope de 5 alertas por regla,
ver D-01 en `docs/12-registro-de-pruebas.md`) para que una regla ruidosa no tape
a las demás frente al LLM — es una MUESTRA a propósito, no todo lo que hay en
Elasticsearch. Este script hace la pregunta inversa, sin ese recorte: consulta
`.alerts-security.alerts-default` directamente (hasta `--size` alertas, las más
recientes de la ventana) y verifica, por cada IP atacante que disparó de
verdad, dos cosas contra `siem_incidents.json`:

  1. Cobertura  — existe un incidente en el panel para esa IP.
  2. Severidad  — la regla que el panel le atribuye a esa IP, PARA CADA TÉCNICA
                  MITRE por separado, es la MÁS GRAVE de las que dispararon esa
                  técnica (mismo criterio de `classifier.py`: varias reglas
                  pueden disparar sobre la misma IP —p.ej. la Low de línea base
                  y la Critical de compromiso— y el panel muestra UNA sola
                  identidad POR TÉCNICA, la más grave; que aparezca solo esa no
                  es un hueco, es el diseño. Por técnica y no en general porque
                  una misma IP puede protagonizar una CAMPAÑA —SSH Y port scan a
                  la vez, por ejemplo— y ahí sí son dos incidentes legítimos,
                  uno por técnica, no uno que tapa al otro).

Los eventos de red (port scan, phishing) no tienen el riesgo de la muestra:
`classifier.py` lee `network_logs/` completo, sin recorte de tamaño (ver
`tests/unit/test_b0x_robustez_y_formatos.py`), así que no hace falta volver a
compararlos contra Elasticsearch acá — lo que sí se verifica es que la regla de
Kibana que corresponde a esos eventos (B1-B4, C1-C3) haya quedado prendida en
el incidente, con el mismo criterio de "la más grave" que SSH.

Uso:
  export PYTHONPATH="$PWD/.devtools"
  python3 verify-cobertura.py                  # ventana 24h, siem_incidents.json actual
  python3 verify-cobertura.py --window 1h --size 2000
"""

from __future__ import annotations

import argparse
import json
import sys

from classifier import _RANGO_SEVERIDAD_SIEM
from siem_lib import (
    ALERTS_INDEX,
    ESUnavailable,
    alerts_query,
    es_search,
    rol_del_campo_agrupado,
)

INCIDENTS_FILE = "siem_incidents.json"


# A qué familia de detección pertenece cada técnica MITRE — mismas tres que
# separan `detect_auth_incidents`/`detect_port_scans`/`detect_phishing`. Una IP
# puede protagonizar una campaña (SSH Y port scan a la vez) y ahí son DOS
# incidentes legítimos, uno por familia — por eso "más grave gana" se calcula
# por (IP, familia), nunca por IP a secas.
_FAMILIA_POR_TECNICA = {"T1110": "auth", "T1046": "port_scan", "T1566": "phishing"}


def alertas_por_ip_y_familia(
    window: str, size: int,
) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """(IP atacante, familia) -> [(rule_name, severity), ...] de sus alertas
    reales, SIN el recorte de 5-por-regla que usa el pipeline. Mismo criterio de
    rol que `prepare-for-ia.parse_alerts`: el valor agrupado solo cuenta como IP
    atacante si el campo por el que agrupó la regla representa al atacante."""
    hits = es_search(ALERTS_INDEX, alerts_query(size=size, window=window))
    por_ip: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for h in hits:
        s = h["_source"]
        rule_name = s.get("kibana.alert.rule.name")
        severity = s.get("kibana.alert.severity")
        threshold = s.get("kibana.alert.threshold_result", {})
        terms = threshold.get("terms") or []
        campo = terms[0].get("field") if terms else None
        valor = terms[0].get("value") if terms else None
        rol = rol_del_campo_agrupado(campo)
        ip = valor if rol == "atacante" else (None if terms else s.get("source_ip"))
        threat = (s.get("kibana.alert.rule.threat") or [{}])[0]
        technique_id = (threat.get("technique") or [{}])[0].get("id")
        familia = _FAMILIA_POR_TECNICA.get(technique_id)
        if not ip or not rule_name or not familia:
            continue
        por_ip.setdefault((ip, familia), []).append((rule_name, severity))
    return por_ip


def regla_mas_severa(alertas: list[tuple[str, str]]) -> str | None:
    """Mismo criterio que `classifier._regla_mas_severa`: con varias reglas
    sobre la misma IP, la más grave manda."""
    mejor, mejor_rango = None, -1
    for rule_name, severity in alertas:
        rango = _RANGO_SEVERIDAD_SIEM.get((severity or "").lower(), -1)
        if rango >= mejor_rango:
            mejor_rango, mejor = rango, rule_name
    return mejor


def reglas_en_el_panel(incidentes: list[dict]) -> dict[tuple[str, str], str]:
    """(IP, familia) -> regla que el panel le atribuye. `source_ip` Y
    `attacker_ips` cuentan como la misma identidad: el clasificador arma cada
    una según el tipo de ataque (en phishing, `attacker_ips` es el servidor
    falso pero la alerta de Kibana quedó indexada por la IP de la víctima que
    mandó las credenciales)."""
    por_ip: dict[tuple[str, str], str] = {}
    for inc in incidentes:
        rn = inc.get("rule_name")
        familia = _FAMILIA_POR_TECNICA.get((inc.get("mitre") or {}).get("technique_id"))
        if not rn or not familia:
            continue
        ips = set(inc.get("attacker_ips") or [])
        if inc.get("source_ip"):
            ips.add(inc["source_ip"])
        for ip in ips:
            por_ip[(ip, familia)] = rn
    return por_ip


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--window", default="24h", help="ventana temporal (default: 24h)")
    ap.add_argument("--size", type=int, default=1000,
                     help="máximo de alertas a traer de Elasticsearch (default: 1000)")
    args = ap.parse_args()

    print(f"Consultando Elasticsearch ({ALERTS_INDEX}, ventana {args.window}, "
          f"sin recorte por regla)...")
    try:
        reales = alertas_por_ip_y_familia(args.window, args.size)
    except ESUnavailable as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    try:
        with open(INCIDENTS_FILE, encoding="utf-8") as fh:
            incidentes = json.load(fh)["incidents"]
    except FileNotFoundError:
        print(f"[ERROR] No existe '{INCIDENTS_FILE}'. Corré primero: python3 siem_pipeline.py")
        sys.exit(1)

    en_panel = reglas_en_el_panel(incidentes)
    total_alertas = sum(len(v) for v in reales.values())

    sin_incidente: list[tuple[str, str]] = []
    severidad_incorrecta: list[tuple[str, str, str, str]] = []  # ip, familia, esperada, mostrada

    for (ip, familia), alertas in reales.items():
        esperada = regla_mas_severa(alertas)
        mostrada = en_panel.get((ip, familia))
        if mostrada is None:
            sin_incidente.append((ip, familia))
        elif mostrada != esperada:
            severidad_incorrecta.append((ip, familia, esperada, mostrada))

    print(f"\n{'='*60}\n  RESULTADO\n{'='*60}")
    print(f"  Alertas reales en Elasticsearch              : {total_alertas}")
    print(f"  Pares (IP, técnica) distintos que dispararon : {len(reales)}")
    print(f"  Incidentes en '{INCIDENTS_FILE}'              : {len(incidentes)}")
    print(f"  Pares (IP, técnica) con incidente en el panel : {len(en_panel)}")
    print()

    if not sin_incidente and not severidad_incorrecta:
        print("✅ Toda IP que disparó una alerta en el SIEM tiene un incidente en el "
              "panel, con la regla más grave de las que dispararon para esa técnica.")
        return

    if sin_incidente:
        print(f"❌ {len(sin_incidente)} par(es) (IP, técnica) dispararon en Kibana y "
              f"NO tienen ningún incidente en el panel:")
        for ip, familia in sorted(sin_incidente):
            print(f"   - {ip} ({familia}): {sorted({r for r, _ in reales[(ip, familia)]})}")
    if severidad_incorrecta:
        print(f"❌ {len(severidad_incorrecta)} par(es) (IP, técnica) muestran una "
              f"regla que NO es la más grave que disparó:")
        for ip, familia, esperada, mostrada in sorted(severidad_incorrecta):
            print(f"   - {ip} ({familia}): panel muestra «{mostrada}», debería ser «{esperada}»")
    print("\n   Puede ser que el pipeline (siem_pipeline.py) no se haya vuelto a "
          "correr\n   después de la última alerta. Volvé a correrlo y repetí esta prueba.")
    sys.exit(1)


if __name__ == "__main__":
    main()
