#!/usr/bin/env python3
"""
Utilidad de inspección ad-hoc: imprime los últimos logs de auth fallida y las
alertas de seguridad desde Elasticsearch. Para el pipeline real usá
prepare-for-ia.py (que limpia y estructura). Este script es para mirar a mano.
"""

from __future__ import annotations

import json

from siem_lib import (
    ALERTS_INDEX,
    ES_HOST,
    LOGS_INDEX,
    ESUnavailable,
    alerts_query,
    auth_failure_query,
    es_search,
    now_iso,
)


def show(hits: list[dict], label: str) -> None:
    print(f"\n{'='*60}\n  {label} — {len(hits)} resultado(s)\n{'='*60}")
    for i, hit in enumerate(hits, 1):
        print(f"\n--- Evento #{i} ---")
        print(json.dumps(hit["_source"], indent=2, ensure_ascii=False))


def main() -> None:
    print(f"Conectando a Elasticsearch en {ES_HOST} ... ({now_iso()})")
    try:
        logs   = es_search(LOGS_INDEX, auth_failure_query(size=5, window="24h"))
        alerts = es_search(ALERTS_INDEX, alerts_query(size=5, window="24h"))
    except ESUnavailable as e:
        print(f"[ERROR] {e}")
        print("        Verificá que los contenedores estén corriendo (docker compose up -d).")
        return

    show(logs, "LOGS DE AUTENTICACIÓN FALLIDA")
    show(alerts, "ALERTAS DE SEGURIDAD")
    print(f"\nResumen: {len(logs)} log(s) + {len(alerts)} alerta(s).")


if __name__ == "__main__":
    main()
