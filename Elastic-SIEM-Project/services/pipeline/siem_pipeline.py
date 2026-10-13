#!/usr/bin/env python3
"""
CLI del pipeline SIEM-IA: dispara un ciclo detección → análisis y muestra el resultado.

Le pide el ciclo al servicio pipeline por HTTP en vez de correrlo en este
proceso: así el servicio sigue siendo el único que escribe el reporte, y dos
disparos simultáneos (este CLI y otro) no pueden pisarse — el segundo recibe un
409 en vez de corromper el archivo.

Uso (dentro del contenedor del pipeline, o con el atajo):
    docker compose exec pipeline python siem_pipeline.py
    ./scripts/siem.sh pipeline

Códigos de salida:  0 = ciclo completo · 1 = falló una etapa crítica o el servicio no responde
"""

from __future__ import annotations

import sys

from siem_servicios import ServicioNoDisponible, llamar

# Tope del ciclo completo. Holgado: con el LLM encendido, el análisis hace una
# llamada a Gemini por incidente.
TIMEOUT_CICLO = 900


def run() -> int:
    print("▶ Ciclo de análisis: collector → classifier → analyst → audit")
    try:
        r = llamar("pipeline", "POST", "/v1/cycles", timeout=TIMEOUT_CICLO)
    except ServicioNoDisponible as e:
        print(f"[ERROR] {e}. ¿Está levantado? (docker compose up -d)")
        return 1

    if not r.ok:
        print(f"[ERROR] {(r.datos or {}).get('error', f'HTTP {r.status}')}")
        return 1

    for etapa in r.datos["etapas"]:
        motivo = f" — {etapa['motivo']}" if etapa.get("motivo") else ""
        print(f"  · {etapa['etapa']:<11} {etapa['estado']}{motivo}")

    report = r.datos["report"]
    print(f"\n{'=' * 64}")
    print(f"✅ Pipeline completo: {report['incident_count']} incidente(s), "
          f"análisis en modo {report['analyst_mode']}.")
    for inc in report["incidents"]:
        sev = (inc.get("analysis") or {}).get("severidad_ajustada", "?")
        print(f"   • {inc['incident_id']}  [{sev}]  {inc['classification']['attack_type']}")
    print("   Abrí el panel de supervisión:  http://127.0.0.1:5000/login")
    print(f"{'=' * 64}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
