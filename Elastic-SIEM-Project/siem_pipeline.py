#!/usr/bin/env python3
"""
Orquestador del pipeline SIEM-IA: detección → análisis → acción.

Encadena las etapas en orden:
  1. prepare-for-ia.py  — extrae/limpia datos de Elasticsearch (si está arriba)
  2. classifier.py      — Agente 1, clasificación determinística
  3. siem_agent.py      — Agente 2, análisis LLM (con fallback)

Si Elasticsearch no está disponible, la etapa 1 falla de forma controlada y el
pipeline sigue usando el último `siem_clean.json` capturado (modo demo offline).
Al terminar, los incidentes quedan en `siem_incidents.json`, listos para que el
analista los supervise en el dashboard (dashboard.py).
"""

from __future__ import annotations

import subprocess
import sys

STEPS = [
    ("Extracción de datos del SIEM (prepare-for-ia.py)", [sys.executable, "prepare-for-ia.py"], True),
    ("Agente 1 — Clasificación determinística (classifier.py)", [sys.executable, "classifier.py"], False),
    ("Agente 2 — Análisis LLM (siem_agent.py)", [sys.executable, "siem_agent.py"], False),
]


def run() -> int:
    for title, cmd, tolerate_failure in STEPS:
        print(f"\n{'#'*64}\n# {title}\n{'#'*64}")
        # `check=False` explícito: el orquestador decide qué hacer con cada código
        # de salida según `tolerate_failure`, no delega en una excepción. Lo pedía
        # la regla W1510 de pylint-secure-coding-standard.
        #
        # Esta es la ÚNICA ejecución de procesos del sistema, y está en la
        # allowlist de tests/test_no_autonomy.py: comandos literales, sin shell y
        # sin ningún dato de log de por medio.
        result = subprocess.run(cmd, check=False)  # noqa: S603
        if result.returncode != 0:
            if tolerate_failure:
                print(f"[INFO] Etapa con error (código {result.returncode}); "
                      f"continúo con los datos existentes.")
                continue
            print(f"[ERROR] Etapa crítica falló (código {result.returncode}). Abortando.")
            return result.returncode

    print(f"\n{'='*64}")
    print("✅ Pipeline completo. Incidentes en 'siem_incidents.json'.")
    print("   Abrí el panel de supervisión con:  python3 dashboard.py")
    print(f"{'='*64}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
