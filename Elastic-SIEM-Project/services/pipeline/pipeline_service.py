#!/usr/bin/env python3
"""Servicio pipeline: orquesta el análisis y es dueño del reporte de incidentes.

API (red interna, exige `X-Internal-Token`):
    POST /v1/cycles                  corre un ciclo completo → 200 {report, etapas}
                                     → 409 si ya hay uno en curso · 502 si falla una etapa crítica
    GET  /v1/incidents               último reporte → 200 · 404 {missing: true} si no hay
    GET  /v1/incidents/<incident_id> un incidente → 200 · 404

El reporte que sirve es el que dejó el pipeline: SIN el estado de las
decisiones. Ese estado lo arma el gateway combinándolo con el registro del
servicio audit, porque la auditoría no es de este servicio.
"""

from __future__ import annotations

from pathlib import Path

from flask import jsonify

from orquestador import INCIDENTS_FILE, CicloEnCurso, ErrorDeEtapa, ejecutar_ciclo
from siem_lib import load_json
from siem_servicios import crear_servicio

app = crear_servicio("pipeline")


@app.post("/v1/cycles")
def nuevo_ciclo():
    try:
        return jsonify(ejecutar_ciclo())
    except CicloEnCurso as e:
        return jsonify({"error": str(e)}), 409
    except ErrorDeEtapa as e:
        return jsonify({"error": str(e)}), 502


@app.get("/v1/incidents")
def incidentes():
    if not Path(INCIDENTS_FILE).exists():
        return jsonify({"error": "todavía no hay incidentes analizados", "missing": True}), 404
    return jsonify(load_json(INCIDENTS_FILE))


@app.get("/v1/incidents/<incident_id>")
def incidente(incident_id: str):
    if Path(INCIDENTS_FILE).exists():
        for inc in load_json(INCIDENTS_FILE).get("incidents", []):
            if inc.get("incident_id") == incident_id:
                return jsonify(inc)
    return jsonify({"error": f"incidente '{incident_id}' no encontrado"}), 404
