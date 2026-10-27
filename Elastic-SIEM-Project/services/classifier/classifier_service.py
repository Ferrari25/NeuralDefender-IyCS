#!/usr/bin/env python3
"""Servicio classifier (Agente 1): clasificación determinística, sin estado.

No guarda nada. Recibe la captura del SIEM y devuelve los incidentes con su
clasificación, su playbook de comandos fijos y la correlación de campañas.

Los eventos de red/web los lee de `network_logs/`, montado en SOLO LECTURA: es
el mismo directorio que Filebeat envía a Elasticsearch, el punto donde un IDS
real escribiría sus eventos.

API (red interna, exige `X-Internal-Token`):
    POST /v1/classify   {siem_data: {...}}  → 200 reporte {generated_at, incident_count, incidents}
"""

from __future__ import annotations

import os

from flask import jsonify

from classifier import reporte
from siem_lib import read_network_logs, ventana_de_analisis, ventana_en_horas
from siem_servicios import crear_servicio, cuerpo_json

NETWORK_LOGS_DIR = os.getenv("SIEM_NETWORK_LOGS_DIR", "network_logs")
# La misma ventana que usa el collector contra Elasticsearch (SIEM_VENTANA).
VENTANA_HORAS = ventana_en_horas(ventana_de_analisis())

app = crear_servicio("classifier")


@app.post("/v1/classify")
def clasificar():
    datos = cuerpo_json()
    if datos is None:
        return jsonify({"error": "se esperaba un cuerpo JSON"}), 400
    siem_data = datos.get("siem_data") or {}
    if not isinstance(siem_data, dict):
        return jsonify({"error": "siem_data debe ser un objeto"}), 400
    return jsonify(reporte(siem_data, read_network_logs(NETWORK_LOGS_DIR, VENTANA_HORAS)))
