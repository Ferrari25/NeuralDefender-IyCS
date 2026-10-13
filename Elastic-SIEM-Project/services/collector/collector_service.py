#!/usr/bin/env python3
"""Servicio collector: el único que habla con Elasticsearch.

Es el único contenedor con credenciales de Elasticsearch y el único conectado a
la red del stack Elastic. Guarda la última captura buena en su propio volumen.

API (red interna, exige `X-Internal-Token`):
    POST /v1/snapshots          captura ahora → 201 + captura
                                → 503 si Elasticsearch no responde (la anterior se conserva)
    GET  /v1/snapshots/latest   última captura guardada → 200 · 404 si nunca hubo una
"""

from __future__ import annotations

from pathlib import Path

from flask import jsonify

from collector import OUTPUT_FILE, capturar
from es_client import ESInsecureTransport, ESUnavailable
from siem_lib import load_json, write_json
from siem_servicios import crear_servicio

app = crear_servicio("collector")


@app.post("/v1/snapshots")
def nueva_captura():
    try:
        captura = capturar()
    except (ESUnavailable, ESInsecureTransport) as e:
        # No se sobreescribe la captura anterior: sigue siendo la última buena.
        return jsonify({"error": str(e),
                        "hay_captura_previa": Path(OUTPUT_FILE).exists()}), 503
    write_json(OUTPUT_FILE, captura)
    return jsonify({"ok": True, "snapshot": captura}), 201


@app.get("/v1/snapshots/latest")
def ultima_captura():
    if not Path(OUTPUT_FILE).exists():
        return jsonify({"error": "todavía no hay ninguna captura del SIEM"}), 404
    return jsonify({"snapshot": load_json(OUTPUT_FILE)})
