#!/usr/bin/env python3
"""Servicio knowledge: la memoria del Agente 2 (dueño de data/knowledge).

Guarda lo que el agente aprende con el uso — documentos de la organización,
casos resueltos y lecciones — y le arma al servicio analyst el contexto
relevante para cada incidente. Ver `memoria.py` para el porqué de cada pieza.

Nada de lo que expone ejecuta algo: guarda texto y lo devuelve. Una lección no
cambia ninguna acción ni ningún comando; solo le da contexto al análisis, y
solo después de que un analista la aprobó.

API (red interna, exige `X-Internal-Token`):
    GET  /v1/documents                     metadatos de los documentos
    POST /v1/documents                     {titulo, contenido, subido_por} → 201
    POST /v1/cases                         un caso resuelto (lo manda el gateway al decidir) → 201
    GET  /v1/lessons                       todas las lecciones, en cualquier estado
    POST /v1/lessons                       lección escrita por un analista → 201 (queda "propuesta")
    POST /v1/lessons/<leccion_id>/review   {decision: aprobar|rechazar, revisor} → 200
    POST /v1/context                       {incidents: [...]} → {incident_id: {lecciones, casos_similares, documentos}}
"""

from __future__ import annotations

from flask import jsonify

import memoria
from siem_servicios import crear_servicio, cuerpo_json

app = crear_servicio("knowledge")


def _error(mensaje: str, status: int = 400):
    return jsonify({"error": mensaje}), status


@app.errorhandler(memoria.ErrorDeMemoria)
def _dato_invalido(e: memoria.ErrorDeMemoria):
    return _error(str(e))


def _cuerpo() -> dict:
    datos = cuerpo_json()
    if datos is None:
        raise memoria.ErrorDeMemoria("se esperaba un cuerpo JSON")
    return datos


@app.get("/v1/documents")
def listar_documentos():
    return jsonify(memoria.listar_documentos())


@app.post("/v1/documents")
def agregar_documento():
    datos = _cuerpo()
    doc = memoria.agregar_documento(datos.get("titulo"), datos.get("contenido"),
                                    datos.get("subido_por"))
    return jsonify({"ok": True, "documento": doc}), 201


@app.post("/v1/cases")
def agregar_caso():
    caso, nuevas = memoria.agregar_caso(_cuerpo())
    return jsonify({"ok": True, "caso": caso, "lecciones_propuestas": nuevas}), 201


@app.get("/v1/lessons")
def listar_lecciones():
    return jsonify(memoria.listar_lecciones())


@app.post("/v1/lessons")
def proponer_leccion():
    datos = _cuerpo()
    leccion = memoria.proponer_leccion_manual(datos.get("texto"), datos.get("attack_type"),
                                              datos.get("ip"), datos.get("propuesta_por"))
    return jsonify({"ok": True, "leccion": leccion}), 201


@app.post("/v1/lessons/<leccion_id>/review")
def revisar_leccion(leccion_id: str):
    datos = _cuerpo()
    try:
        leccion = memoria.revisar_leccion(leccion_id, datos.get("decision"), datos.get("revisor"))
    except KeyError:
        return _error(f"no existe la lección '{leccion_id}'", 404)
    return jsonify({"ok": True, "leccion": leccion})


@app.post("/v1/context")
def contexto():
    datos = _cuerpo()
    if not isinstance(datos.get("incidents"), list):
        return _error("se esperaba {incidents: [...]}")
    return jsonify(memoria.contexto_para(datos["incidents"]))
