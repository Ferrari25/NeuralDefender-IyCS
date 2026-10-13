#!/usr/bin/env python3
"""Servicio analyst (Agente 2): explicación en lenguaje claro, sin estado.

Es el único contenedor con `GEMINI_API_KEY` y el interruptor `SIEM_USE_LLM`.
Sin key, con el interruptor apagado o sin red, usa el análisis determinístico
de respaldo: siempre responde.

API (red interna, exige `X-Internal-Token`):
    POST /v1/analyze   {incidents: [...]} → 200 {incidents, analyzed_at, analyst_mode}
                       → 503 si el servicio audit no responde

Antes de analizar le pide al servicio knowledge la memoria del agente para
cada incidente (lecciones aprobadas, casos similares, documentos).

**Por qué un audit caído es un error y no "sin antecedentes".** El contexto
histórico ("ya se bloqueó esta IP antes") es un hecho auditable que el panel le
muestra al analista. Responder "es la primera vez que se ve esta IP" porque no
se pudo consultar el registro sería afirmar algo falso. Preferimos que la
corrida falle de forma visible.

**Por qué un knowledge caído NO es un error.** La memoria mejora el análisis,
pero no es un hecho que el panel afirme: sin ella, el análisis es el mismo que
antes de que existiera. Cada incidente queda marcado con
`aprendizaje.disponible = false`, así el panel dice "sin memoria" en vez de
"no hay nada que recordar".
"""

from __future__ import annotations

from flask import jsonify

from siem_agent import analizar
from siem_servicios import ServicioNoDisponible, crear_servicio, cuerpo_json, llamar

app = crear_servicio("analyst")


def _decisiones_previas() -> list[dict]:
    respuesta = llamar("audit", "GET", "/v1/decisions")
    if not respuesta.ok or not isinstance(respuesta.datos, list):
        raise ServicioNoDisponible(
            f"el servicio audit respondió {respuesta.status} al pedir las decisiones")
    return respuesta.datos


def _memoria_del_agente(incidents: list[dict]) -> dict[str, dict] | None:
    """Contexto del servicio knowledge por incidente, o `None` si no respondió."""
    resumen = [{
        "incident_id": inc.get("incident_id"),
        "attack_type": (inc.get("classification") or {}).get("attack_type"),
        "source_ip": inc.get("source_ip"),
        "attacker_ips": inc.get("attacker_ips") or [],
        "target_users": inc.get("target_users") or [],
        "target_hosts": inc.get("target_hosts") or [],
    } for inc in incidents]
    try:
        respuesta = llamar("knowledge", "POST", "/v1/context", {"incidents": resumen})
    except ServicioNoDisponible as e:
        print(f"[WARN] Sin memoria del agente: {e}. Se analiza sin ella.")
        return None
    if not respuesta.ok or not isinstance(respuesta.datos, dict):
        print(f"[WARN] Sin memoria del agente: knowledge respondió {respuesta.status}.")
        return None
    return respuesta.datos


@app.post("/v1/analyze")
def analizar_incidentes():
    datos = cuerpo_json()
    if datos is None or not isinstance(datos.get("incidents"), list):
        return jsonify({"error": "se esperaba {incidents: [...]}"}), 400
    try:
        decisiones = _decisiones_previas()
    except ServicioNoDisponible as e:
        return jsonify({"error": f"sin acceso a los antecedentes: {e}"}), 503
    memoria = _memoria_del_agente(datos["incidents"])
    return jsonify(analizar(datos["incidents"], decisiones, memoria))
