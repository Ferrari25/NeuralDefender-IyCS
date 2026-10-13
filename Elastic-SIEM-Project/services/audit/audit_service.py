#!/usr/bin/env python3
"""Servicio de auditoría: único dueño de los registros append-only.

Expone los dos registros encadenados por hash del sistema:

  - `decisions.jsonl`        — cada aprobación/descarte de un analista.
  - `analysis_history.jsonl` — cada corrida del pipeline de análisis.
  - `actividad.jsonl`        — lo que los analistas hacen con la memoria del
                               Agente 2 (documentos, lecciones).

Además arma los reportes (`reportes.py`): una vista de solo lectura de esos
registros, con la verificación de su cadena incluida.

Antes, el panel y el Agente 2 escribían estos archivos directamente. Ahora los
demás servicios le mandan el registro por HTTP y este servicio es el único que
abre los archivos para escribir. El sello de tiempo (`ts`) lo pone este
servicio, no quien llama: el momento en que algo quedó registrado es un hecho
del registro, no un dato que el cliente pueda elegir.

**No expone ninguna operación de modificación ni borrado.** Solo agregar, leer
y verificar.

API (red interna, exige `X-Internal-Token`):
    POST /v1/decisions                    agrega una decisión → 201 + registro escrito
    GET  /v1/decisions                    todas las decisiones (tolera líneas corruptas)
    GET  /v1/decisions/verify             estado de la cadena de hashes
    POST /v1/analysis-history             agrega una corrida del pipeline → 201
    GET  /v1/analysis-history/verify      estado de la cadena del historial
    POST /v1/activity                     agrega un evento de la memoria del agente → 201
    GET  /v1/activity                     todos los eventos de memoria
    GET  /v1/activity/verify              estado de la cadena de actividad
    GET  /v1/reports?desde=&hasta=&formato=json|csv
                                          reporte del período (CSV viaja como {"csv": "..."})
"""

from __future__ import annotations

from flask import jsonify, request

import reportes
from cadena import append_jsonl, read_jsonl, verificar_cadena
from siem_lib import now_iso
from siem_servicios import crear_servicio, cuerpo_json

DECISIONS_FILE = "data/decisions.jsonl"
HISTORY_FILE = "data/analysis_history.jsonl"
ACTIVIDAD_FILE = reportes.ACTIVIDAD_FILE

DECISIONES_VALIDAS = ("approved", "dismissed")
MAX_NOTE_LEN = 500

# Lista blanca de campos de una decisión. El panel ya valida lo que recibe del
# navegador; esto es la segunda barrera, del lado de quien escribe un registro
# que después no se puede corregir. Un campo desconocido se rechaza, no se
# descarta en silencio.
CAMPOS_DECISION = frozenset({
    "incident_id", "action_id", "decision", "analyst", "analyst_rol",
    "session_id", "user_agent", "note", "source_ip", "attacker_ips",
    # Contexto del incidente AL MOMENTO de decidir, para los reportes: el
    # incidente puede no existir en corridas futuras, y el registro es lo único
    # que queda. Nunca el comando: el registro guarda qué se decidió, no qué
    # ejecutar.
    "accion", "attack_type", "severidad", "falso_positivo", "detection_source",
})
CAMPOS_OBLIGATORIOS = ("incident_id", "action_id", "decision", "analyst")

CAMPOS_CORRIDA = frozenset({"analyst_mode", "incident_count", "incident_ids"})

EVENTOS_DE_ACTIVIDAD = ("documento_cargado", "leccion_propuesta",
                        "leccion_aprobada", "leccion_rechazada")
CAMPOS_ACTIVIDAD = frozenset({"evento", "actor", "actor_rol", "leccion_id", "doc_id",
                              "detalle", "attack_type", "ip"})
MAX_DETALLE_LEN = 500

app = crear_servicio("audit")


def _error(mensaje: str, status: int = 400):
    return jsonify({"error": mensaje}), status


def _validar_decision(datos: dict) -> str | None:
    """Devuelve el motivo de rechazo, o `None` si la decisión es válida."""
    sobrantes = set(datos) - CAMPOS_DECISION
    if sobrantes:
        return f"campos no permitidos: {', '.join(sorted(sobrantes))}"
    for campo in CAMPOS_OBLIGATORIOS:
        valor = datos.get(campo)
        if not isinstance(valor, str) or not valor.strip():
            return f"falta o es inválido '{campo}'"
    if datos["decision"] not in DECISIONES_VALIDAS:
        return "decision inválida (approved|dismissed)"
    note = datos.get("note", "")
    if not isinstance(note, str):
        return "note debe ser texto"
    if len(note) > MAX_NOTE_LEN:
        return f"note supera {MAX_NOTE_LEN} caracteres ({len(note)})"
    ips = datos.get("attacker_ips", [])
    if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
        return "attacker_ips debe ser una lista de textos"
    for campo in ("accion", "attack_type", "severidad", "falso_positivo", "detection_source"):
        valor = datos.get(campo)
        if valor is not None and (not isinstance(valor, str) or len(valor) > 300):
            return f"'{campo}' debe ser texto de hasta 300 caracteres"
    return None


def _validar_actividad(datos: dict) -> str | None:
    sobrantes = set(datos) - CAMPOS_ACTIVIDAD
    if sobrantes:
        return f"campos no permitidos: {', '.join(sorted(sobrantes))}"
    if datos.get("evento") not in EVENTOS_DE_ACTIVIDAD:
        return f"evento inválido ({'|'.join(EVENTOS_DE_ACTIVIDAD)})"
    actor = datos.get("actor")
    if not isinstance(actor, str) or not actor.strip():
        return "falta o es inválido 'actor'"
    for campo in CAMPOS_ACTIVIDAD - {"evento", "actor"}:
        valor = datos.get(campo)
        if valor is not None and (not isinstance(valor, str) or len(valor) > MAX_DETALLE_LEN):
            return f"'{campo}' debe ser texto de hasta {MAX_DETALLE_LEN} caracteres"
    return None


@app.post("/v1/decisions")
def agregar_decision():
    datos = cuerpo_json()
    if datos is None:
        return _error("se esperaba un cuerpo JSON")
    motivo = _validar_decision(datos)
    if motivo:
        return _error(motivo)
    escrito = append_jsonl(DECISIONS_FILE, {"ts": now_iso(), **datos})
    return jsonify({"ok": True, "record": escrito}), 201


@app.get("/v1/decisions")
def listar_decisiones():
    # `tolerante`: una línea corrupta marca ese registro pero no deja sin datos
    # al panel. La integridad se comprueba aparte, en /v1/decisions/verify.
    return jsonify(read_jsonl(DECISIONS_FILE, tolerante=True))


@app.get("/v1/decisions/verify")
def verificar_decisiones():
    return jsonify(verificar_cadena(DECISIONS_FILE))


@app.post("/v1/analysis-history")
def agregar_corrida():
    datos = cuerpo_json()
    if datos is None:
        return _error("se esperaba un cuerpo JSON")
    sobrantes = set(datos) - CAMPOS_CORRIDA
    if sobrantes:
        return _error(f"campos no permitidos: {', '.join(sorted(sobrantes))}")
    if not isinstance(datos.get("analyst_mode"), str):
        return _error("falta 'analyst_mode'")
    escrito = append_jsonl(HISTORY_FILE, {"ts": now_iso(), **datos})
    return jsonify({"ok": True, "record": escrito}), 201


@app.get("/v1/analysis-history/verify")
def verificar_historial():
    return jsonify(verificar_cadena(HISTORY_FILE))


@app.post("/v1/activity")
def agregar_actividad():
    datos = cuerpo_json()
    if datos is None:
        return _error("se esperaba un cuerpo JSON")
    motivo = _validar_actividad(datos)
    if motivo:
        return _error(motivo)
    escrito = append_jsonl(ACTIVIDAD_FILE, {"ts": now_iso(), **datos})
    return jsonify({"ok": True, "record": escrito}), 201


@app.get("/v1/activity")
def listar_actividad():
    return jsonify(read_jsonl(ACTIVIDAD_FILE, tolerante=True))


@app.get("/v1/activity/verify")
def verificar_actividad():
    return jsonify(verificar_cadena(ACTIVIDAD_FILE))


@app.get("/v1/reports")
def reporte():
    formato = request.args.get("formato", "json")
    if formato not in reportes.FORMATOS:
        return _error(f"formato inválido ({'|'.join(reportes.FORMATOS)})")
    try:
        datos = reportes.armar_reporte(request.args.get("desde"), request.args.get("hasta"))
    except reportes.PeriodoInvalido as e:
        return _error(str(e))
    if formato == "csv":
        return jsonify({"csv": reportes.a_csv(datos), "periodo": datos["periodo"]})
    return jsonify(datos)
