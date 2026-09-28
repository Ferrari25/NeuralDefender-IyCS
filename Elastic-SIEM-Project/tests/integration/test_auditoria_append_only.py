"""El registro append-only de decisiones: lo que hoy garantiza y lo que no.

Es la propiedad que sostiene todo el discurso de supervisión humana del
proyecto ("cada decisión queda registrada de forma inmutable"). Estos tests
separan con precisión la parte que ya funciona de la parte que hoy es solo una
convención — para que la Fase 2 sepa exactamente qué tiene que construir.

Todos los hallazgos de auditoría están corregidos; sus regresiones viven en
`test_a01_reset_preserva_auditoria.py` (A-01) y `test_a02_a04_integridad.py`
(A-02, A-03, A-04). Este archivo conserva las invariantes de comportamiento del
registro, que se verifican en cada corrida independientemente de esos hallazgos.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import siem_lib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ─── Lo que SÍ está garantizado hoy ──────────────────────────────────────────

def test_el_archivo_solo_crece_nunca_se_reescribe(client, sandbox_con_incidentes):
    """Invariante central: los bytes previos jamás cambian."""
    ruta = sandbox_con_incidentes / "decisions.jsonl"
    inc = client.get("/api/incidents").get_json()["incidents"][0]

    instantaneas = []
    for act in inc["recommended_actions"]:
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": act["action_id"],
            "decision": "approved"})
        instantaneas.append(ruta.read_bytes())

    for previa, siguiente in zip(instantaneas, instantaneas[1:], strict=False):
        assert siguiente.startswith(previa), "se modificó contenido ya escrito"
    assert len(instantaneas[-1]) > len(instantaneas[0])


def test_revisar_una_decision_agrega_no_edita(client, sandbox_con_incidentes):
    """Cambiar de opinión deja las dos decisiones en el historial."""
    ruta = sandbox_con_incidentes / "decisions.jsonl"
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    act_id = inc["recommended_actions"][0]["action_id"]

    for decision in ("approved", "dismissed", "approved"):
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": act_id,
            "decision": decision})

    registros = siem_lib.read_jsonl(ruta)
    assert len(registros) == 3
    assert [r["decision"] for r in registros] == ["approved", "dismissed", "approved"]


def test_el_estado_es_replay_del_log(client):
    """El estado mostrado se reconstruye leyendo el log: gana la última decisión."""
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    act_id = inc["recommended_actions"][0]["action_id"]

    for decision in ("approved", "dismissed"):
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": act_id,
            "decision": decision})

    estado = client.get("/api/incidents").get_json()["incidents"][0]
    assert estado["recommended_actions"][0]["status"] == "dismissed"
    assert len(client.get("/api/decisions").get_json()) == 2


def test_el_estado_sobrevive_al_reinicio(client, app_dashboard, login,
                                         sandbox_con_incidentes):
    """Reiniciar el proceso no pierde nada: el estado vive en el archivo.

    Tras el reinicio hay que volver a autenticarse — que es justamente lo que se
    espera de un servidor que exige sesión (API-01): la cookie firmada no
    sobrevive a un cambio de SECRET_KEY ni a un almacén de usuarios distinto.
    """
    import importlib

    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"})

    importlib.reload(app_dashboard)
    app_dashboard.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    nuevo = app_dashboard.app.test_client()
    assert login(nuevo).status_code == 200

    accion = nuevo.get("/api/v1/incidents").get_json()["incidents"][0]["recommended_actions"][0]
    assert accion["status"] == "approved"
    assert accion["decided_by"] == "ana"
    assert accion["decided_at"] is not None


def test_cada_registro_conserva_el_contexto_del_momento(client):
    """El registro guarda las IPs, no solo el ID: sigue siendo legible aunque
    el incidente desaparezca de corridas futuras."""
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    r = client.post("/api/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"})

    registro = r.get_json()["record"]
    # API-01 sumó la identidad de la sesión: quién decidió, con qué rol, en qué
    # sesión y desde qué cliente.
    assert set(registro) == {"ts", "incident_id", "action_id", "decision",
                             "analyst", "analyst_rol", "session_id", "user_agent",
                             "note", "source_ip", "attacker_ips", "prev_hash"}
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", registro["ts"])
    assert registro["analyst"] == "ana" and registro["analyst_rol"] == "analyst"
    assert registro["session_id"], "cada decisión se atribuye a una sesión concreta"


def test_cada_linea_es_json_valido_e_independiente(client, sandbox_con_incidentes):
    """NDJSON real: una línea corrupta no debería arrastrar a las demás."""
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    for act in inc["recommended_actions"]:
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": act["action_id"],
            "decision": "dismissed", "note": "con acentos: clasificación"})

    crudo = (sandbox_con_incidentes / "decisions.jsonl").read_text(encoding="utf-8")
    assert crudo.endswith("\n")
    for linea in crudo.strip().split("\n"):
        assert json.loads(linea)["decision"] == "dismissed"
    assert "clasificación" in crudo


# ─── El pipeline tampoco pisa la auditoría ───────────────────────────────────

def test_el_pipeline_nunca_reescribe_analysis_history(sandbox_con_incidentes):
    """`siem_agent` agrega una línea por corrida; no reemplaza el historial."""
    ruta = sandbox_con_incidentes / "analysis_history.jsonl"
    siem_lib.append_jsonl(ruta, {"ts": "2026-09-16T10:00:00+00:00", "incident_count": 1})
    primera = ruta.read_bytes()

    entorno = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT), "GEMINI_API_KEY": ""}
    resultado = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "siem_agent.py")],
        cwd=sandbox_con_incidentes, capture_output=True, text=True, timeout=120,
        env=entorno, check=False,
    )
    assert resultado.returncode == 0, resultado.stderr

    assert ruta.read_bytes().startswith(primera)
    assert len(siem_lib.read_jsonl(ruta)) == 2
