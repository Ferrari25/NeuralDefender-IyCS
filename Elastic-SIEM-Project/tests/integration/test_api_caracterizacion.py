"""Caracterización de la API REST del dashboard (:5000).

Congela el contrato de comportamiento endpoint por endpoint. Todos los hallazgos
de API que estaban congelados acá ya están corregidos; sus regresiones viven en
`test_api_v1.py` (API-02 a API-05) y `test_api01_autenticacion.py` (API-01).
"""

from __future__ import annotations

import json

import pytest

# ─── GET / ───────────────────────────────────────────────────────────────────

def test_raiz_sirve_el_panel(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"<html" in r.data.lower()


# ─── GET /api/incidents ──────────────────────────────────────────────────────

def test_incidents_devuelve_la_captura(client):
    r = client.get("/api/incidents")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    assert len(r.get_json()["incidents"]) == 3


def test_incidents_sin_archivo_avisa_que_falta(client, sandbox_con_incidentes):
    """Sin corrida previa del pipeline, la API lo señala con `missing`."""
    (sandbox_con_incidentes / "data" / "siem_incidents.json").unlink()
    datos = client.get("/api/incidents").get_json()
    assert datos == {"incidents": [], "analyst_mode": None, "missing": True}


def test_incidents_arranca_todo_pendiente(client):
    for inc in client.get("/api/incidents").get_json()["incidents"]:
        for act in inc["recommended_actions"]:
            assert act["status"] == "pending"
            assert act["decided_by"] is None and act["decided_at"] is None


# ─── POST /api/decision ──────────────────────────────────────────────────────

def _una_accion(client):
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    return inc["incident_id"], inc["recommended_actions"][0]["action_id"]


def test_decision_aprobar_registra_y_persiste(client):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "approved", "note": "confirmado con el sysadmin"})

    assert r.status_code == 201, "crear un registro devuelve 201, no 200"
    registro = r.get_json()["record"]
    assert registro["decision"] == "approved"
    # API-01: el firmante sale de la sesión autenticada (fixture `client` = ana).
    assert registro["analyst"] == "ana"
    assert registro["analyst_rol"] == "analyst"
    assert registro["note"] == "confirmado con el sysadmin"
    assert registro["source_ip"] == "172.18.0.7"

    estado = client.get("/api/incidents").get_json()["incidents"][0]
    assert estado["recommended_actions"][0]["status"] == "approved"


@pytest.mark.parametrize("decision", ["execute", "run", "", None, "APPROVED"])
def test_decision_rechaza_valores_fuera_del_enum(client, decision):
    """Solo `approved` y `dismissed`. En particular, nada que suene a ejecutar."""
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/decision", json={
        "incident_id": inc_id, "action_id": act_id, "decision": decision})
    assert r.status_code == 400
    assert "decision inválida" in r.get_json()["error"]


def test_decision_exige_los_dos_ids(client):
    r = client.post("/api/decision", json={"decision": "approved"})
    assert r.status_code == 400
    assert "faltan incident_id / action_id" in r.get_json()["error"]


def test_decision_normaliza_la_nota(client):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "dismissed", "note": "   con espacios   "})
    assert r.get_json()["record"]["note"] == "con espacios"


def test_decision_sin_nota_queda_vacia(client):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/decision", json={
        "incident_id": inc_id, "action_id": act_id, "decision": "approved"})
    assert r.get_json()["record"]["note"] == ""


# ─── GET /api/decisions ──────────────────────────────────────────────────────

def test_decisions_arranca_vacio(client):
    assert client.get("/api/decisions").get_json() == []


def test_decisions_devuelve_el_log_crudo_completo(client):
    """La auditoría expone TODAS las revisiones, no solo la última."""
    inc_id, act_id = _una_accion(client)
    for decision in ("approved", "dismissed", "approved"):
        client.post("/api/decision", json={
            "incident_id": inc_id, "action_id": act_id, "decision": decision})

    historial = client.get("/api/decisions").get_json()
    assert [d["decision"] for d in historial] == ["approved", "dismissed", "approved"]


# ─── Superficie de ejecución: no existe, y así debe quedar ───────────────────

def test_la_api_no_expone_ninguna_ruta_de_ejecucion(client):
    """Certificación por enumeración: solo hay 4 rutas y ninguna ejecuta nada."""
    import dashboard

    rutas = {r.rule for r in dashboard.app.url_map.iter_rules()
             if r.endpoint != "static"}
    assert rutas == {
        "/", "/login",
        "/api/incidents", "/api/decision", "/api/decisions",
        "/api/v1/healthz", "/api/v1/incidents", "/api/v1/incidents/<incident_id>",
        "/api/v1/decision", "/api/v1/decisions", "/api/v1/audit/verify",
        "/api/v1/login", "/api/v1/logout", "/api/v1/me",
    }

    for sospechosa in ("/api/execute", "/api/run", "/api/contain", "/api/block",
                       "/api/action", "/api/v1/execute", "/api/v1/remediate"):
        assert client.post(sospechosa, json={}).status_code == 404


def test_aprobar_una_accion_solo_escribe_una_linea(client, sandbox_con_incidentes):
    """Aprobar registra una intención; no dispara nada ni toca otro archivo."""
    antes = {p.name for p in (sandbox_con_incidentes / "data").iterdir()}
    inc_id, act_id = _una_accion(client)
    client.post("/api/decision", json={
        "incident_id": inc_id, "action_id": act_id, "decision": "approved"})

    despues = {p.name for p in (sandbox_con_incidentes / "data").iterdir()}
    assert despues - antes == {"decisions.jsonl"}

    lineas = (sandbox_con_incidentes / "data" / "decisions.jsonl").read_text(
        encoding="utf-8").strip().split("\n")
    assert len(lineas) == 1
    assert json.loads(lineas[0])["decision"] == "approved"
