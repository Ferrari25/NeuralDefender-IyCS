"""Contrato de la API `/api/v1/` — hallazgos **API-02 … API-05**.

Lo que cambió en la Fase 2:

- **API-02** — validación de entrada: `note` acotada a 500 caracteres, tipos
  verificados, `MAX_CONTENT_LENGTH`, y **todos** los errores de `/api/` en JSON
  (antes un cuerpo malformado devolvía el HTML de Werkzeug a un `fetch()`).
- **API-03** — una sola ruta de lectura de `siem_incidents.json`; el POST ya no
  reparsea el archivo entero por su cuenta.
- **API-04** — una decisión sobre un `action_id` inexistente se rechaza con 404.
  Antes se escribía en el registro inmutable, que después no se puede corregir.
- **API-05** — rutas versionadas, `Cache-Control: no-store`, `/healthz`, y
  `/audit/verify` para consultar la integridad de la cadena.

**API-01 (autenticación) sigue abierto**: es trabajo de la Fase 3, y su test
congelado continúa en `test_api_caracterizacion.py`.
"""

from __future__ import annotations

import json

import pytest

import siem_lib


def _una_accion(client):
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    return inc["incident_id"], inc["recommended_actions"][0]["action_id"]


# ─── API-05 · versionado, salud y caché ──────────────────────────────────────

def test_healthz_responde_sin_datos_sensibles(client):
    r = client.get("/api/v1/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok", "incidents_file": True}


def test_healthz_funciona_sin_corrida_previa(client, sandbox_con_incidentes):
    """Sirve para esperar al server aunque el pipeline no haya corrido."""
    (sandbox_con_incidentes / "siem_incidents.json").unlink()
    r = client.get("/api/v1/healthz")
    assert r.status_code == 200
    assert r.get_json()["incidents_file"] is False


@pytest.mark.parametrize("ruta", ["/api/v1/incidents", "/api/v1/decisions"])
def test_los_datos_en_vivo_no_se_cachean(client, ruta):
    assert client.get(ruta).headers["Cache-Control"] == "no-store"


def test_la_verificacion_de_cadena_tampoco_se_cachea(client_como):
    """`/audit/verify` requiere el rol auditor (ver test_api01_autenticacion.py)."""
    auditor = client_como("cata")
    assert auditor.get("/api/v1/audit/verify").headers["Cache-Control"] == "no-store"


def test_las_rutas_sin_versionar_siguen_funcionando(client):
    """Compatibilidad: el panel actual todavía usa `/api/incidents`."""
    assert client.get("/api/incidents").status_code == 200
    assert client.get("/api/decisions").status_code == 200


def test_las_dos_rutas_devuelven_lo_mismo(client):
    """Son dos nombres para la misma función, no dos implementaciones."""
    assert client.get("/api/incidents").get_json() == \
        client.get("/api/v1/incidents").get_json()


def test_incidente_puntual_por_id(client):
    inc_id, _ = _una_accion(client)
    r = client.get(f"/api/v1/incidents/{inc_id}")
    assert r.status_code == 200
    assert r.get_json()["incident_id"] == inc_id


def test_incidente_inexistente_da_404_en_json(client):
    r = client.get("/api/v1/incidents/INC-NO-EXISTE")
    assert r.status_code == 404
    assert r.mimetype == "application/json"
    assert "no encontrado" in r.get_json()["error"]


# ─── API-02 · validación de entrada y errores en JSON ────────────────────────

def test_un_cuerpo_malformado_devuelve_json(client):
    """Antes llegaba el HTML de Werkzeug a un cliente que iba a hacer .json()."""
    r = client.post("/api/v1/decision", data="{esto no es json",
                    content_type="application/json")
    assert r.status_code == 400
    assert r.mimetype == "application/json"
    assert "JSON" in r.get_json()["error"]


def test_un_cuerpo_que_no_es_objeto_se_rechaza(client):
    for cuerpo in ("[]", '"texto"', "42", "null"):
        r = client.post("/api/v1/decision", data=cuerpo,
                        content_type="application/json")
        assert r.status_code == 400
        assert r.mimetype == "application/json"


def test_la_nota_tiene_tope(client):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "approved", "note": "A" * 501})
    assert r.status_code == 400
    assert "supera 500" in r.get_json()["error"]


def test_la_nota_en_el_limite_se_acepta(client):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "approved", "note": "A" * 500})
    assert r.status_code == 201


def test_un_cuerpo_enorme_se_rechaza(client):
    """`MAX_CONTENT_LENGTH`: el server ni siquiera lo parsea."""
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "approved", "note": "A" * 200_000})
    assert r.status_code in (400, 413)


@pytest.mark.parametrize("campo,valor", [
    ("note", 42), ("note", []), ("note", {}),
    ("incident_id", 42), ("incident_id", None), ("incident_id", ""),
    ("action_id", []), ("action_id", ""),
])
def test_los_tipos_se_verifican(client, campo, valor):
    inc_id, act_id = _una_accion(client)
    cuerpo = {"incident_id": inc_id, "action_id": act_id, "decision": "approved"}
    cuerpo[campo] = valor
    assert client.post("/api/v1/decision", json=cuerpo).status_code == 400


@pytest.mark.parametrize("decision", [
    "execute", "run", "contain", "block", "", None, "APPROVED", 1, True,
])
def test_solo_se_aceptan_approved_y_dismissed(client, decision):
    """En particular, nada que suene a ejecutar una acción."""
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id, "decision": decision})
    assert r.status_code == 400


# ─── API-04 · no se audita lo que no existe ──────────────────────────────────

def test_un_action_id_inexistente_da_404(client, sandbox_con_incidentes):
    inc_id, _ = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": f"{inc_id}-inventado",
        "decision": "approved"})

    assert r.status_code == 404
    assert not (sandbox_con_incidentes / "decisions.jsonl").exists(), \
        "no se escribió nada en el registro inmutable"


def test_un_incidente_inexistente_da_404(client, sandbox_con_incidentes):
    r = client.post("/api/v1/decision", json={
        "incident_id": "INC-INVENTADO-000", "action_id": "INC-INVENTADO-000-a1",
        "decision": "approved"})
    assert r.status_code == 404
    assert not (sandbox_con_incidentes / "decisions.jsonl").exists()


def test_no_se_puede_cruzar_una_accion_a_otro_incidente(client, sandbox_con_incidentes):
    """Un `action_id` válido pero de OTRO incidente también se rechaza.

    Si no, el registro diría que se aprobó una acción para un incidente que
    nunca la tuvo.
    """
    incidentes = client.get("/api/v1/incidents").get_json()["incidents"]
    ajeno = incidentes[1]["recommended_actions"][0]["action_id"]

    r = client.post("/api/v1/decision", json={
        "incident_id": incidentes[0]["incident_id"], "action_id": ajeno,
        "decision": "approved"})
    assert r.status_code == 404
    assert not (sandbox_con_incidentes / "decisions.jsonl").exists()


# ─── El camino feliz, con la cadena de auditoría ─────────────────────────────

def test_una_decision_valida_se_registra_y_encadena(client, sandbox_con_incidentes):
    inc_id, act_id = _una_accion(client)
    r = client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id,
        "decision": "approved", "note": "verificado con el sysadmin"})

    assert r.status_code == 201
    registro = r.get_json()["record"]
    assert registro["prev_hash"] == siem_lib.GENESIS_HASH
    assert registro["note"] == "verificado con el sysadmin"

    estado = client.get("/api/v1/incidents").get_json()["incidents"][0]
    assert estado["recommended_actions"][0]["status"] == "approved"


def test_audit_verify_refleja_el_estado_de_la_cadena(client, client_como):
    auditor = client_como("cata")
    assert auditor.get("/api/v1/audit/verify").get_json()["chain_ok"] is True

    inc_id, act_id = _una_accion(client)
    for decision in ("approved", "dismissed"):
        client.post("/api/v1/decision", json={
            "incident_id": inc_id, "action_id": act_id, "decision": decision})

    resultado = auditor.get("/api/v1/audit/verify").get_json()
    assert resultado["chain_ok"] is True
    assert resultado["records"] == 2


def test_audit_verify_denuncia_una_manipulacion(client, client_como,
                                                sandbox_con_incidentes):
    """El panel puede mostrar que su propia auditoría fue alterada."""
    auditor = client_como("cata")
    ruta = sandbox_con_incidentes / "decisions.jsonl"
    inc_id, act_id = _una_accion(client)
    for _ in range(3):
        client.post("/api/v1/decision", json={
            "incident_id": inc_id, "action_id": act_id, "decision": "approved"})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    falsificado = json.loads(lineas[0])
    falsificado["decision"] = "dismissed"
    lineas[0] = json.dumps(falsificado, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    resultado = auditor.get("/api/v1/audit/verify").get_json()
    assert resultado["chain_ok"] is False
    assert resultado["first_broken"] == 2


# ─── Robustez del panel (hallazgo nuevo de la Fase 0) ────────────────────────

def test_una_linea_corrupta_no_tumba_el_panel(client, client_como,
                                              sandbox_con_incidentes):
    """Antes, un byte dañado en `decisions.jsonl` dejaba el panel sin arrancar.

    La lectura es tolerante; la integridad se reporta aparte, en `/audit/verify`.
    """
    ruta = sandbox_con_incidentes / "decisions.jsonl"
    inc_id, act_id = _una_accion(client)
    client.post("/api/v1/decision", json={
        "incident_id": inc_id, "action_id": act_id, "decision": "approved"})

    with open(ruta, "a", encoding="utf-8") as f:
        f.write("{linea corrupta\n")

    assert client.get("/api/v1/incidents").status_code == 200
    assert client.get("/api/v1/decisions").status_code == 200
    assert client_como("cata").get("/api/v1/audit/verify").get_json()["chain_ok"] is False
