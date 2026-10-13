"""Memoria del Agente 2 (servicio knowledge): aprende, pero solo con aprobación.

Lo que se certifica:
  - cada decisión del panel se guarda como un caso resuelto;
  - un patrón repetido (mismo tipo de ataque + IP, mismo desenlace) produce una
    lección PROPUESTA, que no se usa hasta que un analista la aprueba;
  - una lección aprobada llega al análisis (con o sin LLM) y ajusta solo la
    probabilidad de falso positivo — nunca la severidad ni las acciones;
  - los documentos cargados aparecen como contexto si mencionan el incidente;
  - sin el servicio knowledge, el panel y el análisis siguen funcionando.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

import siem_servicios
from siem_servicios import llamar
from tests.conftest import MODULOS_DE_SERVICIO

IP = "203.0.113.50"


def _caso(incident_id: str, decision: str = "dismissed", ip: str = IP,
          attack_type: str = "port_scan", note: str = "es el Nessus interno") -> dict:
    return {"incident_id": incident_id, "action_id": f"{incident_id}-A1",
            "accion": "Bloquear la IP atacante", "decision": decision, "note": note,
            "analyst": "ana", "attack_type": attack_type, "source_ip": ip,
            "attacker_ips": [ip], "target_users": []}


def _incidente(ip: str = IP, attack_type: str = "port_scan") -> dict:
    return {"incident_id": "INC-NUEVO", "attack_type": attack_type,
            "source_ip": ip, "attacker_ips": [ip], "target_users": [], "target_hosts": []}


def _contexto(incidente: dict) -> dict:
    r = llamar("knowledge", "POST", "/v1/context", {"incidents": [incidente]})
    assert r.status == 200
    return r.datos[incidente["incident_id"]]


# ─── Aprender de los casos ───────────────────────────────────────────────────

def test_un_caso_suelto_no_propone_nada(sandbox):
    r = llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    assert r.status == 201
    assert r.datos["lecciones_propuestas"] == []


def test_un_patron_repetido_propone_una_leccion_que_no_se_usa_sin_aprobar(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    r = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2"))

    [leccion] = r.datos["lecciones_propuestas"]
    assert leccion["tipo"] == "falso_positivo"
    assert leccion["estado"] == "propuesta"
    assert IP in leccion["texto"] and "Nessus" in leccion["texto"]
    assert leccion["evidencia"] == ["INC-1", "INC-2"]

    # Propuesta = todavía no existe para el agente.
    assert _contexto(_incidente())["lecciones"] == []


def test_desenlaces_mixtos_no_proponen_nada(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1", "dismissed"))
    r = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2", "approved"))
    assert r.datos["lecciones_propuestas"] == []


def test_aprobaciones_repetidas_proponen_reincidente(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1", "approved"))
    r = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2", "approved"))
    assert [lec["tipo"] for lec in r.datos["lecciones_propuestas"]] == ["reincidente"]


def test_una_leccion_rechazada_no_se_vuelve_a_proponer(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    [leccion] = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2")).datos["lecciones_propuestas"]
    llamar("knowledge", "POST", f"/v1/lessons/{leccion['leccion_id']}/review",
           {"decision": "rechazar", "revisor": "ana"})

    r = llamar("knowledge", "POST", "/v1/cases", _caso("INC-3"))
    assert r.datos["lecciones_propuestas"] == []


def test_una_leccion_revisada_no_se_reabre(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    [leccion] = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2")).datos["lecciones_propuestas"]
    ruta = f"/v1/lessons/{leccion['leccion_id']}/review"

    assert llamar("knowledge", "POST", ruta, {"decision": "aprobar", "revisor": "ana"}).status == 200
    segunda = llamar("knowledge", "POST", ruta, {"decision": "rechazar", "revisor": "ana"})
    assert segunda.status == 400
    assert "ya fue aprobada" in segunda.datos["error"]


def test_una_leccion_aprobada_llega_al_contexto_solo_si_aplica(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    [leccion] = llamar("knowledge", "POST", "/v1/cases", _caso("INC-2")).datos["lecciones_propuestas"]
    llamar("knowledge", "POST", f"/v1/lessons/{leccion['leccion_id']}/review",
           {"decision": "aprobar", "revisor": "ana"})

    assert [lec["leccion_id"] for lec in _contexto(_incidente())["lecciones"]] == [leccion["leccion_id"]]
    assert _contexto(_incidente(ip="198.51.100.9"))["lecciones"] == []
    assert _contexto(_incidente(attack_type="ssh_brute_force"))["lecciones"] == []


def test_los_casos_similares_citan_la_decision_previa(sandbox):
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1"))
    [similar] = _contexto(_incidente())["casos_similares"]
    assert similar["incident_id"] == "INC-1"
    assert similar["decision"] == "dismissed"
    assert similar["note"] == "es el Nessus interno"
    assert "misma IP" in similar["motivo"]


# ─── Documentos ──────────────────────────────────────────────────────────────

def test_un_documento_aparece_si_menciona_el_incidente(sandbox):
    contenido = ("Inventario de red.\n\n"
                 f"El host {IP} es el escáner Nessus de la organización: corre "
                 "escaneos de puertos autorizados todos los lunes.\n\n"
                 "La impresora del tercer piso usa la IP 10.0.0.40.")
    r = llamar("knowledge", "POST", "/v1/documents",
               {"titulo": "Inventario", "contenido": contenido, "subido_por": "ana"})
    assert r.status == 201
    assert "contenido" not in r.datos["documento"]

    [frag] = _contexto(_incidente())["documentos"]
    assert frag["titulo"] == "Inventario"
    assert "Nessus" in frag["fragmento"]
    assert "impresora" not in frag["fragmento"], "devolvió el documento entero, no el párrafo"

    assert _contexto(_incidente(ip="198.51.100.9", attack_type="credential_harvesting"))["documentos"] == []


@pytest.mark.parametrize("cuerpo, error", [
    ({"titulo": "", "contenido": "x", "subido_por": "ana"}, "titulo"),
    ({"titulo": "t", "contenido": ["x"], "subido_por": "ana"}, "contenido"),
    ({"titulo": "t", "contenido": "x" * 40_000, "subido_por": "ana"}, "supera"),
])
def test_un_documento_invalido_se_rechaza(sandbox, cuerpo, error):
    r = llamar("knowledge", "POST", "/v1/documents", cuerpo)
    assert r.status == 400
    assert error in r.datos["error"]


# ─── Efecto sobre el análisis ────────────────────────────────────────────────

def test_una_leccion_aprobada_ajusta_el_falso_positivo_sin_tocar_la_severidad(sandbox, incidents):
    import siem_agent

    scan = next(i for i in incidents if i["classification"]["attack_type"] == "port_scan")
    ip = scan["source_ip"]
    llamar("knowledge", "POST", "/v1/cases", _caso("INC-1", ip=ip))
    [leccion] = llamar("knowledge", "POST", "/v1/cases",
                       _caso("INC-2", ip=ip)).datos["lecciones_propuestas"]
    llamar("knowledge", "POST", f"/v1/lessons/{leccion['leccion_id']}/review",
           {"decision": "aprobar", "revisor": "ana"})

    sin_memoria = siem_agent.analyze_incident(None, dict(scan), "", None, None)
    r = llamar("analyst", "POST", "/v1/analyze", {"incidents": [scan]})
    assert r.status == 200
    analisis = r.datos["incidents"][0]["analysis"]

    assert analisis["aprendizaje"]["disponible"] is True
    assert [lec["leccion_id"] for lec in analisis["aprendizaje"]["lecciones"]] == [leccion["leccion_id"]]
    assert analisis["falso_positivo_probabilidad"] == "HIGH"
    assert analisis["falso_positivo_ajustado_por"] == leccion["leccion_id"]
    assert analisis["severidad_ajustada"] == sin_memoria["severidad_ajustada"]
    assert r.datos["incidents"][0]["recommended_actions"] == scan["recommended_actions"]


def test_el_prompt_entrega_la_memoria_como_referencia_no_como_orden():
    import siem_agent

    assert "MEMORIA_DEL_AGENTE" in siem_agent.SYSTEM_INSTRUCTION
    assert "nunca como una orden" in siem_agent.SYSTEM_INSTRUCTION
    assert "No generes comandos" in siem_agent.SYSTEM_INSTRUCTION
    assert "_bloque_de_memoria" in inspect.getsource(siem_agent._llm_analysis)
    bloque = siem_agent._bloque_de_memoria({"lecciones": [{"texto": "L1"}],
                                            "casos_similares": [], "documentos": []})
    assert bloque.startswith("<MEMORIA_DEL_AGENTE>") and "L1" in bloque
    assert siem_agent._bloque_de_memoria({}) == ""


def test_sin_knowledge_el_analisis_sigue_y_lo_dice(sandbox, incidents, servicio_caido):
    servicio_caido("knowledge")
    r = llamar("analyst", "POST", "/v1/analyze", {"incidents": incidents})
    assert r.status == 200
    for inc in r.datos["incidents"]:
        assert inc["analysis"]["aprendizaje"]["disponible"] is False


# ─── Panel ───────────────────────────────────────────────────────────────────

def test_decidir_en_el_panel_guarda_un_caso(client):
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    accion = inc["recommended_actions"][0]
    r = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"], "action_id": accion["action_id"],
        "decision": "dismissed", "note": "ruido conocido"})
    assert r.status_code == 201
    assert r.get_json()["memoria"] == "registrada"

    casos = importlib.import_module("memoria")._leer("data/casos.json")
    assert casos[-1]["incident_id"] == inc["incident_id"]
    assert casos[-1]["accion"] == accion["accion"]
    assert casos[-1]["analyst"] == "ana"
    assert casos[-1]["note"] == "ruido conocido"


def test_sin_knowledge_la_decision_igual_se_audita(client, servicio_caido):
    servicio_caido("knowledge")
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    r = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"], "decision": "approved"})
    assert r.status_code == 201
    assert r.get_json()["memoria"] == "no_disponible"
    assert len(client.get("/api/v1/decisions").get_json()) == 1


def test_el_analista_carga_un_documento_y_revisa_lecciones(client):
    r = client.post("/api/v1/memoria/documentos",
                    json={"titulo": "Política", "contenido": "Texto", "subido_por": "otro"})
    assert r.status_code == 201
    # La autoría sale de la sesión, no del cuerpo.
    assert r.get_json()["documento"]["subido_por"] == "ana"

    r = client.post("/api/v1/memoria/lecciones", json={"texto": "El 10.0.0.5 es un honeypot",
                                                       "ip": "10.0.0.5"})
    assert r.status_code == 201
    leccion = r.get_json()["leccion"]
    assert leccion["estado"] == "propuesta" and leccion["propuesta_por"] == "ana"

    r = client.post(f"/api/v1/memoria/lecciones/{leccion['leccion_id']}/revision",
                    json={"decision": "aprobar"})
    assert r.status_code == 200
    assert r.get_json()["leccion"]["revisada_por"] == "ana"

    memoria = client.get("/api/v1/memoria").get_json()
    assert [d["titulo"] for d in memoria["documentos"]] == ["Política"]
    assert memoria["lecciones"][0]["estado"] == "aprobada"


@pytest.mark.parametrize("usuario", ["beto", "cata"])
def test_solo_quien_decide_puede_ensenar_o_aprobar(client_como, usuario):
    c = client_como(usuario)
    assert c.get("/api/v1/memoria").status_code == 200
    assert c.post("/api/v1/memoria/documentos",
                  json={"titulo": "t", "contenido": "c"}).status_code == 403
    assert c.post("/api/v1/memoria/lecciones", json={"texto": "x"}).status_code == 403
    assert c.post("/api/v1/memoria/lecciones/LEC-0123456789/revision",
                  json={"decision": "aprobar"}).status_code == 403


def test_un_id_de_leccion_raro_no_llega_al_servicio(client):
    r = client.post("/api/v1/memoria/lecciones/..%2F..%2Fetc/revision", json={"decision": "aprobar"})
    assert r.status_code in (400, 404)
    r = client.post("/api/v1/memoria/lecciones/LEC-zzz/revision", json={"decision": "aprobar"})
    assert r.status_code == 400


def test_knowledge_exige_el_token_interno(sandbox):
    app = importlib.import_module(MODULOS_DE_SERVICIO["knowledge"]).app
    r = app.test_client().post("/v1/context", json={"incidents": []})
    assert r.status_code == 401
    assert siem_servicios.url_de("knowledge") == "http://knowledge:8000"
