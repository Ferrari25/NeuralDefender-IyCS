"""Contratos de la malla de microservicios.

Lo que la migración agregó y que ninguna prueba anterior podía cubrir: el token
interno, la tolerancia a fallos de cada etapa del ciclo, la segunda barrera de
validación del servicio de auditoría, y qué pasa en el panel cuando un servicio
interno se cae. Todo corre en proceso (ver `malla_en_proceso` en conftest).
"""

from __future__ import annotations

import importlib

import pytest

import siem_servicios
from tests.conftest import MODULOS_DE_SERVICIO, TOKEN_INTERNO_DE_PRUEBA

TOKEN = {siem_servicios.ENCABEZADO_TOKEN: TOKEN_INTERNO_DE_PRUEBA}


def _app(servicio: str):
    return importlib.import_module(MODULOS_DE_SERVICIO[servicio]).app


# ─── Token interno ───────────────────────────────────────────────────────────

RUTA_PROTEGIDA = {
    "auth": ("GET", "/v1/users-summary"),
    "audit": ("GET", "/v1/decisions"),
    "collector": ("GET", "/v1/snapshots/latest"),
    "classifier": ("POST", "/v1/classify"),
    "analyst": ("POST", "/v1/analyze"),
    "pipeline": ("GET", "/v1/incidents"),
    "knowledge": ("GET", "/v1/lessons"),
}


@pytest.mark.parametrize("servicio", sorted(RUTA_PROTEGIDA))
def test_sin_token_interno_no_se_atiende(servicio, sandbox):
    metodo, ruta = RUTA_PROTEGIDA[servicio]
    cliente = _app(servicio).test_client()

    sin_token = cliente.open(ruta, method=metodo, json={})
    token_falso = cliente.open(ruta, method=metodo, json={},
                               headers={siem_servicios.ENCABEZADO_TOKEN: "x" * 48})

    assert sin_token.status_code == 401
    assert token_falso.status_code == 401
    assert "token interno" in sin_token.get_json()["error"]


@pytest.mark.parametrize("servicio", sorted(RUTA_PROTEGIDA))
def test_la_sonda_de_salud_no_pide_token(servicio):
    r = _app(servicio).test_client().get("/v1/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok", "servicio": servicio}


def test_un_servicio_no_arranca_sin_token(monkeypatch):
    monkeypatch.delenv("SIEM_INTERNAL_TOKEN")
    with pytest.raises(siem_servicios.ConfiguracionInsegura, match="SIEM_INTERNAL_TOKEN"):
        siem_servicios.crear_servicio("audit")


def test_un_servicio_no_arranca_con_un_token_corto(monkeypatch):
    monkeypatch.setenv("SIEM_INTERNAL_TOKEN", "corto")
    with pytest.raises(siem_servicios.ConfiguracionInsegura, match="demasiado corto"):
        siem_servicios.crear_servicio("audit")


def test_las_urls_salen_del_registro(monkeypatch):
    assert siem_servicios.url_de("audit") == "http://audit:8000"
    monkeypatch.setenv("SIEM_AUDIT_URL", "http://127.0.0.1:9101/")
    assert siem_servicios.url_de("audit") == "http://127.0.0.1:9101"


# ─── Auditoría: segunda barrera ──────────────────────────────────────────────

DECISION_VALIDA = {"incident_id": "INC-1", "action_id": "INC-1-a", "decision": "approved",
                   "analyst": "ana", "note": "", "attacker_ips": ["203.0.113.7"]}


def test_la_auditoria_pone_su_propio_sello_de_tiempo(sandbox):
    r = _app("audit").test_client().post("/v1/decisions", json=DECISION_VALIDA, headers=TOKEN)

    assert r.status_code == 201
    registro = r.get_json()["record"]
    assert registro["ts"] and registro["prev_hash"] == "0" * 64


@pytest.mark.parametrize("cambio, motivo", [
    ({"ts": "2020-01-01T00:00:00+00:00"}, "campos no permitidos"),   # el cliente no elige el momento
    ({"comando_sugerido": "rm -rf /"}, "campos no permitidos"),
    ({"decision": "executed"}, "decision inválida"),
    ({"analyst": ""}, "analyst"),
    ({"note": "x" * 501}, "note supera"),
    ({"attacker_ips": "203.0.113.7"}, "attacker_ips"),
])
def test_la_auditoria_rechaza_registros_invalidos(sandbox, cambio, motivo):
    r = _app("audit").test_client().post("/v1/decisions", json={**DECISION_VALIDA, **cambio},
                                         headers=TOKEN)

    assert r.status_code == 400
    assert motivo in r.get_json()["error"]
    assert not (sandbox / "data" / "decisions.jsonl").exists(), "se escribió algo inválido"


# ─── Ciclo del pipeline: qué etapa tolera fallar y cuál no ───────────────────

def _ciclo():
    return _app("pipeline").test_client().post("/v1/cycles", headers=TOKEN)


def test_el_ciclo_sigue_sin_elasticsearch(sandbox, servicio_caido, network_logs_dir,
                                          copiar_fixture, monkeypatch):
    """El collector es la etapa tolerable: sin él, se clasifica desde network_logs/."""
    monkeypatch.setenv("SIEM_USE_LLM", "false")
    for archivo in network_logs_dir.glob("*.json"):
        copiar_fixture(archivo, sandbox / "network_logs")
    # Los fixtures tienen fecha fija: sin esto, la ventana de 24 h los descarta
    # (mismo problema que resuelve `eventos_de_red` en conftest).
    import classifier_service
    import siem_lib
    monkeypatch.setattr(classifier_service, "read_network_logs",
                        lambda d, *_: siem_lib.read_network_logs(d, window_hours=None))
    servicio_caido("collector")

    r = _ciclo()

    assert r.status_code == 200, r.get_json()
    datos = r.get_json()
    assert datos["etapas"][0] == {"etapa": "collector", "estado": "omitida",
                                  "motivo": "no se pudo conectar con el servicio 'collector'"}
    assert datos["report"]["incident_count"] >= 2
    assert datos["report"]["analyst_mode"] == "fallback"
    assert (sandbox / "data" / "siem_incidents.json").exists()


def test_el_ciclo_usa_la_ultima_captura_si_elasticsearch_no_responde(sandbox, monkeypatch,
                                                                      siem_clean):
    import collector_service
    import es_client
    import siem_lib

    siem_lib.write_json(sandbox / collector_service.OUTPUT_FILE, siem_clean)

    def _caido(*_a, **_k):
        raise es_client.ESUnavailable("No se pudo conectar a Elasticsearch")

    monkeypatch.setattr(es_client, "_es_request", _caido)

    r = _ciclo()

    assert r.status_code == 200, r.get_json()
    assert r.get_json()["etapas"][0]["estado"] == "captura_previa"
    tipos = {i["classification"]["attack_type"] for i in r.get_json()["report"]["incidents"]}
    assert "ssh_brute_force" in tipos, "no se usó la captura previa del SIEM"


@pytest.mark.parametrize("caido", ["classifier", "analyst"])
def test_una_etapa_critica_caida_aborta_sin_pisar_el_reporte(sandbox_con_incidentes,
                                                              servicio_caido, caido):
    reporte = sandbox_con_incidentes / "data" / "siem_incidents.json"
    antes = reporte.read_bytes()
    servicio_caido("collector", caido)

    r = _ciclo()

    assert r.status_code == 502
    assert caido in r.get_json()["error"]
    assert reporte.read_bytes() == antes


def test_sin_auditoria_el_analista_no_inventa_que_no_hay_antecedentes(sandbox, servicio_caido):
    """Un audit caído no es "primera vez que se ve esta IP": es un error visible."""
    servicio_caido("audit")

    r = _app("analyst").test_client().post("/v1/analyze", json={"incidents": []}, headers=TOKEN)

    assert r.status_code == 503
    assert "antecedentes" in r.get_json()["error"]


def test_dos_ciclos_a_la_vez_no_se_pisan(sandbox, servicio_caido):
    import orquestador

    servicio_caido("collector")
    assert orquestador._en_curso.acquire(blocking=False)
    try:
        r = _ciclo()
    finally:
        orquestador._en_curso.release()

    assert r.status_code == 409


# ─── El panel ante un servicio caído ─────────────────────────────────────────

def test_sin_auditoria_el_panel_no_muestra_estados_a_medias(client, servicio_caido):
    """Sin el registro de decisiones, todas las acciones parecerían pendientes."""
    servicio_caido("audit")

    r = client.get("/api/v1/incidents")

    assert r.status_code == 503
    assert "audit" in r.get_json()["error"]


def test_sin_auditoria_no_se_puede_decidir(client, servicio_caido):
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    accion = inc["recommended_actions"][0]
    servicio_caido("audit")

    r = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"], "action_id": accion["action_id"],
        "decision": "approved"})

    assert r.status_code == 503


def test_sin_servicio_de_autenticacion_el_login_responde_503(client_anonimo, login,
                                                              servicio_caido):
    servicio_caido("auth")

    r = login(client_anonimo)

    assert r.status_code == 503
    assert "autenticación" in r.get_json()["error"]


def test_una_sesion_abierta_no_sobrevive_a_un_auth_caido_como_otro_usuario(client,
                                                                            servicio_caido):
    """Sin poder confirmar quién es, la petición falla; no se degrada a anónimo."""
    servicio_caido("auth")

    r = client.get("/api/v1/me")

    assert r.status_code == 503


def test_la_sonda_del_panel_responde_aunque_el_pipeline_este_caido(client_anonimo,
                                                                    servicio_caido):
    servicio_caido("pipeline")

    r = client_anonimo.get("/api/v1/healthz")

    assert r.status_code == 200
    assert r.get_json() == {"status": "ok", "incidents_file": False}


def test_el_gateway_nunca_recibe_el_hash_de_la_contrasena(entorno_auth):
    r = _app("auth").test_client().get("/v1/users/ana", headers=TOKEN)

    assert r.status_code == 200
    assert "password_hash" not in r.get_json()
    assert set(r.get_json()) == {"username", "rol", "activo", "permisos"}


def test_auth_responde_404_a_un_usuario_inexistente(entorno_auth):
    r = _app("auth").test_client().get("/v1/users/nadie", headers=TOKEN)
    assert r.status_code == 404


def test_el_resumen_de_usuarios_cuenta_solo_los_activos(entorno_auth):
    import siem_auth

    usuarios = siem_auth.cargar_usuarios()
    usuarios["beto"].activo = False
    siem_auth.guardar_usuarios(usuarios)

    r = _app("auth").test_client().get("/v1/users-summary", headers=TOKEN)

    assert r.status_code == 200
    assert r.get_json() == {"total": 3, "activos_por_rol": {"analyst": 1, "auditor": 1}}


def test_una_baja_corta_la_sesion_abierta_en_la_siguiente_peticion(client):
    """Atraviesa los dos servicios: la baja se hace en el almacén de `auth` y el
    gateway la ve en la petición siguiente, sin esperar a que caduque la cookie."""
    import siem_auth

    assert client.get("/api/v1/me").status_code == 200
    usuarios = siem_auth.cargar_usuarios()
    usuarios["ana"].activo = False
    siem_auth.guardar_usuarios(usuarios)

    assert client.get("/api/v1/me").status_code == 401


def test_el_login_con_credenciales_malas_no_distingue_el_motivo(client_anonimo, login):
    inexistente = login(client_anonimo, "nadie", "contrasena-de-prueba-1")
    clave_mala = login(client_anonimo, "ana", "otra-contrasena-123")

    assert inexistente.status_code == clave_mala.status_code == 401
    assert inexistente.get_json() == clave_mala.get_json()
