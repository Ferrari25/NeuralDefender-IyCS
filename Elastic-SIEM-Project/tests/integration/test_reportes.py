"""Reportes de la supervisión humana y registro de actividad de la memoria.

Lo que se certifica:
  - cada decisión guarda el contexto que un reporte necesita (acción, tipo de
    ataque) y nunca el comando;
  - lo que se hace con la memoria del agente (documentos, lecciones) queda en
    `actividad.jsonl`, encadenado como el resto de la auditoría;
  - el reporte sale en JSON o CSV, filtra por período, incluye el estado de la
    cadena y neutraliza fórmulas de planilla;
  - antes de decidir, el panel pide confirmación con un resumen de lo decidido.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pytest

from siem_servicios import llamar

APP_JS = (Path(__file__).resolve().parents[2] / "services" / "gateway" / "static"
          / "app.js").read_text(encoding="utf-8")


def _decidir(client, decision="approved", note="", indice=0):
    inc = client.get("/api/v1/incidents").get_json()["incidents"][indice]
    accion = inc["recommended_actions"][0]
    r = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"], "action_id": accion["action_id"],
        "decision": decision, "note": note})
    assert r.status_code == 201
    return inc, accion


# ─── Reporte ─────────────────────────────────────────────────────────────────

def test_el_reporte_json_resume_las_decisiones(client):
    inc, accion = _decidir(client, "approved")
    _decidir(client, "dismissed", "ruido conocido", indice=1)

    rep = client.get("/api/v1/reportes").get_json()
    assert rep["resumen"]["decisiones_registradas"] == 2
    assert rep["resumen"]["estado_vigente"] == {"approved": 1, "dismissed": 1}
    assert rep["resumen"]["por_analista"] == {"ana": 2}
    assert rep["integridad"]["decisiones"]["chain_ok"] is True
    primera = rep["decisiones"][0]
    assert primera["accion"] == accion["accion"]
    assert primera["attack_type"] == inc["classification"]["attack_type"]


def test_el_csv_se_descarga_como_archivo(client):
    _decidir(client, "dismissed", "falso positivo")
    r = client.get("/api/v1/reportes?formato=csv&desde=2000-01-01")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert re.search(r'attachment; filename="reporte-siem-ia_2000-01-01_hoy\.csv"',
                     r.headers["Content-Disposition"])
    filas = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert [f["registro"] for f in filas] == ["decision"]
    assert filas[0]["evento"] == "dismissed" and filas[0]["detalle"] == "falso positivo"
    assert filas[0]["analista"] == "ana"


def test_el_csv_neutraliza_formulas(client):
    _decidir(client, "dismissed", '=HYPERLINK("http://atacante","clic")')
    texto = client.get("/api/v1/reportes?formato=csv").get_data(as_text=True)
    [fila] = list(csv.DictReader(io.StringIO(texto)))
    assert fila["detalle"].startswith("'=")


def test_el_periodo_filtra_y_se_valida(client):
    _decidir(client)
    assert client.get("/api/v1/reportes?hasta=2000-01-01").get_json()["decisiones"] == []
    r = client.get("/api/v1/reportes?desde=ayer")
    assert r.status_code == 400 and "AAAA-MM-DD" in r.get_json()["error"]
    r = client.get("/api/v1/reportes?desde=2026-10-10&hasta=2026-10-01")
    assert r.status_code == 400
    assert client.get("/api/v1/reportes?formato=xml").status_code == 400


@pytest.mark.parametrize("usuario", ["beto", "cata"])
def test_todos_los_roles_que_ven_la_auditoria_sacan_reportes(client_como, usuario):
    assert client_como(usuario).get("/api/v1/reportes").status_code == 200


def test_el_reporte_exige_sesion(client_anonimo):
    assert client_anonimo.get("/api/v1/reportes").status_code == 401


def test_la_herramienta_de_linea_de_comandos(client, capsys):
    import reportes

    _decidir(client)
    assert reportes.main(["--formato", "csv"]) == 0
    salida = capsys.readouterr().out
    assert salida.startswith(",".join(reportes.COLUMNAS_CSV))
    assert reportes.main(["--desde", "mañana"]) == 2


# ─── Actividad de la memoria ─────────────────────────────────────────────────

def _actividad() -> list[dict]:
    return llamar("audit", "GET", "/v1/activity").datos


def test_cargar_un_documento_queda_en_la_actividad(client):
    client.post("/api/v1/memoria/documentos", json={"titulo": "Inventario", "contenido": "x"})
    [evento] = _actividad()
    assert evento["evento"] == "documento_cargado"
    assert evento["actor"] == "ana" and evento["detalle"] == "Inventario"
    assert evento["prev_hash"], "la actividad está encadenada como el resto de la auditoría"


def test_proponer_y_revisar_una_leccion_queda_en_la_actividad(client):
    leccion = client.post("/api/v1/memoria/lecciones",
                          json={"texto": "El 10.0.0.5 es un honeypot", "ip": "10.0.0.5"}
                          ).get_json()["leccion"]
    client.post(f"/api/v1/memoria/lecciones/{leccion['leccion_id']}/revision",
                json={"decision": "rechazar"})

    eventos = [(e["evento"], e["leccion_id"], e.get("ip")) for e in _actividad()]
    assert eventos == [("leccion_propuesta", leccion["leccion_id"], "10.0.0.5"),
                       ("leccion_rechazada", leccion["leccion_id"], "10.0.0.5")]
    rep = client.get("/api/v1/reportes").get_json()
    assert rep["resumen"]["actividad_de_memoria"] == {"leccion_propuesta": 1, "leccion_rechazada": 1}


def test_una_propuesta_del_sistema_queda_a_nombre_del_sistema(client):
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    ip = inc["source_ip"]
    # Un caso previo igual (otro incidente, misma IP y tipo, descartado).
    llamar("knowledge", "POST", "/v1/cases", {
        "incident_id": "INC-ANTERIOR", "action_id": "INC-ANTERIOR-A1", "decision": "dismissed",
        "analyst": "ana", "attack_type": inc["classification"]["attack_type"],
        "source_ip": ip, "attacker_ips": [ip]})

    r = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"], "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "dismissed", "note": "ruido"})
    assert r.get_json()["lecciones_propuestas"] == 1
    [evento] = _actividad()
    assert evento["evento"] == "leccion_propuesta"
    assert evento["actor"] == "sistema" and evento["actor_rol"] == "sistema"


def test_si_la_auditoria_no_registra_la_actividad_se_dice(client, servicio_caido):
    servicio_caido("audit")
    r = client.post("/api/v1/memoria/documentos", json={"titulo": "t", "contenido": "c"})
    assert r.status_code == 503
    assert "no quedó en el registro de actividad" in r.get_json()["error"]


@pytest.mark.parametrize("cuerpo, error", [
    ({"evento": "borrar_todo", "actor": "ana"}, "evento inválido"),
    ({"evento": "documento_cargado", "actor": "ana", "comando": "rm"}, "no permitidos"),
    ({"evento": "documento_cargado"}, "actor"),
])
def test_audit_valida_la_actividad(sandbox, cuerpo, error):
    r = llamar("audit", "POST", "/v1/activity", cuerpo)
    assert r.status == 400 and error in r.datos["error"]


# ─── Confirmación antes de decidir (panel) ───────────────────────────────────

def test_aprobar_pasa_por_la_confirmacion():
    rama = re.search(r'accion === "decidir"\) \{(.*?)\}', APP_JS, re.S).group(1)
    assert "aprobarAccion(" in rama and "decide(" not in rama
    assert re.search(r"async function aprobarAccion.*?await confirmarDecision", APP_JS, re.S)
    assert re.search(r"async function confirmarDescarte.*?await confirmarDecision", APP_JS, re.S)
    assert re.search(r"async function revisarLeccion.*?await confirmarLeccion", APP_JS, re.S)


def test_la_confirmacion_resume_lo_importante():
    cuerpo = APP_JS[APP_JS.index("function confirmarDecision"):APP_JS.index("const ALCANCE_TIPO")]
    for dato in ("a.comando_sugerido", "a.impacto", "a.plazo", "falso_positivo_probabilidad",
                 "contexto_historico", "severidadDe(inc)", "El sistema no ejecuta nada",
                 "sesion.usuario"):
        assert dato in cuerpo, f"la confirmación no muestra {dato}"
    plantilla = (Path(__file__).resolve().parents[2] / "services" / "gateway" / "templates"
                 / "index.html").read_text(encoding="utf-8")
    assert '<dialog id="confirmacion"' in plantilla
