"""El panel no atribuye a Elastic una detección que hizo el Agente 1 (**D-11**).

`detect_port_scans` y `detect_phishing` fijaban a mano:

    rule_name="Network port scan detection", severity_siem="high", risk_score=47
    rule_name="Credential submission to suspicious login page", severity_siem="high", risk_score=68

Ninguno de esos nombres existe en Kibana. El catálogo llama a esas reglas «Port Scan –
Many Distinct Ports» y «Credential Submission to Suspicious Login». El campo se llama
`severity_siem` —severidad *del SIEM*— y el panel lo mostraba bajo la etiqueta «Regla
SIEM».

Y esos dos detectores **ni siquiera consultan Elasticsearch**: leen `network_logs/`
directamente, porque en este laboratorio no hay Suricata. Aparecen aunque no haya una
sola regla desplegada.

Un evaluador que abriera un incidente de escaneo, leyera el nombre y lo buscara en
Kibana no lo encontraría. Peor: el proyecto **sí** tiene una historia buena que contar
acá —hay dos caminos de detección y el sistema funciona aunque el SIEM no dispare—, y
el nombre inventado la tapaba con algo que no era cierto.

Ahora cada incidente declara su procedencia en `detection_source`:

* `"elastic"` — se construyó desde una alerta real; `rule_name`, `severity_siem` y
  `risk_score` son los que trajo esa alerta.
* `"clasificador"` — lo detectó el Agente 1 por su cuenta, y no hay regla que citar.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

import classifier

RAIZ = Path(__file__).resolve().parent.parent.parent
FUENTE = (RAIZ / "src" / "classifier.py").read_text(encoding="utf-8")
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")

# Traducción de la severidad determinística, igual que `SEV_DETERMINISTICA` en el panel.
SEV = {"critica": "CRITICAL", "alta": "HIGH", "media": "MEDIUM", "baja": "LOW"}


def _evento_escaneo(puerto: int) -> dict:
    return {"event_type": "network_flow", "source_ip": "198.51.100.5",
            "dest_ip": "10.1.1.2", "dest_port": puerto,
            "@timestamp": "2026-09-16T10:00:00.000Z"}


# ─── Los detectores determinísticos no citan reglas ──────────────────────────

def test_el_escaneo_no_inventa_una_regla_del_siem():
    inc = classifier.detect_port_scans([_evento_escaneo(p) for p in range(1, 27)])[0]

    assert inc["detection_source"] == "clasificador"
    assert inc["rule_name"] is None, (
        f"el escaneo dice venir de la regla «{inc['rule_name']}», que no existe en "
        f"Kibana: este detector lee network_logs/, no Elasticsearch")
    assert inc["severity_siem"] is None, "no hubo SIEM que asignara una severidad"
    assert inc["risk_score"] is None


def test_el_phishing_no_inventa_una_regla_del_siem(network_logs_dir):
    from tests.conftest import eventos_de_red

    inc = classifier.detect_phishing(eventos_de_red(network_logs_dir))[0]

    assert inc["detection_source"] == "clasificador"
    assert inc["rule_name"] is None
    assert inc["severity_siem"] is None
    assert inc["risk_score"] is None


# ─── Varias reglas sobre la misma IP: gana la alerta más grave ───────────────
#
# Con varias reglas de Kibana activas a la vez (la escalera Low/Medium/High/
# Critical del catálogo), una misma IP atacante puede disparar más de una. Antes
# se quedaba con la ÚLTIMA alerta que devolvía Elasticsearch, sin importar su
# severidad: un incidente realmente crítico podía terminar mostrando "Low" en
# el panel solo por el orden de la respuesta.

def _alerta_auth(rule_name: str, severity: str, source_ip: str = "172.18.0.6",
                 timestamp: str = "2026-09-28T15:00:00.000Z", event_count: int = 5,
                 risk_score: int = 50) -> dict:
    """Un alerta ya parseada (forma que produce `prepare-for-ia.parse_alerts`)."""
    return {"type": "security_alert", "timestamp": timestamp, "rule_name": rule_name,
            "severity": severity, "risk_score": risk_score, "source_ip": source_ip,
            "event_count": event_count,
            "mitre": {"technique_id": "T1110", "technique": "Brute Force",
                      "tactic": "Credential Access"}}


def test_una_alerta_critica_no_se_pierde_detras_de_una_low():
    siem_data = {"alerts": [
        _alerta_auth("SSH Isolated Authentication Failure", "low", event_count=1),
        _alerta_auth("SSH Successful Login After Brute Force", "critical", event_count=25),
    ], "auth_failure_logs": []}

    incs = classifier.detect_auth_incidents(siem_data)
    assert len(incs) == 1, "misma IP: un solo incidente"

    inc = incs[0]
    assert inc["severity_siem"] == "critical"
    assert inc["rule_name"] == "SSH Successful Login After Brute Force"


def test_el_orden_de_llegada_no_importa():
    """La crítica primero o última: el resultado tiene que ser el mismo."""
    orden_a = classifier.detect_auth_incidents({"alerts": [
        _alerta_auth("SSH Successful Login After Brute Force", "critical"),
        _alerta_auth("SSH Isolated Authentication Failure", "low"),
    ], "auth_failure_logs": []})[0]

    orden_b = classifier.detect_auth_incidents({"alerts": [
        _alerta_auth("SSH Isolated Authentication Failure", "low"),
        _alerta_auth("SSH Successful Login After Brute Force", "critical"),
    ], "auth_failure_logs": []})[0]

    assert orden_a["severity_siem"] == orden_b["severity_siem"] == "critical"
    assert orden_a["rule_name"] == orden_b["rule_name"]


def test_entre_dos_alertas_de_la_misma_severidad_se_queda_con_la_mas_reciente():
    """Sin un desempate por gravedad, se preserva el criterio anterior: la que
    llega después en la respuesta de Elasticsearch (normalmente, la más nueva)."""
    inc = classifier.detect_auth_incidents({"alerts": [
        _alerta_auth("SSH Brute Force – Basic Threshold", "medium"),
        _alerta_auth("SSH Invalid User Enumeration", "medium"),
    ], "auth_failure_logs": []})[0]

    assert inc["rule_name"] == "SSH Invalid User Enumeration"


def test_el_risk_score_acompana_a_la_alerta_mas_grave():
    """`risk_score` y `rule_name` tienen que venir de la MISMA alerta: mezclar el
    nombre de una regla con el puntaje de otra sería inconsistente."""
    inc = classifier.detect_auth_incidents({"alerts": [
        _alerta_auth("SSH Isolated Authentication Failure", "low", risk_score=21),
        _alerta_auth("SSH Successful Login After Brute Force", "critical", risk_score=95),
    ], "auth_failure_logs": []})[0]

    assert inc["risk_score"] == 95


# ─── Autenticación: la procedencia depende de si hubo alerta ─────────────────

def test_con_alerta_de_kibana_la_procedencia_es_elastic(siem_clean):
    incs = classifier.detect_auth_incidents(siem_clean)
    con_regla = [i for i in incs if i["rule_name"]]
    assert con_regla, "el fixture tiene alertas; alguna tiene que traer su regla"

    for inc in con_regla:
        assert inc["detection_source"] == "elastic"
        assert inc["severity_siem"], "una alerta real trae su severidad"


def test_sin_alerta_la_procedencia_es_el_clasificador(auth_25_sin_alerta):
    """25 fallos reales y ninguna alerta: el Agente 1 lo detecta solo (escenario L-01).

    Es el caso que demuestra que el sistema no depende del SIEM para detectar.
    """
    incs = classifier.detect_auth_incidents(auth_25_sin_alerta)
    assert incs, "25 fallos tienen que producir un incidente"

    for inc in incs:
        assert inc["detection_source"] == "clasificador"
        assert inc["rule_name"] is None


# ─── Nadie vuelve a escribir un nombre de regla a mano ───────────────────────

def _asignaciones_literales_de(campo: str) -> list[str]:
    """Valores de cadena asignados a `campo=` en el código, ignorando comentarios."""
    arbol = ast.parse(FUENTE)
    fuera = []
    for nodo in ast.walk(arbol):
        if (isinstance(nodo, ast.keyword) and nodo.arg == campo
                and isinstance(nodo.value, ast.Constant)
                and isinstance(nodo.value.value, str)):
            fuera.append(nodo.value.value)
    return fuera


def test_el_clasificador_no_escribe_ningun_nombre_de_regla_a_mano():
    """**El defecto, en una prueba.**

    Se recorre el AST, no el texto: un comentario que *cite* el nombre viejo —como el
    de `Incident`, que explica el hallazgo— no cuenta como asignación.
    """
    literales = _asignaciones_literales_de("rule_name")

    assert not literales, (
        f"classifier.py asigna nombres de regla a mano: {literales}. Un `rule_name` "
        f"solo puede venir de una alerta de Elasticsearch; si lo detecta el Agente 1, "
        f"va en None y `detection_source` lo dice.")


def test_el_clasificador_no_inventa_una_severidad_del_siem():
    literales = _asignaciones_literales_de("severity_siem")
    assert not literales, f"severidad del SIEM escrita a mano: {literales}"


def test_los_nombres_del_catalogo_no_coinciden_con_los_inventados():
    """Por qué el defecto era engañoso y no solo impreciso: los nombres que el
    clasificador ponía **no existían** en el catálogo desplegado."""
    import json

    catalogo = {json.loads(f.read_text(encoding="utf-8").splitlines()[0])["name"]
                for f in (RAIZ / "rules" / "ndjson").glob("*.ndjson")}
    assert len(catalogo) >= 13, "no pude leer el catálogo de reglas"

    for inventado in ("Network port scan detection",
                      "Credential submission to suspicious login page"):
        assert inventado not in catalogo, (
            f"«{inventado}» sí existe en el catálogo; revisar este hallazgo")


@pytest.mark.parametrize("procedencia", ["elastic", "clasificador"])
def test_las_dos_procedencias_son_las_unicas(procedencia: str):
    """Un valor tercero no lo entendería el panel, que decide con `=== "elastic"`."""
    assert f'"{procedencia}"' in FUENTE

    valores = set(_asignaciones_literales_de("detection_source"))
    assert valores <= {"elastic", "clasificador"}, f"procedencia inesperada: {valores}"


# ─── Quitar la severidad del SIEM no degrada ningún incidente ────────────────

@pytest.mark.parametrize(("tipo", "esperada"), [
    ("port_scan", "HIGH"), ("credential_harvesting", "HIGH"),
    ("ssh_brute_force", "HIGH"), ("suspicious_auth", "MEDIUM"),
])
def test_sin_severidad_del_siem_queda_la_determinista(tipo: str, esperada: str):
    """**El riesgo de este arreglo, cubierto.**

    Al vaciar `severity_siem`, el panel podía caer a `MEDIUM` y degradar en silencio
    un incidente — exactamente lo que se evitó en la tarea G1 con el Agente 2. El
    respaldo correcto es la severidad **determinística**, que siempre existe.

    Se reproduce acá la misma cadena que `severidadDe()` aplica en el panel.
    """
    determinista = classifier._classification(tipo, 26, "x", [])["severity"]
    pintada = (None or None or SEV.get(determinista) or "MEDIUM")

    assert pintada == esperada, (
        f"un incidente de {tipo} sin severidad del SIEM se pintaría {pintada}")


# ─── El panel ────────────────────────────────────────────────────────────────

def test_el_panel_decide_la_severidad_en_un_solo_lugar():
    """La misma cadena de respaldos estaba repetida en seis sitios: al cambiarla,
    cualquiera de los seis podía quedar atrás.

    Bajó a cinco cuando se quitó el panel "Registro de eventos del sistema"
    (`renderFeedItem` era uno de los seis) — el número importa menos que la
    garantía: cada sitio que pinta una severidad pasa por `severidadDe()`, nunca
    reimplementa la cadena de respaldos.
    """
    assert "const severidadDe = inc =>" in APP_JS
    assert APP_JS.count("severidadDe(") == 5, "quedaron llamadas fuera del ayudante"
    assert "severidad_ajustada || " not in APP_JS, "sobrevivió una copia de la cadena"


def test_la_cadena_de_respaldos_incluye_la_severidad_deterministica():
    cadena = re.search(r"const severidadDe = inc => \((.*?)\)\.toUpperCase",
                       APP_JS, re.S).group(1)

    assert "severidad_ajustada" in cadena, "falta lo que ajustó el Agente 2"
    assert "severity_siem" in cadena, "falta la severidad de la alerta"
    assert "SEV_DETERMINISTICA" in cadena, (
        "sin la severidad del Agente 1, un incidente sin alerta cae a MEDIUM")
    assert cadena.index("severity_siem") < cadena.index("SEV_DETERMINISTICA"), (
        "el orden importa: la alerta manda sobre la determinística")


def test_el_panel_muestra_la_procedencia_y_no_una_regla_inventada():
    assert "const procedenciaDe = inc =>" in APP_JS
    assert 'inc.detection_source === "elastic"' in APP_JS
    assert '<span class="k">Detección</span>' in APP_JS
    assert "Regla SIEM" not in APP_JS, (
        "el panel sigue etiquetando como «Regla SIEM» algo que puede no serlo")


def test_la_procedencia_deterministica_se_nombra_positivamente():
    """Decir «Agente 1, detección determinística» es información; decir «sin regla»
    a secas suena a que falta algo."""
    procedencia = APP_JS[APP_JS.index("const procedenciaDe"):
                         APP_JS.index("const attackLabel")]
    assert "Agente 1" in procedencia
    assert "determinística" in procedencia
