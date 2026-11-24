"""Entradas con tipo de dato inválido: los servicios responden 400, nunca 500 (defectos D1 a D4).

  - classifier POST /v1/classify: cada elemento de siem_data.alerts tiene que ser un objeto;
  - analyst POST /v1/analyze: cada elemento de incidents tiene que ser un objeto;
  - knowledge POST /v1/context: attacker_ips y target_hosts, si vienen, tienen que ser listas.
"""

from __future__ import annotations

import pytest

from siem_servicios import llamar


def test_classify_rechaza_alertas_que_no_son_objetos(sandbox):
    r = llamar("classifier", "POST", "/v1/classify", {"siem_data": {"alerts": [1, 2]}})
    assert r.status == 400
    assert "alerts" in r.datos["error"]


def test_classify_acepta_alertas_vacias(sandbox):
    assert llamar("classifier", "POST", "/v1/classify", {"siem_data": {"alerts": []}}).status == 200


def test_analyze_rechaza_incidentes_que_no_son_objetos(sandbox):
    r = llamar("analyst", "POST", "/v1/analyze", {"incidents": [1, 2]})
    assert r.status == 400
    assert "incidents" in r.datos["error"]


def test_analyze_acepta_lista_vacia(sandbox):
    assert llamar("analyst", "POST", "/v1/analyze", {"incidents": []}).status == 200


@pytest.mark.parametrize("campo", ["attacker_ips", "target_hosts"])
def test_context_rechaza_listas_que_no_son_listas(sandbox, campo):
    incidente = {"incident_id": "INC-T", campo: 5}
    r = llamar("knowledge", "POST", "/v1/context", {"incidents": [incidente]})
    assert r.status == 400
    assert campo in r.datos["error"]


def test_context_acepta_listas(sandbox):
    incidente = {"incident_id": "INC-T", "attacker_ips": ["203.0.113.5"], "target_hosts": ["h1"]}
    assert llamar("knowledge", "POST", "/v1/context", {"incidents": [incidente]}).status == 200
