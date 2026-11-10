"""Un ataque en curso conserva su ID entre ciclos del pipeline.

El ID sale de `hash(tipo, IP, first_seen)` y `first_seen` es el evento más viejo
de la MUESTRA que trae el collector (las alertas más recientes por regla, los
últimos logs). Con el ataque en curso la muestra avanza, y el incidente cambiaba
de ID cada pocos ciclos: las decisiones del analista dejaban de verse (sus
`action_id` empiezan con el `incident_id`) y el Agente 2 volvía a pasar por el
LLM un ataque ya analizado. Se encontró midiendo la memoria del host: Ollama
nunca descargaba el modelo porque cada ciclo traía un incidente "nuevo".
"""

from __future__ import annotations

import copy

import classifier


def _incidente(incident_id="INC-AUTH-10.0.0.5-aaaa1111", first="2026-11-10T00:30:00Z",
               last="2026-11-10T01:00:00Z"):
    return {
        "incident_id": incident_id, "first_seen": first, "last_seen": last,
        "recommended_actions": [
            {"action_id": f"{incident_id}-bceba4", "alternativa_de": None},
            {"action_id": f"{incident_id}-d99515", "alternativa_de": f"{incident_id}-bceba4"},
        ],
    }


def test_un_ataque_en_curso_conserva_el_id_y_el_de_sus_acciones():
    anterior = _incidente("INC-AUTH-10.0.0.5-aaaa1111", "2026-11-10T00:10:00Z",
                          "2026-11-10T00:58:00Z")
    actual = _incidente("INC-AUTH-10.0.0.5-bbbb2222", "2026-11-10T00:30:00Z",
                        "2026-11-10T01:00:00Z")
    classifier.conservar_identidad([actual], [anterior])

    assert actual["incident_id"] == "INC-AUTH-10.0.0.5-aaaa1111"
    assert actual["first_seen"] == "2026-11-10T00:10:00Z"   # el inicio real, no el de la muestra
    assert [a["action_id"] for a in actual["recommended_actions"]] == [
        "INC-AUTH-10.0.0.5-aaaa1111-bceba4", "INC-AUTH-10.0.0.5-aaaa1111-d99515"]
    assert actual["recommended_actions"][1]["alternativa_de"] == "INC-AUTH-10.0.0.5-aaaa1111-bceba4"


def test_un_corte_largo_es_un_incidente_nuevo():
    anterior = _incidente("INC-AUTH-10.0.0.5-aaaa1111", "2026-11-09T20:00:00Z",
                          "2026-11-09T21:00:00Z")
    actual = _incidente("INC-AUTH-10.0.0.5-bbbb2222", "2026-11-10T00:30:00Z",
                        "2026-11-10T01:00:00Z")
    classifier.conservar_identidad([actual], [anterior])
    assert actual["incident_id"] == "INC-AUTH-10.0.0.5-bbbb2222"
    assert actual["first_seen"] == "2026-11-10T00:30:00Z"


def test_otra_ip_u_otro_tipo_no_heredan_identidad():
    anterior = _incidente("INC-AUTH-10.0.0.5-aaaa1111")
    otra_ip = _incidente("INC-AUTH-10.0.0.6-bbbb2222")
    otro_tipo = _incidente("INC-SCAN-10.0.0.5-cccc3333")
    classifier.conservar_identidad([otra_ip, otro_tipo], [anterior])
    assert otra_ip["incident_id"] == "INC-AUTH-10.0.0.6-bbbb2222"
    assert otro_tipo["incident_id"] == "INC-SCAN-10.0.0.5-cccc3333"


def test_sin_anteriores_o_con_basura_no_cambia_nada():
    actual = _incidente()
    copia = copy.deepcopy(actual)
    classifier.conservar_identidad([actual], None)
    classifier.conservar_identidad([actual], [None, {}, {"incident_id": 5}, {"incident_id": "x"}])
    assert actual == copia


def test_la_muestra_que_avanza_no_cambia_el_id_de_punta_a_punta(siem_clean):
    """Con datos reales: el segundo ciclo ve una muestra sin los eventos más viejos."""
    primero = classifier.classify(siem_clean)
    assert primero

    def mas_nuevo(lista, n):
        return sorted(lista, key=lambda x: x.get("@timestamp") or x.get("timestamp") or "")[n:]

    avanzada = dict(siem_clean, alerts=mas_nuevo(siem_clean.get("alerts", []), 2),
                    auth_failure_logs=mas_nuevo(siem_clean.get("auth_failure_logs", []), 4))
    sin_continuidad = {i["incident_id"] for i in classifier.classify(avanzada)}
    con_continuidad = classifier.classify(avanzada, None, [
        {k: i[k] for k in ("incident_id", "first_seen", "last_seen")} for i in primero])

    ids_previos = {i["incident_id"] for i in primero}
    assert {i["incident_id"] for i in con_continuidad} <= ids_previos
    # La prueba tiene sentido solo si la muestra avanzada SÍ cambiaba algún ID.
    assert sin_continuidad - ids_previos, "la muestra recortada no movió ningún first_seen"
