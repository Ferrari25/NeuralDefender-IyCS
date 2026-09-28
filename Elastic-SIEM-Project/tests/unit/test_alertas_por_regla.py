"""Una regla ruidosa no puede tapar a las demás (defecto **D-01**).

Encontrado al verificar el script de demostración, 25-09-2026.

`prepare-for-ia.py` pedía las **10 alertas más recientes** de la ventana. Con
116 alertas de 8 reglas distintas en Elasticsearch, las 10 que llegaban al
clasificador eran **todas de la misma regla** — la más ruidosa, `Port Scan –
Rapid Sequential Probe`, que había disparado 96 veces.

Entre las que quedaban afuera estaba `SSH Successful Login After Brute Force`:
severidad crítica, riesgo 95, y significa que la fuerza bruta **funcionó**. La
detección más importante del sistema no llegaba al analista.

El defecto empeora cuanto mejor configurado está el SIEM: apareció al desplegar
las 13 reglas del catálogo (tarea P3), donde antes había 4 y el problema no se
notaba.

La corrección pide las N más recientes **de cada regla**, agrupando en
Elasticsearch con `terms` + `top_hits`.
"""

from __future__ import annotations

import pytest

import siem_lib


def _hit(regla: str, ts: str, extra: dict | None = None) -> dict:
    fuente = {"@timestamp": ts, "kibana.alert.rule.name": regla}
    fuente.update(extra or {})
    return {"_source": fuente}


def _respuesta_agrupada(grupos: dict[str, list[dict]]) -> dict:
    """Arma la respuesta que devuelve Elasticsearch para `terms` + `top_hits`."""
    return {
        "aggregations": {
            "por_regla": {
                "buckets": [
                    {"key": regla, "doc_count": len(hits),
                     "recientes": {"hits": {"hits": hits}}}
                    for regla, hits in grupos.items()
                ]
            }
        }
    }


# ─── La consulta ─────────────────────────────────────────────────────────────

def test_la_consulta_agrupa_por_regla():
    consulta = siem_lib.alerts_query_por_regla(por_regla=5)

    terms = consulta["aggs"]["por_regla"]["terms"]
    assert terms["field"] == "kibana.alert.rule.name", "campo de agrupación"
    assert consulta["aggs"]["por_regla"]["aggs"]["recientes"]["top_hits"]["size"] == 5


def test_la_consulta_trae_las_mas_recientes_de_cada_grupo():
    top = siem_lib.alerts_query_por_regla()["aggs"]["por_regla"]["aggs"]["recientes"]
    orden = top["top_hits"]["sort"][0]["@timestamp"]["order"]
    assert orden == "desc", "dentro de cada regla, las más recientes primero"


def test_la_consulta_respeta_la_ventana_temporal():
    consulta = siem_lib.alerts_query_por_regla(window="24h")
    rango = consulta["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rango["gte"] == "now-24h"


def test_el_limite_de_reglas_es_generoso():
    """Con 13 reglas en el catálogo, un tope de 50 deja margen de sobra."""
    terms = siem_lib.alerts_query_por_regla()["aggs"]["por_regla"]["terms"]
    assert terms["size"] >= 20


def test_no_pide_documentos_sueltos():
    """`size: 0` — todo viene por la agregación, no por los hits de primer nivel."""
    assert siem_lib.alerts_query_por_regla()["size"] == 0


# ─── El aplanado ─────────────────────────────────────────────────────────────

def test_aplana_los_grupos_a_una_lista_de_hits(monkeypatch):
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: _respuesta_agrupada({
        "Regla ruidosa": [_hit("Regla ruidosa", "2026-09-25T10:00:00Z"),
                          _hit("Regla ruidosa", "2026-09-25T09:00:00Z")],
        "Regla crítica": [_hit("Regla crítica", "2026-09-25T08:00:00Z")],
    }))

    hits = siem_lib.es_search_por_grupo(".alerts-*", {})
    assert len(hits) == 3
    assert all("_source" in h for h in hits), "misma forma que es_search"


def test_devuelve_los_hits_ordenados_por_tiempo(monkeypatch):
    """Aunque vengan de grupos distintos, el resultado es cronológico."""
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: _respuesta_agrupada({
        "A": [_hit("A", "2026-09-25T08:00:00Z")],
        "B": [_hit("B", "2026-09-25T12:00:00Z")],
        "C": [_hit("C", "2026-09-25T10:00:00Z")],
    }))

    marcas = [h["_source"]["@timestamp"] for h in siem_lib.es_search_por_grupo(".alerts-*", {})]
    assert marcas == sorted(marcas, reverse=True)


def test_una_regla_ruidosa_no_desplaza_a_las_demas(monkeypatch):
    """**El defecto D-01, en una prueba.**

    Se reproduce la situación real: una regla con 96 alertas y otras siete con
    pocas. Con `size=10` a secas llegaban 10 de la ruidosa y cero del resto.
    """
    ruidosa = [_hit("Port Scan – Rapid Sequential Probe",
                    f"2026-09-25T12:{m:02d}:00Z") for m in range(59, 54, -1)]
    grupos = {
        "Port Scan – Rapid Sequential Probe": ruidosa,
        "SSH Successful Login After Brute Force": [
            _hit("SSH Successful Login After Brute Force", "2026-09-25T09:00:00Z",
                 {"kibana.alert.severity": "critical"})],
        "SSH Brute Force – Aggressive per Source IP": [
            _hit("SSH Brute Force – Aggressive per Source IP", "2026-09-25T09:05:00Z")],
        "Credential Submission to Suspicious Login": [
            _hit("Credential Submission to Suspicious Login", "2026-09-25T09:10:00Z")],
    }
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: _respuesta_agrupada(grupos))

    hits = siem_lib.es_search_por_grupo(".alerts-*", {})
    reglas = {h["_source"]["kibana.alert.rule.name"] for h in hits}

    assert reglas == set(grupos), f"se perdieron reglas: {set(grupos) - reglas}"
    assert "SSH Successful Login After Brute Force" in reglas, (
        "la detección crítica —la fuerza bruta funcionó— no llegó al clasificador")


def test_sin_alertas_devuelve_lista_vacia(monkeypatch):
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: {})
    assert siem_lib.es_search_por_grupo(".alerts-*", {}) == []


def test_un_grupo_vacio_no_rompe(monkeypatch):
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: {
        "aggregations": {"por_regla": {"buckets": [
            {"key": "Sin hits", "doc_count": 0, "recientes": {"hits": {"hits": []}}},
            {"key": "Con hits", "doc_count": 1,
             "recientes": {"hits": {"hits": [_hit("Con hits", "2026-09-25T10:00:00Z")]}}},
        ]}}})
    assert len(siem_lib.es_search_por_grupo(".alerts-*", {})) == 1


def test_un_hit_sin_timestamp_no_rompe_el_orden(monkeypatch):
    """Un documento sin `@timestamp` no puede tumbar el `sorted()`."""
    monkeypatch.setattr(siem_lib, "_es_request", lambda *a, **kw: _respuesta_agrupada({
        "A": [{"_source": {"kibana.alert.rule.name": "A"}}],
        "B": [_hit("B", "2026-09-25T10:00:00Z")],
    }))
    hits = siem_lib.es_search_por_grupo(".alerts-*", {})
    assert len(hits) == 2
    assert hits[0]["_source"].get("@timestamp") == "2026-09-25T10:00:00Z"


# ─── El pipeline la usa ──────────────────────────────────────────────────────

def test_prepare_for_ia_usa_la_consulta_agrupada():
    """Blindaje: si alguien vuelve a `alerts_query(size=10)`, el defecto regresa."""
    import pathlib

    fuente = (pathlib.Path(__file__).resolve().parent.parent.parent
              / "prepare-for-ia.py").read_text(encoding="utf-8")

    assert "alerts_query_por_regla" in fuente
    assert "es_search_por_grupo" in fuente
    assert "alerts_query(size=" not in fuente, (
        "volvió la consulta sin agrupar: una regla ruidosa taparía a las demás")


def test_la_consulta_sin_agrupar_sigue_existiendo_para_inspeccion():
    """`get-logs.py` la usa para mirar a mano; no se rompe su contrato."""
    consulta = siem_lib.alerts_query(size=5)
    assert consulta["size"] == 5
    assert "aggs" not in consulta


@pytest.mark.parametrize("por_regla", [1, 3, 5, 10])
def test_el_tamano_por_regla_es_configurable(por_regla):
    consulta = siem_lib.alerts_query_por_regla(por_regla=por_regla)
    assert consulta["aggs"]["por_regla"]["aggs"]["recientes"]["top_hits"]["size"] == por_regla
