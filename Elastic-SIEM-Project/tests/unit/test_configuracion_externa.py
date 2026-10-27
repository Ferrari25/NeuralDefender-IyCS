"""Umbrales y ventana por configuración externa (RNF-MANT-04 · RNF-PORT-05, punto A5).

Antes `BRUTE_FORCE_THRESHOLD`, `CRITICAL_FAILURE_COUNT` y
`PORT_SCAN_DISTINCT_PORTS` eran constantes del código y la ventana era
`WINDOW = "24h"`: cambiarlos exigía reconstruir la imagen. Ahora salen del
entorno al arrancar el servicio.

Lo que se certifica:
  - sin variables, los valores de la ERS (20 / 5000 / 10 / 24h);
  - con variables, el clasificador detecta con el umbral nuevo;
  - un valor inválido NO cae en silencio al valor por defecto: el servicio no
    arranca y el mensaje nombra la variable;
  - el collector y el clasificador usan la MISMA ventana.
"""

from __future__ import annotations

import importlib

import pytest

import siem_lib


@pytest.fixture
def recargar(monkeypatch):
    """Recarga un módulo con el entorno dado y lo deja como estaba al terminar."""
    recargados = []

    def _recargar(modulo, **entorno):
        for variable, valor in entorno.items():
            monkeypatch.setenv(variable, valor)
        recargados.append(modulo)
        return importlib.reload(modulo)

    yield _recargar
    monkeypatch.undo()
    for modulo in recargados:
        importlib.reload(modulo)


# ─── siem_lib ────────────────────────────────────────────────────────────────

def test_entero_de_entorno_sin_variable_usa_el_defecto(monkeypatch):
    monkeypatch.delenv("SIEM_X", raising=False)
    assert siem_lib.entero_de_entorno("SIEM_X", 20) == 20


def test_entero_de_entorno_lee_la_variable(monkeypatch):
    monkeypatch.setenv("SIEM_X", " 35 ")
    assert siem_lib.entero_de_entorno("SIEM_X", 20) == 35


@pytest.mark.parametrize("valor", ["veinte", "2.5", "0", "-3"])
def test_entero_de_entorno_rechaza_valores_invalidos(monkeypatch, valor):
    monkeypatch.setenv("SIEM_X", valor)
    with pytest.raises(ValueError, match="SIEM_X"):
        siem_lib.entero_de_entorno("SIEM_X", 20)


@pytest.mark.parametrize(("ventana", "horas"), [("24h", 24), ("90m", 1.5), ("7d", 168)])
def test_la_ventana_acepta_minutos_horas_y_dias(monkeypatch, ventana, horas):
    monkeypatch.setenv("SIEM_VENTANA", ventana)
    assert siem_lib.ventana_de_analisis() == ventana
    assert siem_lib.ventana_en_horas(ventana) == horas


def test_sin_ventana_es_la_de_la_ers(monkeypatch):
    monkeypatch.delenv("SIEM_VENTANA", raising=False)
    assert siem_lib.ventana_de_analisis() == "24h"


@pytest.mark.parametrize("ventana", ["24", "h", "0h", "24w", "1h/d", "now-1h", "24h||"])
def test_la_ventana_rechaza_lo_que_no_es_una_duracion(monkeypatch, ventana):
    """La ventana se interpola en la consulta a Elasticsearch (`now-<ventana>`):
    solo pasa un número y una unidad."""
    monkeypatch.setenv("SIEM_VENTANA", ventana)
    with pytest.raises(ValueError, match="SIEM_VENTANA"):
        siem_lib.ventana_de_analisis()


# ─── clasificador ────────────────────────────────────────────────────────────

def _fallos(n: int) -> dict:
    return {"alerts": [], "auth_failure_logs": [
        {"timestamp": f"2026-10-27T10:00:{i % 60:02d}Z",
         "message": f"Failed password for root from 203.0.113.5 port {40000 + i} ssh2",
         "host_ip": "172.18.0.7"} for i in range(n)]}


def test_sin_variables_los_umbrales_son_los_de_la_ers(recargar, monkeypatch):
    for v in ("SIEM_UMBRAL_FUERZA_BRUTA", "SIEM_UMBRAL_CRITICO", "SIEM_UMBRAL_PUERTOS"):
        monkeypatch.delenv(v, raising=False)
    import classifier
    mod = recargar(classifier)
    assert (mod.BRUTE_FORCE_THRESHOLD, mod.CRITICAL_FAILURE_COUNT,
            mod.PORT_SCAN_DISTINCT_PORTS) == (20, 5000, 10)


def test_el_umbral_de_fuerza_bruta_se_ajusta_sin_reconstruir(recargar):
    import classifier
    assert classifier.detect_auth_incidents(_fallos(8))[0]["classification"]["attack_type"] \
        != "ssh_brute_force"

    mod = recargar(classifier, SIEM_UMBRAL_FUERZA_BRUTA="5")
    assert mod.detect_auth_incidents(_fallos(8))[0]["classification"]["attack_type"] \
        == "ssh_brute_force"


def test_el_umbral_de_puertos_se_ajusta_sin_reconstruir(recargar):
    import classifier
    eventos = [{"event_type": "network_flow", "source_ip": "203.0.113.5",
                "dest_ip": "172.18.0.5", "dest_port": p} for p in (22, 80, 443, 3389)]
    assert classifier.detect_port_scans(eventos) == []

    mod = recargar(classifier, SIEM_UMBRAL_PUERTOS="4")
    assert len(mod.detect_port_scans(eventos)) == 1


def test_un_umbral_invalido_impide_arrancar(recargar):
    import classifier
    with pytest.raises(ValueError, match="SIEM_UMBRAL_PUERTOS"):
        recargar(classifier, SIEM_UMBRAL_PUERTOS="diez")


def test_el_critico_tiene_que_superar_al_de_fuerza_bruta(recargar):
    import classifier
    with pytest.raises(ValueError, match="SIEM_UMBRAL_CRITICO"):
        recargar(classifier, SIEM_UMBRAL_FUERZA_BRUTA="50", SIEM_UMBRAL_CRITICO="50")


# ─── collector y clasificador comparten la ventana ──────────────────────────

def test_collector_y_clasificador_usan_la_misma_ventana(recargar):
    import classifier_service
    import collector

    col = recargar(collector, SIEM_VENTANA="90m")
    cla = recargar(classifier_service, SIEM_VENTANA="90m")
    assert col.WINDOW == "90m"
    assert col.build_summary([], [], [])["window"] == "90m"
    assert cla.VENTANA_HORAS == 1.5
