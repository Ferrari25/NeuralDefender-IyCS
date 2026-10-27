"""Corrida programada del pipeline (sección 7.9.2 de la ERS, RNF-RD-07).

Antes el ciclo solo corría a mano: una alerta nueva de Kibana no llegaba al panel
hasta que alguien ejecutara `./scripts/siem.sh pipeline`. Ahora el servicio
pipeline corre un ciclo cada `SIEM_PIPELINE_INTERVALO` segundos
(docker-compose.yml lo fija en 120).

Lo que se certifica:
  - un turno programado corre el MISMO ciclo que la API y deja el reporte;
  - si hay un ciclo manual en curso, el turno se saltea (no se encima ni espera);
  - un ciclo que falla no detiene al programador ni toca el reporte anterior;
  - apagado por defecto: importar el servicio (pruebas, CLI) no dispara ciclos;
  - un intervalo inválido o demasiado corto es un error, no se adivina;
  - el contenedor lo trae encendido cada 2 minutos.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def programador(monkeypatch):
    import programador as mod

    monkeypatch.delenv(mod.VARIABLE, raising=False)
    yield mod
    mod.detener()


@pytest.fixture
def ciclo_offline(sandbox, servicio_caido, network_logs_dir, copiar_fixture, monkeypatch):
    """Un ciclo que puede correr sin Elasticsearch: clasifica desde network_logs/."""
    monkeypatch.setenv("SIEM_USE_LLM", "false")
    for archivo in network_logs_dir.glob("*.json"):
        copiar_fixture(archivo, sandbox / "network_logs")
    import classifier_service
    import siem_lib
    monkeypatch.setattr(classifier_service, "read_network_logs",
                        lambda d, *_: siem_lib.read_network_logs(d, window_hours=None))
    servicio_caido("collector")
    return sandbox


def test_un_turno_corre_el_ciclo_completo_y_deja_el_reporte(programador, ciclo_offline):
    resultado = programador.correr_un_turno()

    assert resultado.startswith("ok:"), resultado
    assert (ciclo_offline / "data" / "siem_incidents.json").exists()


def test_si_hay_un_ciclo_manual_en_curso_el_turno_se_saltea(programador, ciclo_offline):
    import orquestador

    assert orquestador._en_curso.acquire(blocking=False)
    try:
        resultado = programador.correr_un_turno()
    finally:
        orquestador._en_curso.release()

    assert resultado.startswith("salteado")
    assert not (ciclo_offline / "data" / "siem_incidents.json").exists()


def test_un_ciclo_que_falla_no_rompe_el_programador(programador, sandbox, servicio_caido):
    """Sin classifier (etapa crítica) el ciclo falla: el turno lo informa y vuelve."""
    servicio_caido("collector", "classifier")

    resultado = programador.correr_un_turno()

    assert resultado.startswith("falló:")
    assert "classifier" in resultado
    assert not (sandbox / "data" / "siem_incidents.json").exists()


def test_apagado_por_defecto(programador):
    assert programador.intervalo_configurado() == 0
    assert programador.iniciar() is False


@pytest.mark.parametrize("valor", ["", "0"])
def test_vacio_o_cero_lo_apagan(programador, monkeypatch, valor):
    monkeypatch.setenv(programador.VARIABLE, valor)
    assert programador.intervalo_configurado() == 0


@pytest.mark.parametrize("valor, error", [
    ("dos minutos", "número de segundos"),
    ("10", "mínimo"),
    ("-5", "mínimo"),
])
def test_un_intervalo_invalido_es_un_error(programador, monkeypatch, valor, error):
    monkeypatch.setenv(programador.VARIABLE, valor)
    with pytest.raises(ValueError, match=error):
        programador.intervalo_configurado()


def test_encendido_arranca_un_solo_hilo(programador, monkeypatch):
    monkeypatch.setenv(programador.VARIABLE, "120")

    assert programador.iniciar() is True
    assert programador.iniciar() is False   # idempotente: no lanza un segundo hilo
    assert programador._hilo.daemon         # no impide que el proceso termine


def test_el_contenedor_corre_el_pipeline_cada_dos_minutos():
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    pipeline = compose.split("\n  pipeline:\n")[1].split("\n  # ")[0]
    assert "SIEM_PIPELINE_INTERVALO=${SIEM_PIPELINE_INTERVALO:-120}" in pipeline
