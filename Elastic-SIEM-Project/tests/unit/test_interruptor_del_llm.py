"""El Agente 2 gasta tokens solo si `SIEM_USE_LLM=true` (pedido directo del
analista: quiere poder prender/apagar el consumo de tokens fácil).

Antes, tener `GEMINI_API_KEY` en `.env` ERA la única condición para que el
Agente 2 llamara a Gemini de verdad. Eso significa que guardar la key —para no
tener que volver a buscarla— ya implicaba gastar tokens en cada corrida del
pipeline, sin un paso explícito de "esto sí, esto no".

Ahora hay dos condiciones, no una: la key sigue siendo necesaria, pero además
hace falta `SIEM_USE_LLM=true`. Apagado por defecto: si la variable no está, o
vale cualquier cosa que no sea "true" (insensible a mayúsculas), el Agente 2
nunca intenta llamar a la API, tenga o no una key válida guardada.
"""

from __future__ import annotations

import pytest

import siem_agent


@pytest.fixture(autouse=True)
def _sin_variables_de_entorno_previas(monkeypatch):
    """Ningún test de este archivo hereda el entorno real de la máquina."""
    monkeypatch.delenv("SIEM_USE_LLM", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


# ─── `_llm_habilitado()` ──────────────────────────────────────────────────────

def test_apagado_por_defecto_sin_la_variable():
    assert siem_agent._llm_habilitado() is False


@pytest.mark.parametrize("valor", ["false", "0", "no", "", "  ", "apagado", "TRUE_ISH"])
def test_cualquier_valor_que_no_sea_true_queda_apagado(monkeypatch, valor: str):
    monkeypatch.setenv("SIEM_USE_LLM", valor)
    assert siem_agent._llm_habilitado() is False


@pytest.mark.parametrize("valor", ["true", "True", "TRUE", "1", "yes", " true "])
def test_se_tolera_mayusculas_y_espacios_para_prenderlo(monkeypatch, valor: str):
    monkeypatch.setenv("SIEM_USE_LLM", valor)
    assert siem_agent._llm_habilitado() is True


# ─── `_build_client()`: la key sola no alcanza ───────────────────────────────

def test_con_key_pero_sin_el_interruptor_no_construye_cliente(monkeypatch):
    """**El caso que motivó el cambio.** Antes esto SÍ armaba un cliente real."""
    monkeypatch.setenv("GEMINI_API_KEY", "una-key-cualquiera")
    assert siem_agent._build_client() is None


def test_con_el_interruptor_pero_sin_key_tampoco_construye_cliente(monkeypatch):
    monkeypatch.setenv("SIEM_USE_LLM", "true")
    assert siem_agent._build_client() is None


def test_ninguna_de_las_dos_es_igual_a_no_tener_ninguna(monkeypatch):
    assert siem_agent._build_client() is None


# ─── `analyze_incident()`: con el interruptor apagado, nunca pega a la red ───

def test_analyze_incident_no_intenta_llm_con_el_interruptor_apagado(monkeypatch):
    """Ni siquiera con una key con pinta de válida: `analyze_incident` recibe
    `None` como cliente (viene de `_build_client()`) y usa el fallback — no hay
    forma de que esto dispare una llamada de red por accidente."""
    monkeypatch.setenv("GEMINI_API_KEY", "una-key-cualquiera")
    cliente = siem_agent._build_client()
    incidente = {"incident_id": "INC-T-1",
                 "classification": {"severity": "alta", "attack_type": "port_scan",
                                    "false_positive_likelihood": "baja", "mitre_technique": "T1046"},
                 "source_ip": "198.51.100.5", "event_count": 26, "recommended_actions": []}

    analisis = siem_agent.analyze_incident(cliente, incidente, "sin antecedentes", None)
    assert analisis["_source"] == "fallback"
