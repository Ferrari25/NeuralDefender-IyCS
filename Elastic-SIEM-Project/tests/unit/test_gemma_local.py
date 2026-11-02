"""Gemma 3 local (Ollama) como LLM del Agente 2.

No se levanta Ollama: se reemplaza `requests.post` y se verifica qué se le
manda (modelo, instrucción del sistema, esquema JSON, sin herramientas) y qué
hace el Agente 2 con lo que vuelve — incluido el caso de Ollama caído o sin
el modelo bajado, que tiene que terminar en el fallback, nunca en un error.
"""

from __future__ import annotations

import json

import pytest
import requests

import proveedores_llm
import siem_agent

INCIDENTE = {
    "incident_id": "INC-G-1",
    "classification": {"severity": "alta", "attack_type": "port_scan",
                       "false_positive_likelihood": "baja", "mitre_technique": "T1046"},
    "source_ip": "198.51.100.5", "attacker_ips": ["198.51.100.5"], "event_count": 26,
    "recommended_actions": [{"orden": 1, "accion": "Bloquear la IP", "impacto": "bajo",
                             "plazo": "inmediato", "responsable": "SOC", "status": "pending",
                             "comando_sugerido": "ufw deny from 198.51.100.5"}],
}

RESPUESTA = {
    "explicacion": "Escaneo de 26 puertos desde 198.51.100.5.",
    "metodologia": "Nmap SYN scan.", "contexto_riesgo": "Reconocimiento previo.",
    "severidad_ajustada": "HIGH", "accion_recomendada": "Priorizar (1) Bloquear la IP.",
    "falso_positivo_probabilidad": "LOW", "referencias": ["T1046"],
    "puntos_de_investigacion": ["¿198.51.100.5 escaneó otros hosts?"],
}


class _Resp:
    def __init__(self, cuerpo: dict, status: int = 200):
        self._cuerpo, self.status_code = cuerpo, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        return self._cuerpo


@pytest.fixture
def enviado(monkeypatch):
    """Captura la petición a Ollama y responde como lo haría Gemma."""
    capturado: dict = {}

    def falso_post(url, **kwargs):
        capturado.update(url=url, cuerpo=kwargs["json"], timeout=kwargs["timeout"])
        return _Resp({"message": {"role": "assistant", "content": json.dumps(RESPUESTA)}})

    monkeypatch.setattr(proveedores_llm.requests, "post", falso_post)
    return capturado


def _cliente():
    return proveedores_llm.ClienteOllama("http://ollama:11434", "gemma3:4b")


def test_la_peticion_a_ollama_lleva_modelo_sistema_y_esquema(enviado):
    siem_agent.analyze_incident(_cliente(), dict(INCIDENTE), "sin antecedentes", None, timeout=42)

    cuerpo = enviado["cuerpo"]
    assert enviado["url"] == "http://ollama:11434/api/chat"
    assert enviado["timeout"] == 42
    assert cuerpo["model"] == "gemma3:4b" and cuerpo["stream"] is False
    assert cuerpo["messages"][0] == {"role": "system", "content": siem_agent.SYSTEM_INSTRUCTION}
    assert "<DATOS_INCIDENTE>" in cuerpo["messages"][1]["content"]
    assert cuerpo["format"] == siem_agent.ESQUEMA_ANALISIS
    # Sin herramientas: el modelo solo puede devolver texto.
    assert "tools" not in cuerpo


def test_el_prompt_nunca_lleva_el_comando_del_playbook(enviado):
    siem_agent.analyze_incident(_cliente(), dict(INCIDENTE), "sin antecedentes", None)
    assert "ufw deny" not in json.dumps(enviado["cuerpo"])


def test_el_esquema_no_tiene_campos_de_comando():
    assert not any("comando" in c for c in siem_agent.ESQUEMA_ANALISIS["properties"])


def test_el_analisis_queda_marcado_como_gemma(enviado):
    del enviado
    analisis = siem_agent.analyze_incident(_cliente(), dict(INCIDENTE), "sin antecedentes", None)
    assert analisis["_source"] == "gemma"
    assert analisis["_modelo"] == "gemma3:4b"
    assert analisis["explicacion"] == RESPUESTA["explicacion"]
    assert analisis["puntos_de_investigacion"] == RESPUESTA["puntos_de_investigacion"]


@pytest.mark.parametrize("falla", [
    requests.ConnectionError("ollama caído"),
    requests.HTTPError("404 model 'gemma3:4b' not found"),
    requests.Timeout("se pasó del tiempo"),
])
def test_ollama_caido_o_sin_modelo_cae_al_fallback(monkeypatch, falla):
    def explota(*args, **kwargs):
        del args, kwargs
        raise falla

    monkeypatch.setattr(proveedores_llm.requests, "post", explota)
    analisis = siem_agent.analyze_incident(_cliente(), dict(INCIDENTE), "sin antecedentes", None)
    assert analisis["_source"] == "fallback"


def test_una_respuesta_que_no_es_un_objeto_cae_al_fallback(monkeypatch):
    monkeypatch.setattr(proveedores_llm.requests, "post", lambda *a, **k: _Resp(
        {"message": {"content": "[1, 2, 3]"}}))
    analisis = siem_agent.analyze_incident(_cliente(), dict(INCIDENTE), "sin antecedentes", None)
    assert analisis["_source"] == "fallback"


def test_el_modo_de_la_corrida_es_gemma(monkeypatch, enviado):
    del enviado
    monkeypatch.setenv("SIEM_USE_LLM", "true")
    monkeypatch.delenv("SIEM_LLM_PROVEEDOR", raising=False)
    resultado = siem_agent.analizar([dict(INCIDENTE)], [], {})
    assert resultado["analyst_mode"] == "gemma"


def test_agotado_el_presupuesto_el_resto_va_al_fallback(monkeypatch, enviado):
    """Gemma en CPU es lento: con presupuesto 0 nadie llega a llamar al LLM."""
    monkeypatch.setenv("SIEM_USE_LLM", "true")
    monkeypatch.setenv("SIEM_LLM_PRESUPUESTO", "0")
    monkeypatch.delenv("SIEM_LLM_PROVEEDOR", raising=False)
    incidentes = [dict(INCIDENTE, incident_id=f"INC-G-{n}") for n in range(3)]
    resultado = siem_agent.analizar(incidentes, [], {})
    assert "url" not in enviado
    assert resultado["analyst_mode"] == "fallback"
    assert {i["analysis"]["_source"] for i in resultado["incidents"]} == {"fallback"}


@pytest.mark.parametrize("valor, esperado", [("", 480), ("abc", 480), ("-5", 0), ("120", 120)])
def test_presupuesto_desde_el_entorno(monkeypatch, valor: str, esperado: float):
    monkeypatch.setenv("SIEM_LLM_PRESUPUESTO", valor)
    assert siem_agent._presupuesto_llm() == esperado
