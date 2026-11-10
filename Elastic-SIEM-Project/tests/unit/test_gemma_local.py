"""Gemma 3 local (Ollama) como LLM del Agente 2.

No se levanta Ollama: se reemplaza `requests.post` y se verifica qué se le
manda (modelo, instrucción del sistema, esquema JSON, sin herramientas) y qué
hace el Agente 2 con lo que vuelve — incluido el caso de Ollama caído o sin
el modelo bajado, que tiene que terminar en el fallback, nunca en un error.
"""

from __future__ import annotations

import json
import time

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
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    resultado = siem_agent.analizar([dict(INCIDENTE)], [], {})
    assert resultado["analyst_mode"] == "gemma"


def test_agotado_el_presupuesto_el_resto_va_al_fallback(monkeypatch, enviado):
    """Gemma en CPU es lento: con presupuesto 0 nadie llega a llamar al LLM."""
    monkeypatch.setenv("SIEM_USE_LLM", "true")
    monkeypatch.setenv("SIEM_LLM_PRESUPUESTO", "0")
    monkeypatch.delenv("SIEM_LLM_PROVEEDOR", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    incidentes = [dict(INCIDENTE, incident_id=f"INC-G-{n}") for n in range(3)]
    resultado = siem_agent.analizar(incidentes, [], {})
    assert "url" not in enviado
    assert resultado["analyst_mode"] == "fallback"
    assert {i["analysis"]["_source"] for i in resultado["incidents"]} == {"fallback"}


@pytest.mark.parametrize("valor, esperado", [
    ("", 480), ("abc", 480), ("-5", 0), ("120", 120),
    # Por encima del techo se recorta: el orquestador corta a los 600 s.
    ("900", 540), ("inf", 480), ("nan", 480)])
def test_presupuesto_desde_el_entorno(monkeypatch, valor: str, esperado: float):
    monkeypatch.setenv("SIEM_LLM_PRESUPUESTO", valor)
    assert siem_agent._presupuesto_llm() == esperado


def test_el_techo_del_presupuesto_cabe_en_el_timeout_del_orquestador():
    """Si el análisis dura más que lo que espera el orquestador, el ciclo falla."""
    import importlib.util
    from pathlib import Path
    ruta = Path(__file__).resolve().parents[2] / "services" / "pipeline" / "orquestador.py"
    spec = importlib.util.spec_from_file_location("orquestador_techo", ruta)
    orquestador = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orquestador)
    # Margen para las consultas a audit y knowledge previas al LLM.
    assert siem_agent.PRESUPUESTO_LLM_MAXIMO + 30 <= orquestador.TIMEOUT_ANALISIS


# ─── Proveedor por defecto ───────────────────────────────────────────────────

@pytest.mark.parametrize("variable, key, esperado", [
    ("", "", "gemma"),
    ("", "your-gemini-api-key-here", "gemma"),   # el valor de ejemplo no es una key
    ("", "AIza-real", "gemma"),                  # Gemini nunca por omisión: los datos saldrían
    ("gemma", "AIza-real", "gemma"),
    ("gemini", "", "gemini"),
    ("cualquiera", "", "gemma"),
])
def test_proveedor_por_defecto(monkeypatch, variable, key, esperado):
    monkeypatch.setenv("SIEM_LLM_PROVEEDOR", variable)
    monkeypatch.setenv("GEMINI_API_KEY", key)
    assert proveedores_llm.proveedor() == esperado


# ─── Gemini: plazo por llamada y Gemma alojado ───────────────────────────────

class _ModelosFalsos:
    def __init__(self, texto: str):
        self.texto, self.pedido = texto, {}

    def generate_content(self, **kwargs):
        self.pedido.update(kwargs)
        return type("R", (), {"text": self.texto})()


def _cliente_gemini(modelo: str, texto: str):
    cliente = proveedores_llm.ClienteGemini.__new__(proveedores_llm.ClienteGemini)
    cliente.modelo = modelo
    modelos = _ModelosFalsos(texto)
    cliente._cliente = type("C", (), {"models": modelos})()
    return cliente, modelos


def test_gemini_respeta_el_timeout_de_la_llamada():
    pytest.importorskip("google.genai")
    cliente, modelos = _cliente_gemini("gemini-flash-lite-latest", "{}")
    cliente.generar_json("SIS", "PROMPT", {}, timeout=12.5)
    config = modelos.pedido["config"]
    assert config.http_options.timeout == 12500
    assert config.system_instruction == "SIS"
    assert config.response_mime_type == "application/json"
    assert modelos.pedido["contents"] == "PROMPT"


def test_gemma_alojado_no_usa_instruccion_de_sistema_ni_modo_json():
    """La API rechaza ambas cosas para `gemma-*` (400 INVALID_ARGUMENT)."""
    pytest.importorskip("google.genai")
    cliente, modelos = _cliente_gemini("gemma-3-27b-it", '```json\n{"a": 1}\n```')
    texto = cliente.generar_json("SIS", "PROMPT", {}, timeout=30)
    config = modelos.pedido["config"]
    assert config.system_instruction is None
    assert config.response_mime_type is None
    assert config.http_options.timeout == 30000
    assert modelos.pedido["contents"].startswith("SIS\n\nPROMPT")
    assert json.loads(texto) == {"a": 1}


# ─── Reutilización entre ciclos ──────────────────────────────────────────────

def _contador_de_llamadas(monkeypatch) -> list:
    llamadas: list = []

    def falso_post(url, **kwargs):
        llamadas.append(url)
        return _Resp({"message": {"role": "assistant", "content": json.dumps(RESPUESTA)}})

    monkeypatch.setattr(proveedores_llm.requests, "post", falso_post)
    monkeypatch.setenv("SIEM_USE_LLM", "true")
    monkeypatch.setenv("SIEM_LLM_PROVEEDOR", "gemma")
    monkeypatch.delenv("SIEM_LLM_REUSO", raising=False)
    return llamadas


def test_un_incidente_sin_cambios_reutiliza_el_analisis(monkeypatch):
    llamadas = _contador_de_llamadas(monkeypatch)
    primero = siem_agent.analizar([dict(INCIDENTE)], [], {})
    previos = {i["incident_id"]: i["analysis"] for i in primero["incidents"]}
    # Solo cambian cifras que la huella ignora a propósito.
    segundo = siem_agent.analizar([dict(INCIDENTE, event_count=30, last_seen="otro")],
                                  [], {}, previos)
    assert len(llamadas) == 1
    assert segundo["analyst_mode"] == "gemma"
    assert segundo["incidents"][0]["analysis"]["explicacion"] == RESPUESTA["explicacion"]


def test_un_cambio_relevante_vuelve_a_pasar_por_el_llm(monkeypatch):
    llamadas = _contador_de_llamadas(monkeypatch)
    primero = siem_agent.analizar([dict(INCIDENTE)], [], {})
    previos = {i["incident_id"]: i["analysis"] for i in primero["incidents"]}
    cambiado = dict(INCIDENTE, attacker_ips=["198.51.100.5", "203.0.113.9"])
    siem_agent.analizar([cambiado], [], {}, previos)
    assert len(llamadas) == 2


def test_un_analisis_viejo_o_del_fallback_no_se_reutiliza(monkeypatch):
    llamadas = _contador_de_llamadas(monkeypatch)
    primero = siem_agent.analizar([dict(INCIDENTE)], [], {})
    previo = primero["incidents"][0]["analysis"]

    viejo = dict(previo, _generado_ts=previo["_generado_ts"] - 7200)
    siem_agent.analizar([dict(INCIDENTE)], [], {}, {"INC-G-1": viejo})
    assert len(llamadas) == 2

    del_fallback = dict(previo, _source="fallback")
    siem_agent.analizar([dict(INCIDENTE)], [], {}, {"INC-G-1": del_fallback})
    assert len(llamadas) == 3

    otro_modelo = dict(previo, _modelo="gemma3:1b")
    siem_agent.analizar([dict(INCIDENTE)], [], {}, {"INC-G-1": otro_modelo})
    assert len(llamadas) == 4


def test_sin_proveedor_y_con_key_avisa_que_usa_gemma(monkeypatch, capsys):
    monkeypatch.delenv("SIEM_LLM_PROVEEDOR", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-real")
    assert proveedores_llm.proveedor() == "gemma"
    assert "SIEM_LLM_PROVEEDOR=gemini" in capsys.readouterr().out


@pytest.mark.parametrize("respuesta", [
    '```json {"a": 1}```',                                 # cerco y JSON en una sola línea
    'Aquí está el análisis:\n```json\n{"a": 1}\n```\nEspero que sirva.',
    '{"a": 1}',
])
def test_solo_json_rescata_el_objeto(respuesta):
    assert json.loads(proveedores_llm._solo_json(respuesta)) == {"a": 1}


# ─── Huella: qué invalida un análisis reutilizable ───────────────────────────

def _h(inc):
    return siem_agent._huella(inc, "sin antecedentes", None, {})


def test_la_huella_cambia_si_cambia_el_perfil_o_el_prompt(monkeypatch):
    antes = _h(dict(INCIDENTE))
    monkeypatch.setattr(siem_agent, "SYSTEM_INSTRUCTION", siem_agent.SYSTEM_INSTRUCTION + " nuevo")
    assert _h(dict(INCIDENTE)) != antes
    monkeypatch.undo()
    monkeypatch.setattr(siem_agent, "PROMPT_INSTRUCCIONES", siem_agent.PROMPT_INSTRUCCIONES + "x")
    assert _h(dict(INCIDENTE)) != antes


def test_la_huella_sigue_el_volumen_por_orden_de_magnitud():
    base = _h(dict(INCIDENTE, event_count=25))
    assert _h(dict(INCIDENTE, event_count=27)) == base       # mismo orden de magnitud
    assert _h(dict(INCIDENTE, event_count=4000)) != base     # el ataque creció


def test_la_huella_incluye_factores_sin_atarse_a_las_cifras():
    def con(factores):
        c = dict(INCIDENTE["classification"], factores=factores)
        return _h(dict(INCIDENTE, classification=c))
    base = con(["181 fallo(s) de autenticación"])
    assert con(["190 fallo(s) de autenticación"]) == base
    assert con(["181 fallo(s) de autenticación", "Host atacado: 10.0.0.5"]) != base


def test_la_huella_cambia_si_se_reordenan_las_acciones():
    a1 = dict(INCIDENTE["recommended_actions"][0], orden=1, accion="Bloquear la IP")
    a2 = dict(a1, orden=2, accion="Habilitar fail2ban")
    normal = _h(dict(INCIDENTE, recommended_actions=[a1, a2]))
    invertido = _h(dict(INCIDENTE, recommended_actions=[dict(a1, orden=2), dict(a2, orden=1)]))
    assert normal != invertido


def test_la_vigencia_se_reparte_entre_incidentes(monkeypatch):
    monkeypatch.setenv("SIEM_LLM_REUSO", "3600")
    vidas = {siem_agent._vida_util(f"INC-{n}") for n in range(20)}
    assert all(2700 <= v <= 3600 for v in vidas)
    assert len(vidas) > 1


def test_sin_tiempo_se_mantiene_el_analisis_vencido_en_vez_del_fallback(monkeypatch):
    llamadas = _contador_de_llamadas(monkeypatch)
    primero = siem_agent.analizar([dict(INCIDENTE)], [], {})
    previo = primero["incidents"][0]["analysis"]
    vencido = dict(previo, _generado_ts=previo["_generado_ts"] - 7200)
    monkeypatch.setenv("SIEM_LLM_PRESUPUESTO", "0")
    segundo = siem_agent.analizar([dict(INCIDENTE)], [], {}, {"INC-G-1": vencido})
    assert len(llamadas) == 1
    assert segundo["incidents"][0]["analysis"]["_source"] == "gemma"


def test_el_plazo_de_quien_pide_corta_el_llm(monkeypatch):
    llamadas = _contador_de_llamadas(monkeypatch)
    resultado = siem_agent.analizar([dict(INCIDENTE)], [], {}, None,
                                    fin_plazo=time.monotonic() - 1)
    assert llamadas == []
    assert resultado["analyst_mode"] == "fallback"
