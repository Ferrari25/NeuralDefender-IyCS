"""Proveedores de LLM del Agente 2: Gemma local (Ollama) o Gemini (API de Google).

Los dos exponen lo mismo — `generar_json(sistema, prompt, esquema, timeout)`,
que devuelve el texto JSON del modelo — y un nombre `fuente` que queda
registrado en cada análisis (`_source`), así el panel dice qué modelo lo
escribió. Ninguno tiene herramientas ni function calling: el modelo solo
devuelve texto, nunca actúa.

**Gemma (default).** Gemma 3 es el modelo abierto de Google. Corre en el
contenedor `ollama`, en la misma máquina: no necesita key, no tiene cuota y es
gratis. Además los datos del incidente no salen del equipo, y el contenedor
vive en una red sin salida a internet (`llm-net`, `internal: true`).

**Gemini.** La API de Google, con `GEMINI_API_KEY`. El modelo se elige con
`SIEM_GEMINI_MODELO`; con una key gratuita de AI Studio también sirve un Gemma
alojado por Google (por ejemplo `gemma-3-27b-it`).
"""

from __future__ import annotations

import os

import requests

GEMINI_MODELO_POR_DEFECTO = "gemini-flash-lite-latest"
OLLAMA_HOST_POR_DEFECTO = "http://ollama:11434"
OLLAMA_MODELO_POR_DEFECTO = "gemma3:4b"


class ClienteOllama:
    """Gemma local. Habla con la API HTTP de Ollama (`POST /api/chat`)."""

    fuente = "gemma"

    def __init__(self, host: str, modelo: str):
        self.host = host.rstrip("/")
        self.modelo = modelo

    def generar_json(self, sistema: str, prompt: str, esquema: dict, timeout: float) -> str:
        # `format` con un JSON Schema hace que Ollama restrinja la decodificación
        # al esquema: la respuesta es JSON válido aunque el modelo sea chico.
        r = requests.post(f"{self.host}/api/chat", json={
            "model": self.modelo,
            "messages": [{"role": "system", "content": sistema},
                         {"role": "user", "content": prompt}],
            "format": esquema,
            "stream": False,
            "options": {"temperature": 0.2},
        }, timeout=timeout)
        r.raise_for_status()
        return r.json()["message"]["content"]


class ClienteGemini:
    """Gemini (o Gemma alojado por Google) a través del SDK `google-genai`."""

    fuente = "gemini"

    def __init__(self, api_key: str, modelo: str):
        from google import genai
        self._cliente = genai.Client(api_key=api_key)
        self.modelo = modelo

    def generar_json(self, sistema: str, prompt: str, esquema: dict, timeout: float) -> str:
        del esquema, timeout  # el SDK no restringe por esquema ni corta por tiempo acá
        from google.genai import types
        config = types.GenerateContentConfig(
            system_instruction=sistema,
            response_mime_type="application/json",
            temperature=0.2,
        )
        resp = self._cliente.models.generate_content(model=self.modelo, contents=prompt,
                                                     config=config)
        return resp.text


def proveedor() -> str:
    """`gemma` (default) o `gemini`, según `SIEM_LLM_PROVEEDOR`."""
    valor = os.getenv("SIEM_LLM_PROVEEDOR", "").strip().lower()
    return "gemini" if valor == "gemini" else "gemma"


def construir() -> ClienteOllama | ClienteGemini | None:
    """El cliente del proveedor elegido, o None si no se puede armar.

    No decide si el LLM está prendido: eso es `SIEM_USE_LLM`, y lo mira
    `siem_agent._build_client()` antes de llamar acá.
    """
    if proveedor() == "gemma":
        host = os.getenv("SIEM_OLLAMA_HOST", "").strip() or OLLAMA_HOST_POR_DEFECTO
        modelo = os.getenv("SIEM_OLLAMA_MODELO", "").strip() or OLLAMA_MODELO_POR_DEFECTO
        print(f"[INFO] Agente 2 con Gemma local ({modelo} en {host}).")
        return ClienteOllama(host, modelo)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[INFO] Sin GEMINI_API_KEY: usando análisis determinístico (fallback).")
        return None
    modelo = os.getenv("SIEM_GEMINI_MODELO", "").strip() or GEMINI_MODELO_POR_DEFECTO
    try:
        return ClienteGemini(api_key, modelo)
    except Exception as e:  # SDK ausente o key inválida en init
        print(f"[WARN] No se pudo inicializar el cliente Gemini ({e}). Usando fallback.")
        return None
