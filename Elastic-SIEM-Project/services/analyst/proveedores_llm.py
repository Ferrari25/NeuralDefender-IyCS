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
alojado por Google (por ejemplo `gemma-3-27b-it`). Esos modelos `gemma-*`
rechazan la instrucción de sistema y el modo JSON de la API (400
INVALID_ARGUMENT), así que para ellos la instrucción va dentro del mensaje y el
JSON se pide en el texto: ver `ClienteGemini.generar_json`.

**Qué proveedor se usa.** `SIEM_LLM_PROVEEDOR` (`gemma` o `gemini`). Si no
está definido, siempre `gemma`: mandar los datos de los incidentes (IPs,
usuarios, muestras de log) a una API externa tiene que ser una decisión
explícita, nunca un efecto de haber dejado una key guardada en `.env`. Si hay
una `GEMINI_API_KEY` real y el proveedor no está definido, se avisa con un WARN
para que una instalación que antes usaba Gemini sepa por qué cambió.
"""

from __future__ import annotations

import os

import requests

GEMINI_MODELO_POR_DEFECTO = "gemini-flash-lite-latest"
OLLAMA_HOST_POR_DEFECTO = "http://ollama:11434"
OLLAMA_MODELO_POR_DEFECTO = "gemma3:4b"

# El valor de ejemplo de `.env.example` no es una key: no cuenta como configurada.
_KEYS_DE_EJEMPLO = {"your-gemini-api-key-here"}


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

    @property
    def _es_gemma(self) -> bool:
        # `gemma-3-27b-it`, `models/gemma-3-4b-it`, etc.
        return self.modelo.rsplit("/", 1)[-1].lower().startswith("gemma")

    def generar_json(self, sistema: str, prompt: str, esquema: dict, timeout: float) -> str:
        del esquema  # el SDK no restringe la decodificación por esquema acá
        from google.genai import types
        # Sin esto la llamada no tiene plazo: un 503/429 con reintentos podría
        # pasarse del presupuesto del LLM y del timeout del orquestador.
        http = types.HttpOptions(timeout=max(1000, int(timeout * 1000)))
        if self._es_gemma:
            # Gemma alojado no acepta `system_instruction` ni
            # `response_mime_type`: la instrucción va al principio del mensaje.
            config = types.GenerateContentConfig(temperature=0.2, http_options=http)
            contenido = (f"{sistema}\n\n{prompt}\n\nRespondé únicamente con el objeto JSON, "
                         "sin texto antes ni después y sin bloque de código.")
        else:
            config = types.GenerateContentConfig(
                system_instruction=sistema,
                response_mime_type="application/json",
                temperature=0.2,
                http_options=http,
            )
            contenido = prompt
        resp = self._cliente.models.generate_content(model=self.modelo, contents=contenido,
                                                     config=config)
        return _solo_json(resp.text or "")


def _solo_json(texto: str) -> str:
    """El objeto JSON de la respuesta, aunque venga en un bloque ```json``` o con texto alrededor.

    Los Gemma alojados no tienen modo JSON y suelen envolver la respuesta. Se
    toma desde la primera `{` hasta la última `}`; si no hay, se devuelve el
    texto tal cual y `json.loads` dirá qué está mal.
    """
    t = texto.strip()
    inicio, fin = t.find("{"), t.rfind("}")
    return t[inicio:fin + 1] if 0 <= inicio < fin else t


def _gemini_key() -> str:
    key = (os.getenv("GEMINI_API_KEY") or "").strip()
    return "" if key in _KEYS_DE_EJEMPLO else key


def proveedor() -> str:
    """`gemma` o `gemini`, según `SIEM_LLM_PROVEEDOR`. Sin la variable: `gemma`."""
    valor = os.getenv("SIEM_LLM_PROVEEDOR", "").strip().lower()
    if valor in ("gemma", "gemini"):
        return valor
    if valor:
        print(f"[WARN] SIEM_LLM_PROVEEDOR={valor!r} no es 'gemma' ni 'gemini': se usa gemma.")
    elif _gemini_key():
        print("[WARN] Hay una GEMINI_API_KEY pero SIEM_LLM_PROVEEDOR no está definido: se usa "
              "Gemma local. Para usar Gemini, definir SIEM_LLM_PROVEEDOR=gemini en .env.")
    return "gemma"


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

    api_key = _gemini_key()
    if not api_key:
        print("[INFO] Sin GEMINI_API_KEY: usando análisis determinístico (fallback).")
        return None
    modelo = os.getenv("SIEM_GEMINI_MODELO", "").strip() or GEMINI_MODELO_POR_DEFECTO
    try:
        print(f"[INFO] Agente 2 con Gemini ({modelo}).")
        return ClienteGemini(api_key, modelo)
    except Exception as e:  # SDK ausente o key inválida en init
        print(f"[WARN] No se pudo inicializar el cliente Gemini ({e}). Usando fallback.")
        return None
