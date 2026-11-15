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
`SIEM_GEMINI_MODELO`.

**Gemma en la nube (`gemma-nube`).** El mismo Gemma abierto, pero alojado por
Google y servido por la misma API de Gemini (misma `GEMINI_API_KEY`, gratis en
AI Studio). Sale de `SIEM_GEMMA_NUBE_MODELO`, por defecto `gemma-4-26b-a4b-it`
(MoE: ~8 s por incidente, contra ~75 s de Gemma 3 4b en CPU). Igual que
Gemini, los datos del incidente salen del equipo. Los Gemma 3 alojados
rechazaban la instrucción de sistema y el modo JSON (400 INVALID_ARGUMENT); a
esos la instrucción va dentro del mensaje: ver `ClienteGemini.generar_json`.
Los Gemma 4 aceptan las dos cosas.

**Qué proveedor se usa.** `SIEM_LLM_PROVEEDOR` (`gemma`, `gemma-nube` o
`gemini`). Si no está definido, siempre `gemma`: mandar los datos de los incidentes (IPs,
usuarios, muestras de log) a una API externa tiene que ser una decisión
explícita, nunca un efecto de haber dejado una key guardada en `.env`. Si hay
una `GEMINI_API_KEY` real y el proveedor no está definido, se avisa con un WARN
para que una instalación que antes usaba Gemini sepa por qué cambió.
"""

from __future__ import annotations

import os
import time

import requests

GEMINI_MODELO_POR_DEFECTO = "gemini-flash-lite-latest"
OLLAMA_HOST_POR_DEFECTO = "http://ollama:11434"
OLLAMA_MODELO_POR_DEFECTO = "gemma3:4b"
GEMMA_NUBE_MODELO_POR_DEFECTO = "gemma-4-26b-a4b-it"

PROVEEDORES = ("gemma", "gemma-nube", "gemini")

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
    """Gemini (o Gemma alojado por Google) a través del SDK `google-genai`.

    `fuente` es `gemini` o `gemma-nube`: lo que queda en `_source` de cada análisis.
    """

    def __init__(self, api_key: str, modelo: str, fuente: str = "gemini"):
        from google import genai
        self._cliente = genai.Client(api_key=api_key)
        self.modelo = modelo
        self.fuente = fuente

    @property
    def _es_gemma(self) -> bool:
        # Solo los Gemma 3 alojados (`gemma-3-27b-it`, `models/gemma-3-4b-it`)
        # rechazan instrucción de sistema y modo JSON; los Gemma 4 los aceptan.
        return self._nombre.startswith("gemma-3")

    @property
    def _es_gemma_4(self) -> bool:
        return self._nombre.startswith("gemma-4")

    @property
    def _nombre(self) -> str:
        return self.modelo.rsplit("/", 1)[-1].lower()

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
            extra = {}
            if self._es_gemma_4:
                # Gemma 4 razona antes de contestar: por defecto ~2.400 tokens
                # ocultos, ~60 s por incidente. Con "minimal" baja a ~10-14 s y
                # el JSON sale igual de completo (medido con incidentes reales).
                extra["thinking_config"] = types.ThinkingConfig(thinking_level="minimal")
            config = types.GenerateContentConfig(
                system_instruction=sistema,
                response_mime_type="application/json",
                temperature=0.2,
                http_options=http,
                **extra,
            )
            contenido = prompt
        return _solo_json(self._llamar(contenido, config, timeout))

    def _llamar(self, contenido: str, config, timeout: float) -> str:
        """Una llamada, más un reintento si Google contesta 5xx y queda plazo.

        Los Gemma alojados devuelven `500 INTERNAL` de vez en cuando (en las
        mediciones, ~1 de cada 6 llamadas) y al instante: reintentar una vez
        evita mandar ese incidente al fallback. El reintento usa solo lo que
        queda del plazo, así no se pasa del presupuesto del LLM.
        """
        from google.genai import errors, types
        limite = time.monotonic() + timeout
        try:
            resp = self._cliente.models.generate_content(model=self.modelo, contents=contenido,
                                                         config=config)
        except errors.ServerError:
            restante = limite - time.monotonic()
            if restante < 5:
                raise
            config.http_options = types.HttpOptions(timeout=int(restante * 1000))
            resp = self._cliente.models.generate_content(model=self.modelo, contents=contenido,
                                                         config=config)
        return resp.text or ""


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
    """`gemma`, `gemma-nube` o `gemini`, según `SIEM_LLM_PROVEEDOR`. Sin la variable: `gemma`."""
    valor = os.getenv("SIEM_LLM_PROVEEDOR", "").strip().lower()
    if valor in PROVEEDORES:
        return valor
    if valor:
        print(f"[WARN] SIEM_LLM_PROVEEDOR={valor!r} no es 'gemma', 'gemma-nube' ni 'gemini': "
              "se usa gemma.")
    elif _gemini_key():
        print("[WARN] Hay una GEMINI_API_KEY pero SIEM_LLM_PROVEEDOR no está definido: se usa "
              "Gemma local. Para usar Gemini, definir SIEM_LLM_PROVEEDOR=gemini en .env.")
    return "gemma"


def construir() -> ClienteOllama | ClienteGemini | None:
    """El cliente del proveedor elegido, o None si no se puede armar.

    No decide si el LLM está prendido: eso es `SIEM_USE_LLM`, y lo mira
    `siem_agent._build_client()` antes de llamar acá.
    """
    elegido = proveedor()
    if elegido == "gemma":
        host = os.getenv("SIEM_OLLAMA_HOST", "").strip() or OLLAMA_HOST_POR_DEFECTO
        modelo = os.getenv("SIEM_OLLAMA_MODELO", "").strip() or OLLAMA_MODELO_POR_DEFECTO
        print(f"[INFO] Agente 2 con Gemma local ({modelo} en {host}).")
        return ClienteOllama(host, modelo)

    api_key = _gemini_key()
    if not api_key:
        print("[INFO] Sin GEMINI_API_KEY: usando análisis determinístico (fallback).")
        return None
    if elegido == "gemma-nube":
        modelo = os.getenv("SIEM_GEMMA_NUBE_MODELO", "").strip() or GEMMA_NUBE_MODELO_POR_DEFECTO
        nombre = "Gemma en la nube"
    else:
        modelo = os.getenv("SIEM_GEMINI_MODELO", "").strip() or GEMINI_MODELO_POR_DEFECTO
        nombre = "Gemini"
    try:
        print(f"[INFO] Agente 2 con {nombre} ({modelo}).")
        return ClienteGemini(api_key, modelo, fuente=elegido)
    except Exception as e:  # SDK ausente o key inválida en init
        print(f"[WARN] No se pudo inicializar el cliente Gemini ({e}). Usando fallback.")
        return None
