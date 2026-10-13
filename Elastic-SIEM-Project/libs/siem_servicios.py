#!/usr/bin/env python3
"""Comunicación entre los microservicios de SIEM-IA.

Antes, las etapas se pasaban datos escribiendo y leyendo archivos de un mismo
directorio `data/`, y el orquestador las lanzaba con `subprocess`. Ahora cada
servicio es dueño de sus datos y los expone por HTTP en la red interna de
Docker. Este módulo es la ÚNICA puerta para esas llamadas, con tres reglas:

1. **Registro cerrado de destinos.** Solo se puede hablar con los servicios de
   `SERVICIOS`. No hay forma de pedirle a este cliente una URL arbitraria: el
   nombre del servicio se resuelve a su URL desde la configuración, nunca desde
   un dato recibido. Es la versión, entre servicios, de la regla de los
   comandos del playbook: nada que venga de un log decide a dónde se conecta
   el sistema.
2. **Token interno.** Todo servicio interno exige `X-Internal-Token` (salvo su
   sonda de salud). Los puertos internos no se publican al host, así que el
   token es defensa en profundidad: un contenedor ajeno en la misma red no
   puede escribir en la auditoría ni autenticar usuarios por su cuenta.
3. **Sin token, no arranca.** Igual que `SECRET_KEY` en el panel: un valor por
   defecto haría que todos los despliegues compartieran la misma credencial.

Las pruebas reemplazan el transporte HTTP por uno en proceso
(`instalar_transporte`), así la malla completa se ejercita sin Docker.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

# Servicios internos. El panel (`gateway`) no figura: nadie lo llama, él llama.
SERVICIOS = ("auth", "audit", "collector", "classifier", "analyst", "pipeline",
             "knowledge")

PUERTO_INTERNO = 8000
ENCABEZADO_TOKEN = "X-Internal-Token"  # noqa: S105 — el NOMBRE del encabezado, no un secreto
TOKEN_MIN = 32

# La sonda de salud queda abierta: Docker la consulta sin credenciales para
# decidir si el contenedor está listo, y no devuelve datos sensibles.
RUTA_SALUD = "/v1/healthz"

# Tope de cuerpo de las peticiones internas. Una captura del SIEM con sus
# alertas y un reporte con todos sus incidentes caben holgados en 16 MB.
MAX_CUERPO_INTERNO = 16 * 1024 * 1024


class ConfiguracionInsegura(RuntimeError):
    """El servicio no puede arrancar con esta configuración."""


class ServicioNoDisponible(RuntimeError):
    """Un servicio interno no respondió (caído, iniciando o saturado)."""


@dataclass
class Respuesta:
    status: int
    datos: Any

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


# ─── Configuración ───────────────────────────────────────────────────────────

def token_interno() -> str:
    """Token compartido entre servicios. Sin valor por defecto, a propósito."""
    token = os.getenv("SIEM_INTERNAL_TOKEN", "").strip()
    if not token:
        raise ConfiguracionInsegura(
            "Falta SIEM_INTERNAL_TOKEN. Los servicios no arrancan sin el token interno.\n"
            "Generá uno con:  python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
            "y agregalo a .env como SIEM_INTERNAL_TOKEN=<valor>.")
    if len(token) < TOKEN_MIN:
        raise ConfiguracionInsegura(
            f"SIEM_INTERNAL_TOKEN es demasiado corto ({len(token)} caracteres; "
            f"mínimo {TOKEN_MIN}).")
    return token


def url_de(servicio: str) -> str:
    """URL base de un servicio del registro.

    Por defecto es el nombre del servicio en la red de Docker
    (`http://audit:8000`); `SIEM_<SERVICIO>_URL` lo sobreescribe para correr
    un servicio fuera de Docker.
    """
    if servicio not in SERVICIOS:
        raise ValueError(f"servicio desconocido: {servicio!r}. Válidos: {', '.join(SERVICIOS)}.")
    return os.getenv(f"SIEM_{servicio.upper()}_URL",
                     f"http://{servicio}:{PUERTO_INTERNO}").rstrip("/")


# ─── Cliente ─────────────────────────────────────────────────────────────────

Transporte = Callable[[str, str, str, Any, float], tuple[int, Any]]


def _transporte_http(servicio: str, metodo: str, ruta: str, cuerpo: Any,
                     timeout: float) -> tuple[int, Any]:
    try:
        r = requests.request(metodo, url_de(servicio) + ruta, json=cuerpo, timeout=timeout,
                             headers={ENCABEZADO_TOKEN: token_interno()})
    except requests.exceptions.Timeout as e:
        raise ServicioNoDisponible(
            f"el servicio '{servicio}' no respondió en {timeout:g} s") from e
    except requests.exceptions.RequestException as e:
        raise ServicioNoDisponible(f"no se pudo conectar con el servicio '{servicio}'") from e
    try:
        datos = r.json()
    except ValueError:
        datos = None
    return r.status_code, datos


_transporte: Transporte = _transporte_http


def instalar_transporte(transporte: Transporte | None) -> None:
    """Reemplaza el transporte HTTP (lo usan las pruebas). `None` lo restaura."""
    global _transporte  # noqa: PLW0603 — punto de inyección deliberado
    _transporte = transporte or _transporte_http


def llamar(servicio: str, metodo: str, ruta: str, cuerpo: Any = None,
           timeout: float = 10) -> Respuesta:
    """Llama a un servicio interno y devuelve su respuesta.

    Lanza `ServicioNoDisponible` si no se pudo hablar con él; un código HTTP de
    error NO es una excepción: el llamador decide qué significa cada uno.
    """
    if servicio not in SERVICIOS:
        raise ValueError(f"servicio desconocido: {servicio!r}")
    if not ruta.startswith("/v1/"):
        raise ValueError(f"ruta interna inválida: {ruta!r}")
    status, datos = _transporte(servicio, metodo.upper(), ruta, cuerpo, timeout)
    return Respuesta(status, datos)


# ─── Servidor ────────────────────────────────────────────────────────────────

def crear_servicio(nombre: str) -> Flask:
    """Aplicación Flask base de un servicio interno.

    Aporta lo que todos comparten: sonda de salud, token interno obligatorio,
    errores siempre en JSON y tope de cuerpo. Falla al construirse si falta el
    token, igual que el panel sin `SECRET_KEY`.
    """
    token = token_interno()
    app = Flask(nombre)
    app.config.update(MAX_CONTENT_LENGTH=MAX_CUERPO_INTERNO, JSON_SORT_KEYS=False)

    @app.before_request
    def _exigir_token():
        if request.path == RUTA_SALUD:
            return None
        recibido = request.headers.get(ENCABEZADO_TOKEN, "")
        # Comparación en tiempo constante: no le da a nadie un oráculo de
        # cuántos caracteres del token acertó.
        if not hmac.compare_digest(recibido.encode(), token.encode()):
            return jsonify({"error": "token interno ausente o inválido"}), 401
        return None

    @app.errorhandler(HTTPException)
    def _error_json(e: HTTPException):
        return jsonify({"error": e.description, "status": e.code}), e.code

    @app.get(RUTA_SALUD)
    def healthz():
        return jsonify({"status": "ok", "servicio": nombre})

    return app


def cuerpo_json() -> dict | None:
    """El cuerpo de la petición si es un objeto JSON; `None` si no."""
    datos = request.get_json(silent=True)
    return datos if isinstance(datos, dict) else None
