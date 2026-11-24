#!/usr/bin/env python3
"""Sesión web y control de acceso del gateway (hallazgo API-01).

Antes vivía dentro de `siem_auth.py`, mezclado con el almacén de usuarios. Con
la migración a microservicios se separó en dos mitades:

  - el servicio `auth` sabe QUIÉN es cada usuario y QUÉ puede hacer (guarda los
    hashes, aplica Argon2id y el control de intentos);
  - este módulo, en el gateway, maneja la COOKIE: expiración, identificador de
    sesión para la auditoría y los decoradores que exigen un permiso.

El gateway nunca ve un hash de contraseña: le manda las credenciales al
servicio `auth` y recibe solo el rol y los permisos.

**Nota de diseño.** Ningún rol puede ejecutar acciones de contención. El RBAC
controla QUIÉN DECIDE, no quién ejecuta — porque nadie ejecuta, nunca. Ver
`tests/test_no_autonomy.py`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote

from flask import abort, jsonify, request
from flask_login import UserMixin, current_user

from siem_servicios import ServicioNoDisponible, llamar

# Expiración de sesión. Dos límites distintos y los dos necesarios: el de
# inactividad protege una terminal desatendida; el absoluto acota el daño de una
# cookie robada aunque el atacante la mantenga activa.
INACTIVIDAD_MAX = timedelta(minutes=30)
SESION_MAX = timedelta(hours=8)

# Permisos que NO existen y no deben existir. La tabla de permisos vive en el
# servicio `auth`; esta lista se repite acá porque el gateway es quien los
# EXIGE, y un decorador que pidiera uno de estos tiene que fallar al cargar el
# módulo, sin esperar a que alguien consulte al otro servicio.
PERMISOS_PROHIBIDOS = frozenset({
    "ejecutar", "ejecutar_accion", "contener", "bloquear_ip", "remediar",
    "execute", "run_command", "contain",
})


# ─── Usuario de la sesión ────────────────────────────────────────────────────

@dataclass
class UsuarioDeSesion(UserMixin):
    """Lo que el gateway sabe del analista conectado. `UserMixin` es para Flask-Login."""

    username: str
    rol: str
    permisos: frozenset[str] = field(default_factory=frozenset)

    def get_id(self) -> str:  # Flask-Login
        return self.username

    def puede(self, permiso: str) -> bool:
        return permiso in self.permisos


@dataclass
class ResultadoLogin:
    ok: bool
    usuario: UsuarioDeSesion | None = None
    motivo: str | None = None
    espera_segundos: int = 0
    no_disponible: bool = False


def autenticar(username: object, password: object, ip: str) -> ResultadoLogin:
    """Valida las credenciales contra el servicio `auth`.

    El motivo de rechazo lo decide ese servicio y es siempre el mismo
    —"usuario o contraseña incorrectos"— para no confirmar qué nombres existen.
    """
    try:
        r = llamar("auth", "POST", "/v1/authenticate",
                   {"username": username, "password": password, "client_ip": ip})
    except ServicioNoDisponible:
        return ResultadoLogin(False, motivo="el servicio de autenticación no está disponible",
                              no_disponible=True)

    datos = r.datos if isinstance(r.datos, dict) else {}
    if r.status == 200:
        return ResultadoLogin(True, usuario=UsuarioDeSesion(
            username=datos["usuario"], rol=datos["rol"],
            permisos=frozenset(datos.get("permisos") or [])))
    if r.status == 429:
        return ResultadoLogin(False, motivo=datos.get("error"),
                              espera_segundos=int(datos.get("reintentar_en") or 1))
    if r.status in (400, 401):
        return ResultadoLogin(False, motivo=datos.get("error") or "usuario o contraseña incorrectos")
    return ResultadoLogin(False, motivo="el servicio de autenticación no está disponible",
                          no_disponible=True)


def cargar_usuario_de_sesion(username: str) -> UsuarioDeSesion | None:
    """`user_loader` de Flask-Login.

    Le pregunta al servicio `auth` en cada petición, a propósito: dar de baja a
    un analista (o cambiarle el rol) tiene efecto inmediato, sin esperar a que
    caduque su cookie. Si el servicio no responde, la petición falla con 503 en
    vez de tratar al usuario como desconocido: no es lo mismo "no sé quién sos"
    que "no puedo averiguarlo ahora".
    """
    try:
        r = llamar("auth", "GET", f"/v1/users/{quote(username, safe='')}")
    except ServicioNoDisponible:
        abort(503, description="el servicio de autenticación no está disponible")
    if r.status == 404:
        return None
    if r.status != 200 or not isinstance(r.datos, dict):
        abort(503, description="el servicio de autenticación no está disponible")
    if not r.datos.get("activo"):
        return None
    return UsuarioDeSesion(username=r.datos["username"], rol=r.datos["rol"],
                           permisos=frozenset(r.datos.get("permisos") or []))


# ─── Sesión ──────────────────────────────────────────────────────────────────

def session_id_de(username: str, emitido_en: str) -> str:
    """Identificador de sesión para el registro de auditoría.

    **Derivado, no la cookie.** Guardar el identificador de sesión real en un
    archivo append-only sería entregar un token de sesión válido a cualquiera que
    lea la auditoría. Este valor permite agrupar las decisiones de una misma
    sesión sin que sirva para suplantarla.
    """
    semilla = f"{username}|{emitido_en}"
    return hashlib.sha256(semilla.encode(), usedforsecurity=False).hexdigest()[:16]


def sesion_expirada(emitido_en: str | None, ultimo_uso: str | None,
                    ahora: datetime | None = None) -> str | None:
    """Devuelve el motivo de expiración, o `None` si la sesión sigue vigente."""
    ahora = ahora or datetime.now(timezone.utc)

    def _parse(valor):
        if not valor:
            return None
        try:
            return datetime.fromisoformat(valor)
        except ValueError:
            return None

    inicio, uso = _parse(emitido_en), _parse(ultimo_uso)
    if inicio is None or uso is None:
        return "sesión sin marca temporal válida"
    if ahora - inicio > SESION_MAX:
        return f"sesión expirada: supera el máximo absoluto de {SESION_MAX}"
    if ahora - uso > INACTIVIDAD_MAX:
        return f"sesión expirada por inactividad de más de {INACTIVIDAD_MAX}"
    return None


def ip_del_cliente() -> str:
    """IP del cliente, sin confiar en encabezados de proxy.

    `X-Forwarded-For` lo pone el cliente y es trivial de falsificar; usarlo acá
    permitiría esquivar el control de intentos cambiando un encabezado. El
    gateway se publica en loopback del host, así que `remote_addr` es el dato
    real. Si algún día se publica detrás de un proxy inverso, hay que usar
    `ProxyFix` con el número de saltos conocido, no leer el encabezado a ciegas.
    """
    return request.remote_addr or "desconocida"


# ─── Decoradores de autorización ─────────────────────────────────────────────

def _sin_permiso(permiso: str):
    return jsonify({
        "error": f"el rol '{getattr(current_user, 'rol', '?')}' no tiene permiso "
                 f"para '{permiso}'",
        "permiso_requerido": permiso,
    }), 403


def requiere_permiso(permiso: str):
    """Exige un permiso concreto, no un rol.

    Pedir el permiso y no el rol es lo que permite cambiar la tabla de permisos
    (en el servicio `auth`) sin tocar una sola vista.
    """
    if permiso in PERMISOS_PROHIBIDOS:
        raise ValueError(
            f"'{permiso}' no es un permiso válido: el sistema no ejecuta acciones. "
            f"Ver sesion_web.PERMISOS_PROHIBIDOS y tests/test_no_autonomy.py.")

    def decorador(vista):
        @wraps(vista)
        def envoltorio(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "se requiere autenticación"}), 401
            if not current_user.puede(permiso):
                return _sin_permiso(permiso)
            return vista(*args, **kwargs)
        return envoltorio
    return decorador


def requiere_sesion(vista):
    """Solo exige estar autenticado, sin permiso puntual."""
    @wraps(vista)
    def envoltorio(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "se requiere autenticación"}), 401
        return vista(*args, **kwargs)
    return envoltorio
