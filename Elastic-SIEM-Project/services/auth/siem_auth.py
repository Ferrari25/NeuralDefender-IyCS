#!/usr/bin/env python3
"""Autenticación y roles del servicio `auth` (hallazgo API-01).

Dominio puro: almacén de usuarios, Argon2id, tabla de permisos y control de
intentos. La sesión web (cookie, expiración, decoradores de permiso) vive en el
gateway (`services/gateway/sesion_web.py`), que le pregunta a este servicio por
HTTP quién es cada usuario y qué puede hacer.

**El problema que cierra este módulo.** Hasta ahora, el campo `analyst` del
registro inmutable salía de una variable de entorno:

    ANALYST = os.getenv("ANALYST_NAME", "analista-soc")

Quien corría el proceso decidía qué nombre quedaba firmando cada decisión. La
cadena de hash (A-04) garantiza que el registro **no se alteró después de
escribirse**; no garantizaba **quién lo escribió**. En un sistema cuya premisa
entera es la supervisión humana trazable, esa era la brecha más importante.

**Nota de diseño que conviene leer antes de mirar la tabla de permisos.**

    Ningún rol puede ejecutar acciones de contención. El RBAC de acá controla
    QUIÉN DECIDE, no quién ejecuta — porque nadie ejecuta, nunca. No existe un
    rol `admin` que "apriete el botón rojo": ese botón no existe en el sistema.
    La ejecución la hace una persona, a mano, fuera de la plataforma.

Esa propiedad está certificada en `tests/test_no_autonomy.py` y este módulo no
la toca: agregar autenticación no agrega capacidad de actuar, solo identidad a
quien decide.

**Alcance deliberado (v1.0).** Almacén de usuarios en un archivo JSON con
permisos restrictivos, gestionado por CLI. Queda fuera —y se declara, en vez de
simularse—: MFA, SSO/LDAP, recuperación de contraseña, alta por interfaz y
multi-tenancy. Para un laboratorio con un puñado de analistas, un archivo
protegido alcanza; decirlo es más honesto que aparentar lo contrario.
Ver `docs/03-autenticacion-y-control-de-acceso.md`.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# ─── Configuración ───────────────────────────────────────────────────────────

USERS_FILE = os.getenv("SIEM_USERS_FILE", "users.json")

# El archivo de usuarios guarda hashes de contraseña: 0600, como la auditoría.
USERS_FILE_MODE = 0o600

# Anti-fuerza bruta. Es irónico que un sistema que detecta fuerza bruta sea
# vulnerable a ella, así que el panel se defiende con el mismo criterio que
# aplica a los hosts que vigila.
INTENTOS_MAX = 5
VENTANA_BLOQUEO = timedelta(minutes=15)

# Argon2id con los parámetros por defecto de argon2-cffi (RFC 9106). No se usa
# el hash por defecto de werkzeug: hoy es scrypt, y Argon2id es el estándar
# recomendado actual.
_hasher = PasswordHasher()

_USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")
PASSWORD_MIN = 12


# ─── Roles y permisos ────────────────────────────────────────────────────────
#
# Los permisos viven en UNA tabla, no dispersos en `if` por las vistas. Que se
# puedan leer de un vistazo es parte del control: un permiso mal puesto dentro
# de una función es mucho más difícil de auditar que una fila de más acá.

PERMISOS: dict[str, frozenset[str]] = {
    # ve el triage y los incidentes
    "viewer":  frozenset({"ver_incidentes", "ver_auditoria"}),
    # además, aprueba o descarta acciones
    "analyst": frozenset({"ver_incidentes", "ver_auditoria", "decidir"}),
    # ve todo y verifica la cadena de hash, pero NO decide: separar quien decide
    # de quien audita es lo que hace que la auditoría signifique algo
    "auditor": frozenset({"ver_incidentes", "ver_auditoria", "verificar_cadena"}),
}

ROLES = tuple(PERMISOS)

# Permisos que NO existen y no deben existir. Si alguien agrega uno de estos a la
# tabla, `test_no_autonomy.py` y `test_ningun_rol_puede_ejecutar` lo detectan.
PERMISOS_PROHIBIDOS = frozenset({
    "ejecutar", "ejecutar_accion", "contener", "bloquear_ip", "remediar",
    "execute", "run_command", "contain",
})


def permisos_de(rol: str) -> frozenset[str]:
    return PERMISOS.get(rol, frozenset())


# ─── Usuario ─────────────────────────────────────────────────────────────────

@dataclass
class Usuario:
    """Un analista del SOC, tal como lo guarda el servicio de autenticación.

    Ya no hereda de `UserMixin`: la sesión web es asunto del gateway, que arma
    su propio objeto de sesión con lo que este servicio le devuelve.
    """

    username: str
    rol: str
    password_hash: str
    activo: bool = True
    creado: str = ""
    ultimo_acceso: str | None = None

    @property
    def is_active(self) -> bool:  # un usuario dado de baja no entra
        return self.activo

    def puede(self, permiso: str) -> bool:
        return permiso in permisos_de(self.rol)

    def to_dict(self) -> dict:
        return {
            "username": self.username, "rol": self.rol,
            "password_hash": self.password_hash, "activo": self.activo,
            "creado": self.creado, "ultimo_acceso": self.ultimo_acceso,
        }


# ─── Almacén de usuarios ─────────────────────────────────────────────────────

class ErrorUsuarios(RuntimeError):
    """Problema de validación o de estado del almacén de usuarios."""


def _ruta_usuarios() -> Path:
    return Path(os.getenv("SIEM_USERS_FILE", USERS_FILE))


def cargar_usuarios() -> dict[str, Usuario]:
    """Lee el archivo de usuarios. Un archivo ausente es un almacén vacío."""
    ruta = _ruta_usuarios()
    if not ruta.exists():
        return {}
    try:
        crudo = json.loads(ruta.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ErrorUsuarios(f"'{ruta}' no es JSON válido: {e}") from e

    usuarios = {}
    for datos in crudo.get("usuarios", []):
        try:
            usuarios[datos["username"]] = Usuario(
                username=datos["username"], rol=datos["rol"],
                password_hash=datos["password_hash"],
                activo=datos.get("activo", True), creado=datos.get("creado", ""),
                ultimo_acceso=datos.get("ultimo_acceso"))
        except KeyError as e:
            raise ErrorUsuarios(f"usuario incompleto en '{ruta}': falta {e}") from e
    return usuarios


def guardar_usuarios(usuarios: dict[str, Usuario]) -> None:
    """Escribe el archivo con bloqueo y permisos 0600.

    Mismo criterio que `siem_lib.append_jsonl`: `os.open` con modo explícito, en
    vez de dejar los permisos a merced del umask. Un archivo de hashes de
    contraseña legible por todo el sistema no protege gran cosa.
    """
    ruta = _ruta_usuarios()
    contenido = {
        "version": 1,
        "actualizado": datetime.now(timezone.utc).isoformat(),
        "usuarios": [u.to_dict() for u in usuarios.values()],
    }
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, USERS_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            json.dump(contenido, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    # Si el archivo ya existía, `os.open` no cambia su modo: lo forzamos.
    os.chmod(ruta, USERS_FILE_MODE)


# ─── Validación y hashing ────────────────────────────────────────────────────

def validar_username(valor: str) -> str:
    """Mismo criterio que `siem_validators.valid_username`, algo más estricto.

    Se exige minúscula inicial y 3 caracteres mínimo: un nombre de usuario del
    panel se escribe a mano y va a quedar grabado en un registro inmutable.
    """
    if not isinstance(valor, str) or not _USERNAME_RE.match(valor.strip()):
        raise ErrorUsuarios(
            f"username inválido: {valor!r}. Debe empezar con minúscula y usar "
            f"solo [a-z0-9._-], entre 3 y 32 caracteres.")
    return valor.strip()


def validar_rol(valor: str) -> str:
    if valor not in PERMISOS:
        raise ErrorUsuarios(f"rol inválido: {valor!r}. Válidos: {', '.join(ROLES)}.")
    return valor


def validar_password(valor: str) -> str:
    if not isinstance(valor, str) or len(valor) < PASSWORD_MIN:
        raise ErrorUsuarios(f"la contraseña debe tener al menos {PASSWORD_MIN} caracteres.")
    return valor


def hash_password(password: str) -> str:
    return _hasher.hash(validar_password(password))


def verificar_password(usuario: Usuario, password: str) -> bool:
    """Verifica la contraseña en tiempo aproximadamente constante.

    `argon2-cffi` lanza excepción cuando no coincide; se traduce a booleano. Un
    hash corrupto se trata como fallo, no como error: no se le da al atacante la
    posibilidad de distinguir "usuario roto" de "contraseña incorrecta".
    """
    if not isinstance(password, str) or not password:
        return False
    try:
        return _hasher.verify(usuario.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def necesita_rehash(usuario: Usuario) -> bool:
    """¿El hash quedó con parámetros viejos? (Argon2 los versiona en el string.)"""
    try:
        return _hasher.check_needs_rehash(usuario.password_hash)
    except InvalidHashError:
        return True


# ─── Anti-fuerza bruta ───────────────────────────────────────────────────────

@dataclass
class _Intentos:
    fallos: list[float] = field(default_factory=list)


class ControlDeIntentos:
    """Limita los intentos de login por (usuario, IP).

    En memoria a propósito: el servicio de autenticación corre en un solo
    proceso (gunicorn con `--workers 1`; ver su Dockerfile) y el estado no
    tiene por qué sobrevivir a un reinicio — un atacante que reinicia el servidor
    ya tiene un problema mayor. Persistirlo agregaría un archivo más que proteger
    sin ganar nada en este alcance.

    El backoff crece con los fallos acumulados: el sexto intento espera, el
    séptimo espera más. Encarece el ataque sin bloquear para siempre a un
    analista que se equivocó de contraseña.
    """

    def __init__(self, maximo: int = INTENTOS_MAX, ventana: timedelta = VENTANA_BLOQUEO):
        self._intentos: dict[tuple[str, str], _Intentos] = defaultdict(_Intentos)
        self._maximo = maximo
        self._ventana = ventana.total_seconds()

    def _vigentes(self, clave: tuple[str, str]) -> list[float]:
        ahora = time.monotonic()
        registro = self._intentos[clave]
        registro.fallos = [t for t in registro.fallos if ahora - t < self._ventana]
        return registro.fallos

    def bloqueado(self, username: str, ip: str) -> tuple[bool, int]:
        """¿Está bloqueado? Devuelve `(bloqueado, segundos_restantes)`."""
        fallos = self._vigentes((username, ip))
        if len(fallos) < self._maximo:
            return False, 0
        # Backoff: cada fallo por encima del máximo duplica la espera base,
        # acotada a la ventana completa.
        exceso = len(fallos) - self._maximo
        espera = min(self._ventana, 60 * (2 ** min(exceso, 8)))
        restante = espera - (time.monotonic() - fallos[-1])
        if restante <= 0:
            return False, 0
        return True, int(restante) + 1

    def registrar_fallo(self, username: str, ip: str) -> None:
        self._vigentes((username, ip)).append(time.monotonic())

    def limpiar(self, username: str, ip: str) -> None:
        """Un login exitoso borra el historial de fallos de esa combinación."""
        self._intentos.pop((username, ip), None)

    def reset(self) -> None:
        self._intentos.clear()


control_intentos = ControlDeIntentos()


# ─── Autenticación ───────────────────────────────────────────────────────────

@dataclass
class ResultadoLogin:
    ok: bool
    usuario: Usuario | None = None
    motivo: str | None = None
    espera_segundos: int = 0


def autenticar(username: object, password: object, ip: str) -> ResultadoLogin:
    """Valida credenciales aplicando el control de intentos.

    El motivo que se devuelve al cliente es siempre el mismo —"usuario o
    contraseña incorrectos"— sin importar si el usuario no existe, está dado de
    baja o erró la contraseña. Distinguirlos le confirmaría a un atacante qué
    nombres de usuario son válidos.
    """
    nombre = username.strip() if isinstance(username, str) else ""
    if not nombre or not isinstance(password, str):
        return ResultadoLogin(False, motivo="usuario o contraseña incorrectos")

    bloqueado, espera = control_intentos.bloqueado(nombre, ip)
    if bloqueado:
        return ResultadoLogin(
            False, motivo=f"demasiados intentos fallidos; reintentá en {espera} s",
            espera_segundos=espera)

    usuarios = cargar_usuarios()
    usuario = usuarios.get(nombre)

    if usuario is None or not usuario.activo or not verificar_password(usuario, password):
        control_intentos.registrar_fallo(nombre, ip)
        return ResultadoLogin(False, motivo="usuario o contraseña incorrectos")

    control_intentos.limpiar(nombre, ip)

    # Si los parámetros de Argon2 quedaron viejos, se rehashea con la contraseña
    # ya verificada: es el único momento en que está disponible en claro.
    if necesita_rehash(usuario):
        usuario.password_hash = hash_password(password)

    usuario.ultimo_acceso = datetime.now(timezone.utc).isoformat()
    usuarios[nombre] = usuario
    guardar_usuarios(usuarios)
    return ResultadoLogin(True, usuario=usuario)


def vista_publica(usuario: Usuario) -> dict:
    """Lo que el servicio le cuenta de un usuario a otros servicios.

    Nunca incluye el hash de la contraseña: ese dato no sale de este servicio.
    """
    return {
        "username": usuario.username,
        "rol": usuario.rol,
        "activo": usuario.activo,
        "permisos": sorted(permisos_de(usuario.rol)),
    }
