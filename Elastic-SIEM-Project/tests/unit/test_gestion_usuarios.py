"""Almacén de usuarios y CLI de gestión (hallazgo **API-01**).

El alta de usuarios se hace por línea de comandos y no por la interfaz web:
crear cuentas es administración del sistema, no una función del panel del
analista. Exponerlo en la web agregaría superficie de ataque para ganar
comodidad en algo que se hace una vez por integrante.

Las pruebas del control de acceso propiamente dicho están en
`tests/integration/test_api01_autenticacion.py`; acá se verifica el almacén, la
validación y la herramienta que lo gestiona.
"""

from __future__ import annotations

import json
import os

import pytest

import manage_users
import siem_auth
from siem_auth import ErrorUsuarios

PASSWORD_OK = "contrasena-valida-1"


@pytest.fixture
def almacen(sandbox, monkeypatch):
    """Almacén de usuarios vacío dentro del sandbox."""
    ruta = sandbox / "users.json"
    monkeypatch.setenv("SIEM_USERS_FILE", str(ruta))
    monkeypatch.setenv("SIEM_NEW_PASSWORD", PASSWORD_OK)
    siem_auth.control_intentos.reset()
    return ruta


def _cli(*args) -> int:
    return manage_users.main(list(args))


# ─── Hashing ─────────────────────────────────────────────────────────────────

def test_el_hash_es_argon2id():
    """No el scrypt por defecto de werkzeug: Argon2id es el estándar actual."""
    assert siem_auth.hash_password(PASSWORD_OK).split("$")[1] == "argon2id"


def test_dos_hashes_de_la_misma_contrasena_son_distintos():
    """Salt por hash: dos usuarios con la misma contraseña no se delatan entre sí."""
    assert siem_auth.hash_password(PASSWORD_OK) != siem_auth.hash_password(PASSWORD_OK)


def test_el_hash_no_contiene_la_contrasena():
    assert PASSWORD_OK not in siem_auth.hash_password(PASSWORD_OK)


def test_verificar_password_acepta_la_correcta_y_rechaza_el_resto():
    usuario = siem_auth.Usuario("ana", "analyst", siem_auth.hash_password(PASSWORD_OK))
    assert siem_auth.verificar_password(usuario, PASSWORD_OK) is True
    for malo in ("otra-contrasena-1", "", None, 42, PASSWORD_OK + " "):
        assert siem_auth.verificar_password(usuario, malo) is False


def test_un_hash_corrupto_se_trata_como_fallo_no_como_error():
    """No se le da al atacante forma de distinguir 'usuario roto' de 'clave mala'."""
    usuario = siem_auth.Usuario("ana", "analyst", "esto-no-es-un-hash")
    assert siem_auth.verificar_password(usuario, PASSWORD_OK) is False
    assert siem_auth.necesita_rehash(usuario) is True


def test_un_hash_actual_no_necesita_rehash():
    usuario = siem_auth.Usuario("ana", "analyst", siem_auth.hash_password(PASSWORD_OK))
    assert siem_auth.necesita_rehash(usuario) is False


# ─── Validación ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("nombre", ["ana", "juan.perez", "soc-1", "a_b", "x" * 32])
def test_usernames_validos(nombre):
    assert siem_auth.validar_username(nombre) == nombre


@pytest.mark.parametrize("nombre", [
    "Ana",              # mayúscula inicial
    "1ana",             # empieza con dígito
    "ab",               # menos de 3
    "x" * 33,           # más de 32
    "ana perez",        # espacio
    "ana;rm -rf /",     # metacaracteres de shell
    "../../etc/passwd", # recorrido de rutas
    "", "   ", None, 42,
])
def test_usernames_invalidos(nombre):
    with pytest.raises(ErrorUsuarios, match="username inválido"):
        siem_auth.validar_username(nombre)


@pytest.mark.parametrize("rol", ["viewer", "analyst", "auditor"])
def test_roles_validos(rol):
    assert siem_auth.validar_rol(rol) == rol


@pytest.mark.parametrize("rol", ["admin", "root", "ejecutor", "", None])
def test_roles_invalidos(rol):
    with pytest.raises(ErrorUsuarios, match="rol inválido"):
        siem_auth.validar_rol(rol)


@pytest.mark.parametrize("password", ["corta", "x" * 11, "", None, 42])
def test_contrasenas_demasiado_cortas(password):
    with pytest.raises(ErrorUsuarios, match="al menos 12"):
        siem_auth.validar_password(password)


# ─── Persistencia ────────────────────────────────────────────────────────────

def test_un_almacen_inexistente_es_un_almacen_vacio(almacen):
    assert not almacen.exists()
    assert siem_auth.cargar_usuarios() == {}


def test_el_archivo_se_crea_con_permisos_restrictivos(almacen):
    """Guarda hashes de contraseña: 0600, como el registro de auditoría."""
    _cli("crear", "ana", "--rol", "analyst")
    assert almacen.stat().st_mode & 0o777 == 0o600


def test_un_archivo_preexistente_tambien_queda_en_0600(almacen):
    """`os.open` no cambia el modo de un archivo que ya existe: se fuerza."""
    almacen.write_text('{"usuarios": []}', encoding="utf-8")
    os.chmod(almacen, 0o644)

    _cli("crear", "ana", "--rol", "analyst")
    assert almacen.stat().st_mode & 0o777 == 0o600


def test_ida_y_vuelta_conserva_los_datos(almacen):
    _cli("crear", "ana", "--rol", "analyst")
    usuario = siem_auth.cargar_usuarios()["ana"]

    assert usuario.username == "ana"
    assert usuario.rol == "analyst"
    assert usuario.activo is True
    assert usuario.creado
    assert siem_auth.verificar_password(usuario, PASSWORD_OK)


def test_un_archivo_corrupto_da_un_error_claro(almacen):
    almacen.write_text("{esto no es json", encoding="utf-8")
    with pytest.raises(ErrorUsuarios, match="no es JSON válido"):
        siem_auth.cargar_usuarios()


def test_un_usuario_incompleto_da_un_error_claro(almacen):
    almacen.write_text(json.dumps({"usuarios": [{"username": "ana"}]}), encoding="utf-8")
    with pytest.raises(ErrorUsuarios, match="falta"):
        siem_auth.cargar_usuarios()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def test_crear_los_tres_roles(almacen, capsys):
    for nombre, rol in (("ana", "analyst"), ("beto", "viewer"), ("cata", "auditor")):
        assert _cli("crear", nombre, "--rol", rol) == 0

    usuarios = siem_auth.cargar_usuarios()
    assert {u.rol for u in usuarios.values()} == {"analyst", "viewer", "auditor"}
    assert "creado con rol" in capsys.readouterr().out


def test_no_se_puede_crear_dos_veces_el_mismo(almacen, capsys):
    _cli("crear", "ana", "--rol", "analyst")
    assert _cli("crear", "ana", "--rol", "viewer") == 1
    assert "ya existe" in capsys.readouterr().err
    # Y el rol del existente no cambió por el intento.
    assert siem_auth.cargar_usuarios()["ana"].rol == "analyst"


def test_crear_con_username_invalido_falla(almacen, capsys):
    assert _cli("crear", "Ana", "--rol", "analyst") == 1
    assert "username inválido" in capsys.readouterr().err
    assert siem_auth.cargar_usuarios() == {}


def test_crear_con_contrasena_corta_falla(almacen, monkeypatch, capsys):
    monkeypatch.setenv("SIEM_NEW_PASSWORD", "corta")
    assert _cli("crear", "ana", "--rol", "analyst") == 1
    assert "al menos 12" in capsys.readouterr().err
    assert siem_auth.cargar_usuarios() == {}


def test_un_rol_inexistente_lo_rechaza_el_parser(almacen):
    """`argparse` sale con 2 ante un argumento inválido: error de uso."""
    with pytest.raises(SystemExit) as salida:
        _cli("crear", "ana", "--rol", "superadmin")
    assert salida.value.code == 2


def test_listar_sin_usuarios_explica_como_crear_el_primero(almacen, capsys):
    assert _cli("listar") == 0
    salida = capsys.readouterr().out
    assert "No hay usuarios" in salida
    assert "manage_users.py crear" in salida


def test_listar_muestra_rol_y_estado(almacen, capsys):
    _cli("crear", "ana", "--rol", "analyst")
    _cli("crear", "beto", "--rol", "viewer")
    _cli("baja", "beto")

    assert _cli("listar") == 0
    salida = capsys.readouterr().out
    assert "ana" in salida and "analyst" in salida and "activo" in salida
    assert "beto" in salida and "DE BAJA" in salida


def test_listar_verbose_incluye_los_permisos(almacen, capsys):
    _cli("crear", "ana", "--rol", "analyst")
    _cli("listar", "-v")
    salida = capsys.readouterr().out
    assert "Permisos por rol" in salida
    assert "decidir" in salida


def test_cambiar_contrasena(almacen, monkeypatch):
    _cli("crear", "ana", "--rol", "analyst")
    anterior = siem_auth.cargar_usuarios()["ana"].password_hash

    monkeypatch.setenv("SIEM_NEW_PASSWORD", "contrasena-nueva-2")
    assert _cli("password", "ana") == 0

    usuario = siem_auth.cargar_usuarios()["ana"]
    assert usuario.password_hash != anterior
    assert siem_auth.verificar_password(usuario, "contrasena-nueva-2")
    assert not siem_auth.verificar_password(usuario, PASSWORD_OK)


def test_baja_y_alta(almacen):
    _cli("crear", "ana", "--rol", "analyst")

    assert _cli("baja", "ana") == 0
    assert siem_auth.cargar_usuarios()["ana"].activo is False

    assert _cli("alta", "ana") == 0
    assert siem_auth.cargar_usuarios()["ana"].activo is True


def test_la_baja_no_borra_el_usuario(almacen):
    """Borrarlo dejaría decisiones firmadas por un usuario que ya no existe."""
    _cli("crear", "ana", "--rol", "analyst")
    _cli("baja", "ana")
    assert "ana" in siem_auth.cargar_usuarios()


def test_cambiar_de_rol(almacen, capsys):
    _cli("crear", "ana", "--rol", "analyst")
    assert _cli("rol", "ana", "--rol", "auditor") == 0

    assert siem_auth.cargar_usuarios()["ana"].rol == "auditor"
    assert "analyst → auditor" in capsys.readouterr().out


@pytest.mark.parametrize("comando", ["password", "baja", "alta"])
def test_operar_sobre_un_usuario_inexistente_falla(almacen, capsys, comando):
    assert _cli(comando, "nadie") == 1
    assert "no existe" in capsys.readouterr().err


def test_cambiar_el_rol_de_un_inexistente_falla(almacen, capsys):
    assert _cli("rol", "nadie", "--rol", "viewer") == 1
    assert "no existe" in capsys.readouterr().err


def test_el_comando_roles_documenta_la_no_autonomia(capsys):
    """La herramienta lo dice en voz alta: ningún rol ejecuta nada."""
    assert _cli("roles") == 0
    salida = capsys.readouterr().out

    for rol in siem_auth.ROLES:
        assert rol in salida
    assert "QUIÉN DECIDE, no quién ejecuta" in salida
    assert "no las" in salida and "ejecuta" in salida


def test_sin_subcomando_es_error_de_uso():
    with pytest.raises(SystemExit) as salida:
        _cli()
    assert salida.value.code == 2


# ─── Sesión ──────────────────────────────────────────────────────────────────

def test_el_session_id_es_estable_y_corto():
    uno = siem_auth.session_id_de("ana", "2026-09-17T10:00:00+00:00")
    dos = siem_auth.session_id_de("ana", "2026-09-17T10:00:00+00:00")
    assert uno == dos and len(uno) == 16


def test_el_session_id_cambia_con_la_sesion():
    """Dos sesiones del mismo usuario se distinguen en la auditoría."""
    assert siem_auth.session_id_de("ana", "2026-09-17T10:00:00+00:00") != \
        siem_auth.session_id_de("ana", "2026-09-17T11:00:00+00:00")


def test_el_session_id_no_permite_recuperar_al_usuario():
    """Es un resumen, no el nombre codificado."""
    assert "ana" not in siem_auth.session_id_de("ana", "2026-09-17T10:00:00+00:00")


# ─── Permisos ────────────────────────────────────────────────────────────────

def test_permisos_de_un_rol_inexistente_es_el_conjunto_vacio():
    """Un rol desconocido no hereda permisos por accidente."""
    assert siem_auth.permisos_de("superadmin") == frozenset()
    assert siem_auth.permisos_de("") == frozenset()


def test_solo_analyst_decide():
    assert siem_auth.Usuario("x", "analyst", "h").puede("decidir") is True
    assert siem_auth.Usuario("x", "viewer", "h").puede("decidir") is False
    assert siem_auth.Usuario("x", "auditor", "h").puede("decidir") is False


def test_solo_auditor_verifica_la_cadena():
    assert siem_auth.Usuario("x", "auditor", "h").puede("verificar_cadena") is True
    assert siem_auth.Usuario("x", "analyst", "h").puede("verificar_cadena") is False


def test_un_usuario_dado_de_baja_no_esta_activo():
    assert siem_auth.Usuario("x", "analyst", "h", activo=False).is_active is False
