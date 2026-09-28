#!/usr/bin/env python3
"""Gestión de usuarios del panel de supervisión (hallazgo API-01).

El alta de usuarios se hace por línea de comandos y no por la interfaz web,
deliberadamente: crear cuentas es una operación de administración del sistema,
no una función del panel del analista. Exponerla en la web agregaría superficie
de ataque para ganar comodidad en algo que se hace una vez por integrante.

Uso:
    python3 manage_users.py crear ana --rol analyst
    python3 manage_users.py listar
    python3 manage_users.py password ana
    python3 manage_users.py baja ana
    python3 manage_users.py alta ana
    python3 manage_users.py rol ana --rol auditor
    python3 manage_users.py roles

La contraseña se pide de forma interactiva (no se escribe en la línea de
comandos, donde quedaría en el historial del shell). Para automatizar, se puede
pasar por la variable `SIEM_NEW_PASSWORD`.

Códigos de salida:  0 = ok · 1 = error de operación · 2 = error de uso.

Esta herramienta **no ejecuta nada del sistema**: solo lee y escribe el archivo
de usuarios.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime, timezone

from siem_auth import (
    PASSWORD_MIN,
    PERMISOS,
    ROLES,
    ErrorUsuarios,
    Usuario,
    _ruta_usuarios,
    cargar_usuarios,
    guardar_usuarios,
    hash_password,
    validar_rol,
    validar_username,
)


def _pedir_password(confirmar: bool = True) -> str:
    """Toma la contraseña del entorno o la pide sin mostrarla en pantalla."""
    desde_entorno = os.getenv("SIEM_NEW_PASSWORD")
    if desde_entorno:
        return desde_entorno

    password = getpass.getpass(f"Contraseña (mínimo {PASSWORD_MIN} caracteres): ")
    if confirmar and password != getpass.getpass("Repetir contraseña: "):
        raise ErrorUsuarios("las contraseñas no coinciden.")
    return password


def cmd_crear(args) -> int:
    usuarios = cargar_usuarios()
    nombre = validar_username(args.username)
    rol = validar_rol(args.rol)

    if nombre in usuarios:
        raise ErrorUsuarios(f"el usuario '{nombre}' ya existe. Usá 'password' o 'rol'.")

    usuarios[nombre] = Usuario(
        username=nombre, rol=rol, password_hash=hash_password(_pedir_password()),
        activo=True, creado=datetime.now(timezone.utc).isoformat())
    guardar_usuarios(usuarios)

    print(f"✅ Usuario '{nombre}' creado con rol '{rol}'.")
    print(f"   Permisos: {', '.join(sorted(PERMISOS[rol]))}")
    return 0


def cmd_listar(args) -> int:
    usuarios = cargar_usuarios()
    if not usuarios:
        print(f"No hay usuarios en '{_ruta_usuarios()}'.")
        print("Creá el primero con:  python3 manage_users.py crear <nombre> --rol analyst")
        return 0

    print(f"{'USUARIO':<20} {'ROL':<10} {'ESTADO':<10} ÚLTIMO ACCESO")
    print("─" * 72)
    for u in sorted(usuarios.values(), key=lambda x: x.username):
        estado = "activo" if u.activo else "DE BAJA"
        print(f"{u.username:<20} {u.rol:<10} {estado:<10} {u.ultimo_acceso or '—'}")
    print(f"\n{len(usuarios)} usuario(s) · archivo: {_ruta_usuarios()}")
    if args.verbose:
        print("\nPermisos por rol:")
        for rol, permisos in PERMISOS.items():
            print(f"  {rol:<10} {', '.join(sorted(permisos))}")
    return 0


def cmd_password(args) -> int:
    usuarios = cargar_usuarios()
    nombre = args.username
    if nombre not in usuarios:
        raise ErrorUsuarios(f"el usuario '{nombre}' no existe.")

    usuarios[nombre].password_hash = hash_password(_pedir_password())
    guardar_usuarios(usuarios)
    print(f"✅ Contraseña de '{nombre}' actualizada.")
    print("   Las sesiones abiertas siguen vigentes hasta que expiren.")
    return 0


def _cambiar_estado(nombre: str, activo: bool) -> int:
    usuarios = cargar_usuarios()
    if nombre not in usuarios:
        raise ErrorUsuarios(f"el usuario '{nombre}' no existe.")

    usuarios[nombre].activo = activo
    guardar_usuarios(usuarios)

    if activo:
        print(f"✅ Usuario '{nombre}' dado de alta.")
    else:
        print(f"✅ Usuario '{nombre}' dado de baja.")
        print("   Efecto inmediato: el almacén se relee en cada petición, así que")
        print("   su sesión abierta deja de ser válida en la siguiente.")
    return 0


def cmd_baja(args) -> int:
    return _cambiar_estado(args.username, activo=False)


def cmd_alta(args) -> int:
    return _cambiar_estado(args.username, activo=True)


def cmd_rol(args) -> int:
    usuarios = cargar_usuarios()
    nombre = args.username
    if nombre not in usuarios:
        raise ErrorUsuarios(f"el usuario '{nombre}' no existe.")

    anterior = usuarios[nombre].rol
    usuarios[nombre].rol = validar_rol(args.rol)
    guardar_usuarios(usuarios)
    print(f"✅ Rol de '{nombre}': {anterior} → {args.rol}")
    print(f"   Permisos: {', '.join(sorted(PERMISOS[args.rol]))}")
    return 0


def cmd_roles(args) -> int:
    del args
    print("Roles disponibles y qué puede hacer cada uno:\n")
    descripciones = {
        "viewer":  "Consulta el triage y la auditoría. NO decide.",
        "analyst": "Consulta y aprueba o descarta acciones sugeridas.",
        "auditor": "Consulta y verifica la cadena de hash. NO decide.",
    }
    for rol in ROLES:
        print(f"  {rol}")
        print(f"     {descripciones[rol]}")
        print(f"     Permisos: {', '.join(sorted(PERMISOS[rol]))}\n")
    print("Ningún rol puede ejecutar acciones de contención: el sistema no las")
    print("ejecuta. El control de acceso decide QUIÉN DECIDE, no quién ejecuta.")
    return 0


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gestión de usuarios del panel de supervisión SIEM-IA.",
        epilog="La contraseña se pide de forma interactiva; para automatizar, "
               "usá la variable de entorno SIEM_NEW_PASSWORD.")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("crear", help="crear un usuario nuevo")
    p.add_argument("username")
    p.add_argument("--rol", required=True, choices=ROLES)
    p.set_defaults(func=cmd_crear)

    p = sub.add_parser("listar", help="listar los usuarios existentes")
    p.add_argument("-v", "--verbose", action="store_true", help="incluir los permisos por rol")
    p.set_defaults(func=cmd_listar)

    p = sub.add_parser("password", help="cambiar la contraseña de un usuario")
    p.add_argument("username")
    p.set_defaults(func=cmd_password)

    p = sub.add_parser("baja", help="desactivar un usuario sin borrarlo")
    p.add_argument("username")
    p.set_defaults(func=cmd_baja)

    p = sub.add_parser("alta", help="reactivar un usuario dado de baja")
    p.add_argument("username")
    p.set_defaults(func=cmd_alta)

    p = sub.add_parser("rol", help="cambiar el rol de un usuario")
    p.add_argument("username")
    p.add_argument("--rol", required=True, choices=ROLES)
    p.set_defaults(func=cmd_rol)

    p = sub.add_parser("roles", help="mostrar los roles y sus permisos")
    p.set_defaults(func=cmd_roles)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return args.func(args)
    except ErrorUsuarios as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelado.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
