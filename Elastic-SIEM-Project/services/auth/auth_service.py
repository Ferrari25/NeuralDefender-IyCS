#!/usr/bin/env python3
"""Servicio de autenticación: único dueño del almacén de usuarios.

Los hashes de contraseña nunca salen de este servicio. El gateway le manda las
credenciales que tipeó el analista y recibe solo quién es y qué puede hacer.

API (red interna, exige `X-Internal-Token`):
    POST /v1/authenticate      {username, password, client_ip}
                               → 200 {usuario, rol, permisos}
                               → 401 credenciales inválidas (mismo mensaje siempre)
                               → 429 {reintentar_en} si el control de intentos bloquea
    GET  /v1/users/<username>  → 200 vista pública del usuario · 404 si no existe
    GET  /v1/users-summary     → usuarios activos por rol (para el arranque del panel)

El alta, la baja y los cambios de rol NO están en la API, igual que antes no
estaban en la web: se hacen con `manage_users.py` sobre el volumen del servicio.
"""

from __future__ import annotations

from flask import jsonify

from siem_auth import ErrorUsuarios, autenticar, cargar_usuarios, vista_publica
from siem_servicios import crear_servicio, cuerpo_json

app = crear_servicio("auth")


@app.post("/v1/authenticate")
def autenticar_usuario():
    datos = cuerpo_json()
    if datos is None:
        return jsonify({"error": "se esperaba un cuerpo JSON"}), 400

    # La IP del navegador la conoce el gateway, no este servicio (que solo ve
    # al gateway). Es la clave del control de intentos junto con el usuario.
    ip = datos.get("client_ip")
    if not isinstance(ip, str) or not ip:
        ip = "desconocida"

    resultado = autenticar(datos.get("username"), datos.get("password"), ip)
    if not resultado.ok:
        if resultado.espera_segundos:
            return jsonify({"error": resultado.motivo,
                            "reintentar_en": resultado.espera_segundos}), 429
        return jsonify({"error": resultado.motivo}), 401

    publico = vista_publica(resultado.usuario)
    return jsonify({"usuario": publico["username"], "rol": publico["rol"],
                    "permisos": publico["permisos"]}), 200


@app.get("/v1/users/<username>")
def usuario(username: str):
    """Relee el almacén en cada consulta: una baja tiene efecto inmediato."""
    encontrado = cargar_usuarios().get(username)
    if encontrado is None:
        return jsonify({"error": "usuario inexistente"}), 404
    return jsonify(vista_publica(encontrado))


@app.get("/v1/users-summary")
def resumen_usuarios():
    try:
        usuarios = cargar_usuarios()
    except ErrorUsuarios as e:
        return jsonify({"error": str(e)}), 500
    por_rol: dict[str, int] = {}
    for u in usuarios.values():
        if u.activo:
            por_rol[u.rol] = por_rol.get(u.rol, 0) + 1
    return jsonify({"total": len(usuarios), "activos_por_rol": por_rol})
