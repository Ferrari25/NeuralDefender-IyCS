"""Suite 1: inicio de sesión (P1, `/login`). Casos CP-UI-01 a CP-UI-06 del plan de pruebas de interfaz."""

from __future__ import annotations

import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import DESCARTABLE, MENSAJE_LOGIN_INVALIDO, PASSWORD, URL, entrar


def _escribir(page, usuario: str, password: str) -> None:
    page.locator("#username").fill(usuario)
    page.locator("#password").fill(password)


def test_cp_ui_01_login_valido_entra_al_panel(page, malla, consola):
    # CP-UI-01: con credenciales válidas, /login redirige a / y el panel muestra el usuario en #sesion.
    page.goto(f"{URL}/login")
    _escribir(page, "analista00", PASSWORD)
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(page).to_have_url(f"{URL}/")
    expect(page.locator("#sesion")).to_contain_text("analista00")
    consola.verificar_javascript()


def test_cp_ui_02_contrasena_incorrecta_muestra_error_y_vacia_el_campo(page, malla):
    # CP-UI-02: con contraseña incorrecta se queda en /login, #aviso dice el error y el campo de contraseña se vacía.
    page.goto(f"{URL}/login")
    _escribir(page, "analista00", "contraseña-incorrecta")
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(page.locator("#aviso")).to_have_text(MENSAJE_LOGIN_INVALIDO)
    expect(page.locator("#password")).to_have_value("")
    expect(page).to_have_url(f"{URL}/login")


def test_cp_ui_03_usuario_inexistente_no_revela_que_no_existe(page, malla):
    # CP-UI-03: un usuario inexistente recibe el mismo mensaje que CP-UI-02, sin revelar si existe.
    page.goto(f"{URL}/login")
    _escribir(page, "noexiste99", "cualquier-contraseña")
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(page.locator("#aviso")).to_have_text(MENSAJE_LOGIN_INVALIDO)
    expect(page).to_have_url(f"{URL}/login")


def test_cp_ui_04_campos_vacios_no_envian_el_formulario(page, malla):
    # CP-UI-04: con ambos campos vacíos el formulario no se envía (no hay llamada a la API) y sigue en /login.
    llamadas = []
    page.on("request", lambda r: llamadas.append(r.url) if r.url.endswith("/api/v1/login") else None)
    page.goto(f"{URL}/login")
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(page).to_have_url(f"{URL}/login")
    assert page.locator("#username").evaluate("e => e.validity.valueMissing")
    assert page.locator("#password").evaluate("e => e.validity.valueMissing")
    assert llamadas == []


def test_cp_ui_05_bloqueo_tras_cinco_intentos_fallidos(page, malla):
    # CP-UI-05 (valor límite 5 y 6): los cinco primeros intentos reciben el error; el sexto, el bloqueo (clase espera).
    page.goto(f"{URL}/login")
    aviso = page.locator("#aviso")
    for n in range(1, 6):
        _escribir(page, DESCARTABLE, f"incorrecta-{n}")
        page.get_by_role("button", name="Iniciar sesión").click()
        expect(aviso).to_have_text(MENSAJE_LOGIN_INVALIDO)
        expect(aviso).to_have_class(re.compile(r"(^|\s)error(\s|$)"))
        expect(page.locator("#password")).to_have_value("")
        expect(page.locator("#enviar")).to_be_enabled()
    _escribir(page, DESCARTABLE, "incorrecta-6")
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(aviso).to_have_class(re.compile(r"(^|\s)espera(\s|$)"))
    expect(aviso).to_contain_text(re.compile(r"\d"))  # el tiempo de bloqueo
    expect(page).to_have_url(f"{URL}/login")


def test_cp_ui_06_con_sesion_abierta_login_redirige_al_panel(page, malla):
    # CP-UI-06: con una sesión abierta, abrir /login redirige a / sin pedir credenciales.
    entrar(page, "analista")
    page.goto(f"{URL}/login")
    expect(page).to_have_url(f"{URL}/")
