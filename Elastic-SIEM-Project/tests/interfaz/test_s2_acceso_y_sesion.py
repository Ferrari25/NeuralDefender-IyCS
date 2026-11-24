"""Suite 2: acceso y sesión (P2, `/`). Casos CP-UI-07 a CP-UI-11."""

from __future__ import annotations

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import FILAS, URL, entrar


def test_cp_ui_07_panel_sin_sesion_redirige_al_login(page, malla):
    # CP-UI-07: abrir / sin sesión redirige a /login.
    page.goto(f"{URL}/")
    expect(page).to_have_url(f"{URL}/login")


def test_cp_ui_08_el_panel_carga_completo_y_sin_errores(page, malla, consola):
    # CP-UI-08: el panel muestra usuario y rol, origen del análisis, totales y filas, sin errores de consola
    # ni recursos con respuesta 404 (incluido el ícono del sitio).
    entrar(page, "analista")
    page.wait_for_load_state("networkidle")
    expect(page.locator("#sesion")).to_contain_text("analista00")
    expect(page.locator("#sesion .rol")).to_have_text("analyst")
    expect(page.locator("#modeBadge")).not_to_have_text("cargando…")
    expect(page.locator("#modeBadge")).not_to_be_empty()
    expect(page.locator("#summary")).to_contain_text("incidente")
    expect(page.locator("#summary")).to_contain_text("acci")
    expect(page.locator(FILAS).first).to_be_visible()
    # El navegador pide el ícono por su cuenta y esa petición no pasa por page.on("response"): se consulta de forma
    # explícita (el <link rel="icon"> de la plantilla o, si no hay, /favicon.ico) para que el resultado no dependa del momento.
    icono = page.evaluate("document.querySelector('link[rel~=icon]')?.href ?? new URL('/favicon.ico', location).href")
    if not icono.startswith("data:"):  # un ícono embebido no genera ninguna petición
        assert page.request.get(icono).status < 400, f"el ícono del sitio responde con error: {icono}"
    consola.verificar_todo()


def test_cp_ui_09_cerrar_sesion_corta_el_acceso(page, malla):
    # CP-UI-09: #salir vuelve a /login y, al abrir /, se vuelven a pedir las credenciales.
    entrar(page, "analista")
    page.locator("#salir").click()
    expect(page).to_have_url(f"{URL}/login")
    page.goto(f"{URL}/")
    expect(page).to_have_url(f"{URL}/login")


def test_cp_ui_10_una_respuesta_401_en_el_refresco_redirige_al_login(page, malla):
    # CP-UI-10: con una sesión que el servidor da por vencida (401 simulado con page.route en /api/v1/incidents),
    # el panel navega a /login en el siguiente refresco (cada 15 s; se espera con el timeout de la espera).
    # Se comprueba la petición a /login y no la URL final: la sesión real sigue vigente y el servidor
    # devuelve a / a quien entra a /login con sesión (CP-UI-06).
    entrar(page, "analista")
    with page.expect_request(f"{URL}/login", timeout=20_000):
        page.route("**/api/v1/incidents", lambda ruta: ruta.fulfill(
            status=401, content_type="application/json", body='{"error": "se requiere autenticación"}'))


def test_cp_ui_11_el_panel_se_actualiza_cada_15_segundos(page, malla):
    # CP-UI-11: #meta ("actualizado hh:mm:ss") cambia tras esperar 16 s. Pausa fija permitida: el caso mide el refresco.
    entrar(page, "analista")
    antes = page.locator("#meta").inner_text()
    page.wait_for_timeout(16_000)
    despues = page.locator("#meta").inner_text()
    assert despues != antes, f"#meta no cambió en 16 s: {antes!r}"
