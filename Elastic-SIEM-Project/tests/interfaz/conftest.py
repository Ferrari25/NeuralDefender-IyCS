"""Pruebas de interfaz: un navegador de verdad (Chromium, vía Playwright) usa el panel.

Las pruebas de `tests/integration/` le pegan a la API con el cliente de Flask:
verifican lo que el servidor responde, pero no lo que el analista VE. Acá el
panel se sirve por HTTP real en un puerto efímero de 127.0.0.1 y Chromium lo
maneja como lo haría una persona: tipea, hace clic, espera, lee la pantalla.
Así se prueba también `app.js` y `login.js`, que el resto de la suite no ejecuta.

El servidor es el mismo `dashboard` de `app_dashboard` (sandbox + usuarios de
prueba + malla de microservicios en proceso), pero con CSRF **encendido**: el
navegador tiene que hacer el mismo recorrido que en producción.

Si Playwright o Chromium no están instalados, todas estas pruebas se saltean
(no fallan): ver `pruebas_de_interfaz.md` para instalarlos.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from tests.conftest import PASSWORD_DE_PRUEBA

sync_api = pytest.importorskip("playwright.sync_api", reason="falta playwright (ver pruebas_de_interfaz.md)")


@pytest.fixture(scope="session", autouse=True)
def _chromium_instalado():
    with sync_api.sync_playwright() as p:
        if not Path(p.chromium.executable_path).exists():
            pytest.skip("falta Chromium: python3 -m playwright install chromium")


@pytest.fixture
def panel(app_dashboard) -> str:
    """URL base del panel, servido por HTTP real en un hilo."""
    from werkzeug.serving import make_server

    app = app_dashboard.app
    app.config.update(TESTING=False, WTF_CSRF_ENABLED=True)
    servidor = make_server("127.0.0.1", 0, app, threaded=True)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{servidor.server_port}"
    servidor.shutdown()
    hilo.join(timeout=5)


@pytest.fixture
def errores_de_consola(page) -> list[str]:
    """Junta los errores de JavaScript de la página: ninguna prueba debería dejar uno."""
    errores: list[str] = []
    page.on("pageerror", lambda e: errores.append(str(e)))
    page.on("console", lambda m: errores.append(m.text) if m.type == "error" else None)
    return errores


@pytest.fixture
def entrar(page, panel):
    """Abre sesión desde la pantalla de login, como una persona."""

    def _entrar(usuario: str = "ana", password: str = PASSWORD_DE_PRUEBA):
        page.goto(f"{panel}/login")
        page.fill("#username", usuario)
        page.fill("#password", password)
        page.click("#enviar")
        page.wait_for_url(f"{panel}/")
        # El panel está listo cuando la tabla de incidentes ya se dibujó.
        page.wait_for_selector("table.events tbody tr")
        return page

    return _entrar
