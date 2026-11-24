"""Ayudas comunes de las nueve suites de interfaz, que corren contra la malla aislada.

Las suites `test_s1_*.py` a `test_s9_*.py` usan el panel que sirve la malla en
`http://127.0.0.1:18080` (arrancada con `entregables/2-servicios/postman/malla.sh reiniciar`),
con los usuarios de prueba de cada rol. Los selectores salen de
`entregables/3-interfaces/inventario-interfaz.md`.

Reglas del plan que se respetan acá: sin pausas fijas (solo `expect` con espera automática; las únicas
excepciones son CP-UI-11 y CP-UI-20, que esperan un ciclo de refresco), un contexto de navegador por
prueba, y los casos que simulan al servidor lo hacen con `page.route`.
"""

from __future__ import annotations

import os
import re

from playwright.sync_api import Page, expect

URL = os.environ.get("NEURALDEFENDER_URL", "http://127.0.0.1:18080")
PASSWORD = "PruebaMalla#2026"
USUARIO = {"analista": "analista00", "observador": "observador00", "auditor": "auditor00"}
DESCARTABLE = "victima00x00"

FILAS = "table.events tbody tr"
DIALOGO = "dialog#confirmacion"
MENSAJE_LOGIN_INVALIDO = "usuario o contraseña incorrectos"


class Consola:
    """Junta lo que el navegador registra como error: consola, excepciones y recursos con 4xx o 5xx."""

    def __init__(self, page: Page) -> None:
        self.mensajes: list[str] = []
        self.excepciones: list[str] = []
        self.recursos: list[str] = []
        page.on("console", lambda m: self.mensajes.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: self.excepciones.append(str(e)))
        page.on("response", lambda r: self.recursos.append(f"{r.status} {r.url}") if r.status >= 400 else None)

    def verificar_javascript(self) -> None:
        assert not self.excepciones, f"excepciones de JavaScript: {self.excepciones}"

    def verificar_todo(self) -> None:
        """Ningún error de consola ni recurso con error, incluido el ícono del sitio (plan, sección 7)."""
        self.verificar_javascript()
        assert not self.mensajes, f"errores de consola: {self.mensajes}"
        assert not self.recursos, f"recursos con error: {self.recursos}"


# ─── Sesión ─────────────────────────────────────────────────────────────────

def entrar(page: Page, rol: str = "analista", password: str = PASSWORD) -> Page:
    """Inicia sesión desde la pantalla de login, como una persona, y espera a que la tabla se dibuje."""
    page.goto(f"{URL}/login")
    page.locator("#username").fill(USUARIO.get(rol, rol))
    page.locator("#password").fill(password)
    page.get_by_role("button", name="Iniciar sesión").click()
    expect(page).to_have_url(f"{URL}/")
    expect(page.locator(FILAS).first).to_be_visible()
    return page


# ─── Detalle y decisiones ───────────────────────────────────────────────────

def abrir_ficha(page: Page, indice: int = 0) -> str:
    """Abre la ficha de la fila `indice` y devuelve su incident_id."""
    fila = page.locator(FILAS).nth(indice)
    incidente = fila.get_attribute("data-incidente")
    fila.click()
    expect(page.locator("#detailWrap .card")).to_be_visible()
    return incidente


def accion(page: Page, action_id: str):
    """La acción principal con ese identificador (sus botones están en `> .top`)."""
    return page.locator(f'#detailWrap .action:has(> .top [data-action-id="{action_id}"][data-accion="decidir"])')


def primera_pendiente(page: Page) -> str:
    """action_id de la primera acción principal que sigue pendiente en la ficha abierta."""
    boton = page.locator(
        '#detailWrap .action:not(.alternativa):has(> .top .state.s-pending) > .top [data-accion="decidir"]').first
    expect(boton).to_be_visible()
    return boton.get_attribute("data-action-id")


def confirmar(page: Page) -> None:
    expect(page.locator(DIALOGO)).to_be_visible()
    page.locator("#confirmacionSi").click()
    expect(page.locator(DIALOGO)).to_be_hidden()


def cancelar_dialogo(page: Page) -> None:
    expect(page.locator(DIALOGO)).to_be_visible()
    page.locator(DIALOGO).get_by_role("button", name="Cancelar").click()
    expect(page.locator(DIALOGO)).to_be_hidden()


def aprobar(page: Page, action_id: str) -> None:
    """Aprobar con el cuadro de confirmación, esperando el aviso de la decisión registrada."""
    accion(page, action_id).locator(':scope > .top [data-accion="decidir"]').click()
    confirmar(page)
    expect(page.locator("#toast")).to_contain_text("✔ Acción aprobada")


def pendientes_del_resumen(page: Page) -> int:
    return int(page.locator("#summary .principal .n").inner_text())


def abrir_desplegable(page: Page, texto: str) -> None:
    """Abre el <details> cuyo <summary> dice `texto`, si está cerrado."""
    detalle = page.locator("details").filter(has=page.locator("summary", has_text=texto))
    if not detalle.evaluate("e => e.open"):
        detalle.locator("summary").click()
    expect(detalle).to_have_attribute("open", "")


# ─── Memoria ────────────────────────────────────────────────────────────────

def proponer_leccion(page: Page, texto: str) -> None:
    abrir_desplegable(page, "Enseñarle algo al agente")
    page.locator("#leccionTexto").fill(texto)
    page.get_by_role("button", name="Proponer lección").click()
    expect(page.locator("#toast")).to_contain_text("Lección propuesta")


def leccion(page: Page, texto: str):
    return page.locator("#memoriaLecciones .leccion").filter(has_text=texto)


# ─── Simulación de respuestas del servidor (page.route) ─────────────────────

def modificar_incidentes(page: Page, cambio) -> None:
    """Intercepta GET /api/v1/incidents: pide la respuesta real y le aplica `cambio(datos)`."""

    def manejador(ruta):
        if ruta.request.method != "GET":
            ruta.continue_()
            return
        respuesta = ruta.fetch()
        datos = respuesta.json()
        cambio(datos)
        ruta.fulfill(response=respuesta, json=datos)

    page.route("**/api/v1/incidents", manejador)


def sin_filtro(page: Page) -> None:
    expect(page.locator("#fSeverity")).to_have_value("")
    expect(page.locator("#fType")).to_have_value("")
    expect(page.locator("#fSearch")).to_have_value("")


def celdas(page: Page, columna: int) -> list[str]:
    """Texto de la columna `columna` (1 = ID) de cada fila visible."""
    return [t.strip() for t in page.locator(f"{FILAS} td:nth-child({columna})").all_inner_texts()]


def con_clase(texto: str) -> re.Pattern:
    return re.compile(rf"(^|\s){re.escape(texto)}(\s|$)")
