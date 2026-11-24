"""Suite 6: decisiones sobre acciones (P5, P10 y P11). Casos CP-UI-28 a CP-UI-35.

Los casos que registran una decisión consumen acciones pendientes de la malla: una corrida completa
necesita la malla recién reiniciada (`malla.sh reiniciar`).
"""

from __future__ import annotations

import json
import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import (
    DIALOGO,
    abrir_ficha,
    accion,
    aprobar,
    cancelar_dialogo,
    confirmar,
    entrar,
    pendientes_del_resumen,
    primera_pendiente,
)

PENDIENTE = re.compile(r"pendiente")


def _boton(page, action_id: str, nombre: str):
    return accion(page, action_id).locator(":scope > .top").get_by_role("button", name=nombre, exact=True)


def _estado(page, action_id: str):
    return accion(page, action_id).locator(":scope > .top .state")


def _registrar_posts(page) -> list[str]:
    posts: list[str] = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/v1/decision") else None)
    return posts


def test_cp_ui_28_aprobar_con_confirmacion_en_tres_interacciones(analista):
    # CP-UI-28: seleccionar la fila (1), Aprobar (2) y Confirmar (3) muestran el cuadro, el aviso «✔ Acción aprobada»,
    # la acción «✔ aprobada», la decisión en el historial y un pendiente menos en el resumen.
    page = analista
    pendientes = pendientes_del_resumen(page)
    incidente = page.locator("table.events tbody tr").first.get_attribute("data-incidente")
    page.locator(f'tr[data-incidente="{incidente}"]').click()                      # interacción 1
    action_id = primera_pendiente(page)
    page.locator(f'[data-accion="decidir"][data-action-id="{action_id}"]').click()  # interacción 2
    expect(page.locator("#confirmacionTitulo")).to_have_text("Vas a aprobar esta acción")
    page.locator("#confirmacionSi").click()                                         # interacción 3
    expect(page.locator("#toast")).to_contain_text("✔ Acción aprobada")
    expect(_estado(page, action_id)).to_have_text("✔ aprobada")
    expect(page.locator("#decisionHistory")).to_contain_text(incidente)
    expect(page.locator("#summary .principal .n")).to_have_text(str(pendientes - 1))


def test_cp_ui_29_cancelar_la_confirmacion_no_registra_nada(analista):
    # CP-UI-29: cancelar el cuadro de confirmación cierra el cuadro, deja la acción pendiente y no llama a la API.
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    posts = _registrar_posts(page)
    historial = page.locator("#decisionHistory").inner_text()
    page.locator(f'[data-accion="decidir"][data-action-id="{action_id}"]').click()
    cancelar_dialogo(page)
    expect(_estado(page, action_id)).to_have_text(PENDIENTE)
    expect(page.locator("#decisionHistory")).to_have_text(historial)
    assert posts == []


def test_cp_ui_30_descartar_con_motivo_guarda_la_nota(analista):
    # CP-UI-30: Descartar pide el motivo; al confirmar, el aviso es «✘ Acción descartada» y .decided muestra la nota.
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    _boton(page, action_id, "Descartar").click()
    page.locator(f'[id="motivo-{action_id}"]').fill("falso positivo de prueba CP-UI-30")
    page.get_by_role("button", name="Confirmar descarte").click()
    expect(page.locator("#confirmacionTitulo")).to_have_text("Vas a descartar esta sugerencia")
    confirmar(page)
    expect(page.locator("#toast")).to_contain_text("✘ Acción descartada")
    expect(_estado(page, action_id)).to_have_text("✘ descartada")
    expect(accion(page, action_id).locator(":scope > .decided")).to_contain_text("nota: falso positivo de prueba CP-UI-30")


def test_cp_ui_31_descartar_sin_motivo_advierte_y_no_registra(analista):
    # CP-UI-31: confirmar el descarte sin motivo muestra la advertencia en el cuadro; al cancelarlo no se registra nada.
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    posts = _registrar_posts(page)
    _boton(page, action_id, "Descartar").click()
    page.get_by_role("button", name="Confirmar descarte").click()
    expect(page.locator(f"{DIALOGO} .confirmacion-avisos")).to_contain_text("Descartás sin motivo")
    cancelar_dialogo(page)
    expect(_estado(page, action_id)).to_have_text(PENDIENTE)
    assert posts == []


def test_cp_ui_32_cancelar_el_formulario_del_motivo(analista):
    # CP-UI-32: cancelar el formulario del motivo lo oculta y la acción sigue pendiente.
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    _boton(page, action_id, "Descartar").click()
    formulario = page.locator(f'[id="motivo-{action_id}"]')
    expect(formulario).to_be_visible()
    page.locator('[data-accion="cancelar-motivo"]').click()
    expect(formulario).to_have_count(0)
    expect(_estado(page, action_id)).to_have_text(PENDIENTE)


def test_cp_ui_33_decidir_de_nuevo_advierte_que_reemplaza_la_decision(analista):
    # CP-UI-33: decidir sobre una acción ya aprobada advierte en el cuadro que la decisión reemplaza a la anterior.
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    aprobar(page, action_id)
    _boton(page, action_id, "Descartar").click()
    page.get_by_role("button", name="Confirmar descarte").click()
    expect(page.locator(f"{DIALOGO} .confirmacion-avisos")).to_contain_text("Esta acción ya estaba")
    expect(page.locator(f"{DIALOGO} .confirmacion-avisos")).to_contain_text("Tu decisión la reemplaza")
    cancelar_dialogo(page)


def test_cp_ui_34_si_el_servidor_falla_se_avisa_y_la_accion_sigue_pendiente(page, malla):
    # CP-UI-34: con POST /api/v1/decision simulado en 503 (page.route), el aviso es de error y la acción sigue pendiente.
    def caido(ruta):
        if ruta.request.method == "POST":
            ruta.fulfill(status=503, content_type="application/json",
                         body=json.dumps({"error": "el servicio audit no está disponible"}))
        else:
            ruta.continue_()

    page.route("**/api/v1/decision", caido)
    entrar(page, "analista")
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    page.locator(f'[data-accion="decidir"][data-action-id="{action_id}"]').click()
    confirmar(page)
    expect(page.locator("#toast")).to_have_class(re.compile(r"(^|\s)error(\s|$)"))
    expect(page.locator("#toast")).to_contain_text("el servicio audit no está disponible")
    expect(_estado(page, action_id)).to_have_text(PENDIENTE)


def test_cp_ui_35_la_decision_se_firma_con_el_usuario_de_la_sesion(analista):
    # CP-UI-35: tras aprobar, .decided muestra el nombre del usuario de la sesión (analista00).
    page = analista
    abrir_ficha(page)
    action_id = primera_pendiente(page)
    aprobar(page, action_id)
    expect(accion(page, action_id).locator(":scope > .decided")).to_contain_text("por analista00")
