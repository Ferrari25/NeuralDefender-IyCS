"""Suite 3: permisos por rol (P2). Tabla de decisión: rol contra controles visibles. Casos CP-UI-12 a CP-UI-14."""

from __future__ import annotations

import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import abrir_ficha

DECIDIR = '[data-accion="decidir"]'
DESCARTAR = '[data-accion="pedir-motivo"]'
REVISAR_LECCION = '[data-accion="revisar-leccion"]'


def _sin_controles_de_escritura(page) -> None:
    expect(page.locator("body")).to_have_class(re.compile(r"solo-lectura"))
    expect(page.locator(f"#detailWrap {DECIDIR}").first).to_be_hidden()
    expect(page.locator(f"#detailWrap {DESCARTAR}").first).to_be_hidden()
    expect(page.locator("#formLeccion")).to_be_hidden()
    expect(page.locator("#formDocumento")).to_be_hidden()
    expect(page.locator(REVISAR_LECCION).first).to_be_hidden()


def test_cp_ui_12_el_analista_ve_los_controles_de_decision(analista):
    # CP-UI-12: el analista ve Aprobar y Descartar en una acción pendiente y los formularios de memoria.
    page = analista
    abrir_ficha(page)
    expect(page.locator(f"#detailWrap {DECIDIR}").first).to_be_visible()
    expect(page.locator(f"#detailWrap {DESCARTAR}").first).to_be_visible()
    expect(page.locator("body")).not_to_have_class(re.compile(r"solo-lectura"))
    expect(page.locator("#formLeccion")).to_be_attached()
    expect(page.locator("#formDocumento")).to_be_attached()
    page.locator("summary", has_text="Enseñarle algo al agente").click()
    page.locator("summary", has_text="Cargar un documento").click()
    expect(page.locator("#formLeccion")).to_be_visible()
    expect(page.locator("#formDocumento")).to_be_visible()


def test_cp_ui_13_el_observador_no_ve_controles_de_decision_ni_de_memoria(observador):
    # CP-UI-13: el observador ve el incidente y sus acciones, sin botones de decisión ni formularios de memoria.
    page = observador
    abrir_ficha(page)
    expect(page.locator("#detailWrap .action").first).to_be_visible()
    _sin_controles_de_escritura(page)


def test_cp_ui_14_el_auditor_no_ve_controles_de_decision_ni_de_memoria(auditor):
    # CP-UI-14: el auditor ve el incidente sin botones de decisión ni formularios de memoria.
    page = auditor
    abrir_ficha(page)
    expect(page.locator("#detailWrap .action").first).to_be_visible()
    _sin_controles_de_escritura(page)
