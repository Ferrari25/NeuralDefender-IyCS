"""Suite 7: historial de decisiones y reportes (P6 y P7). Casos CP-UI-36 a CP-UI-39."""

from __future__ import annotations

import json

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import abrir_desplegable, abrir_ficha, aprobar, primera_pendiente

CABECERA = "#decisionHistory .decision-head"


def _con_una_decision(page) -> None:
    """Precondición de CP-UI-36: al menos una decisión registrada (si no hay, se aprueba una acción)."""
    page.locator("#decisionHistory").wait_for()
    if page.locator(CABECERA).count() == 0:
        abrir_ficha(page)
        aprobar(page, primera_pendiente(page))
    expect(page.locator(CABECERA).first).to_be_visible()


def _rango(page, desde: str, hasta: str) -> None:
    abrir_desplegable(page, "Sacar un reporte")
    page.locator("#repDesde").fill(desde)
    page.locator("#repHasta").fill(hasta)


def test_cp_ui_36_desplegar_el_historial_de_decisiones(analista):
    # CP-UI-36: el botón del historial pasa aria-expanded a true y muestra el detalle de las decisiones.
    page = analista
    _con_una_decision(page)
    cabecera = page.locator(CABECERA).first
    expect(cabecera).to_have_attribute("aria-expanded", "false")
    cabecera.click()
    expect(cabecera).to_have_attribute("aria-expanded", "true")
    expect(page.locator("#decisionHistory .decision-detalle").first).to_contain_text("Aprobada")


def test_cp_ui_37_descargar_el_reporte_csv_con_rango_valido(analista):
    # CP-UI-37: con un rango válido, «Descargar CSV» inicia una descarga con nombre terminado en .csv.
    page = analista
    _rango(page, "2026-01-01", "2026-12-31")
    with page.expect_download() as descarga:
        page.get_by_role("button", name="Descargar CSV").click()
    assert descarga.value.suggested_filename.endswith(".csv"), descarga.value.suggested_filename


def test_cp_ui_38_ver_el_reporte_json_en_una_pestana_nueva(analista):
    # CP-UI-38: con el mismo rango, «Ver JSON» abre una pestaña con un JSON que trae generado_en, periodo, resumen, decisiones, accesos, actividad e integridad.
    page = analista
    _rango(page, "2026-01-01", "2026-12-31")
    with page.context.expect_page() as nueva:
        page.get_by_role("button", name="Ver JSON").click()
    pestana = nueva.value
    pestana.wait_for_load_state()
    datos = json.loads(pestana.locator("body").inner_text())
    faltan = {"generado_en", "periodo", "resumen", "decisiones", "accesos", "actividad", "integridad"} - set(datos)
    assert not faltan, f"al JSON le faltan {sorted(faltan)}; trae {sorted(datos)}"


def test_cp_ui_39_rango_de_fechas_invertido_muestra_el_error_400(analista):
    # CP-UI-39: con «desde» posterior a «hasta» el servidor responde 400 y no se descarga ningún archivo.
    page = analista
    descargas = []
    page.on("download", lambda d: descargas.append(d))
    _rango(page, "2026-12-31", "2026-01-01")
    with page.expect_navigation() as navegacion:
        page.get_by_role("button", name="Descargar CSV").click()
    assert navegacion.value.status == 400
    expect(page.locator("body")).to_contain_text("posterior")
    assert descargas == []
