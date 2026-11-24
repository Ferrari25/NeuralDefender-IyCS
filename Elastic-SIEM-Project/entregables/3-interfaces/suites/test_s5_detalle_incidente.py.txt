"""Suite 5: detalle del incidente (P5). Casos CP-UI-22 a CP-UI-27."""

from __future__ import annotations

import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import FILAS, abrir_ficha, entrar, modificar_incidentes

FICHA = "#detailWrap .card"


def test_cp_ui_22_abrir_la_ficha_con_un_clic(analista):
    # CP-UI-22: pulsar una fila abre la ficha en #detailWrap .card y marca la fila como selected.
    page = analista
    incidente = page.locator(FILAS).first.get_attribute("data-incidente")
    page.locator(f'tr[data-incidente="{incidente}"]').click()
    expect(page.locator(FICHA)).to_be_visible()
    expect(page.locator(f'tr[data-incidente="{incidente}"]')).to_have_class(re.compile(r"(^|\s)selected(\s|$)"))
    expect(page.locator(f"{FICHA} .id")).to_have_text(incidente)
    expect(page.locator(FICHA)).to_contain_text("Qué pasó:")
    expect(page.locator(f"{FICHA} .actions")).to_be_visible()


def test_cp_ui_23_abrir_la_ficha_con_el_teclado(analista):
    # CP-UI-23: una fila alcanzada con Tab se abre con Enter, igual que con el ratón.
    page = analista
    for _ in range(40):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.matches('tr[data-incidente]')"):
            break
    else:
        raise AssertionError("ninguna fila recibió el foco con Tab")
    incidente = page.evaluate("document.activeElement.dataset.incidente")
    page.keyboard.press("Enter")
    expect(page.locator(FICHA)).to_be_visible()
    expect(page.locator(f"{FICHA} .id")).to_have_text(incidente)


def test_cp_ui_24_cerrar_la_ficha_quita_la_marca_de_la_fila(analista):
    # CP-UI-24: el botón «cerrar ✕» cierra la ficha y quita la marca selected de la fila.
    page = analista
    incidente = abrir_ficha(page)
    page.locator(f"{FICHA} .close").click()
    expect(page.locator(FICHA)).to_have_count(0)
    expect(page.locator(f'tr[data-incidente="{incidente}"]')).not_to_have_class(re.compile(r"(^|\s)selected(\s|$)"))


def test_cp_ui_25_desplegar_evidencia_y_alternativas(analista):
    # CP-UI-25: la evidencia y las alternativas se despliegan; aria-expanded pasa a true y el contenido se ve.
    page = analista
    abrir_ficha(page)
    evidencia = page.locator(f"{FICHA} .ev-head")
    cuerpo = page.locator(f"{FICHA} .ev-body")
    expect(evidencia).to_have_attribute("aria-expanded", "true")  # la evidencia nace desplegada
    evidencia.click()
    expect(evidencia).to_have_attribute("aria-expanded", "false")
    expect(cuerpo).to_be_hidden()
    evidencia.click()
    expect(evidencia).to_have_attribute("aria-expanded", "true")
    expect(cuerpo).to_be_visible()
    alternativas = page.locator(f"{FICHA} .alt-head").first
    expect(alternativas).to_have_attribute("aria-expanded", "false")
    alternativas.click()
    expect(alternativas).to_have_attribute("aria-expanded", "true")
    expect(page.locator(f"{FICHA} .alt-body").first).to_be_visible()


def test_cp_ui_26_enlace_a_un_incidente_de_la_misma_campana(page, malla):
    # CP-UI-26: el banner de campaña enlaza a los incidentes relacionados y el enlace abre su ficha.
    # La malla no trae ninguna campaña: se simula en la respuesta de /api/v1/incidents con page.route.
    def con_campana(datos):
        a, b = datos["incidents"][0], datos["incidents"][1]
        a["related_incidents"], b["related_incidents"] = [b["incident_id"]], [a["incident_id"]]
        a["campaign_shared_ips"] = b["campaign_shared_ips"] = ["203.0.113.77"]

    modificar_incidentes(page, con_campana)
    entrar(page, "analista")
    primero, segundo = (page.locator(FILAS).nth(i).get_attribute("data-incidente") for i in (0, 1))
    page.locator(f'tr[data-incidente="{primero}"]').click()
    banner = page.locator(f"{FICHA} .campaign-banner")
    expect(banner).to_contain_text("Parte de una campaña de 2 incidentes")
    banner.locator(f'a[data-incidente="{segundo}"]').click()
    expect(page.locator(f"{FICHA} .id")).to_have_text(segundo)


def test_cp_ui_27_el_comando_se_muestra_como_texto_con_su_explicacion(page, malla):
    # CP-UI-27: el comando sugerido es texto («$ …») con su explicación, la explicación del análisis y el falso positivo,
    # sin control que lo ejecute. La malla no trae análisis: se simula un incidente con análisis con page.route.
    def con_analisis(datos):
        datos["incidents"][0]["analysis"] = {
            "explicacion": "Escaneo de puertos desde una IP interna.", "metodologia": "Umbral de puertos distintos.",
            "contexto_riesgo": "Host expuesto.", "falso_positivo_probabilidad": "LOW"}

    modificar_incidentes(page, con_analisis)
    entrar(page, "analista")
    abrir_ficha(page)
    expect(page.locator(f"{FICHA} .analysis")).to_contain_text("Escaneo de puertos desde una IP interna.")
    comando = page.locator(f"{FICHA} .cmd").first
    expect(comando).to_contain_text("$ ")
    expect(page.locator(f"{FICHA} .cmd-explain").first).to_be_visible()
    falso_positivo = page.locator(f"{FICHA} .grid span.k", has_text="Falso pos.").locator("xpath=following-sibling::span[1]")
    expect(falso_positivo).to_contain_text("LOW")
    botones = page.locator(f"{FICHA} .actions button")
    permitidos = {"decidir", "pedir-motivo", "confirmar-descarte", "cancelar-motivo", "alternativas"}
    for boton in botones.all():
        assert boton.get_attribute("data-accion") in permitidos, boton.inner_text()
    expect(page.locator(f"{FICHA} .actions").get_by_role("button", name=re.compile("ejecut", re.I))).to_have_count(0)
