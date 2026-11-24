"""Suite 4: filtros de la vista de triage (P3 y P4). Casos CP-UI-15 a CP-UI-21."""

from __future__ import annotations

import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import FILAS, celdas, sin_filtro

SEVERIDADES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
TIPOS = {"Fuerza bruta SSH", "Escaneo de puertos", "Phishing / robo de credenciales", "Autenticación sospechosa"}
VACIO = "No hay eventos que coincidan con el filtro."


def _primera_fila(page) -> dict:
    """Severidad, IP y tipo de la primera fila, para elegir valores que existen."""
    fila = page.locator(FILAS).first
    return {"sev": fila.locator("td:nth-child(2) .badge").inner_text().strip(),
            "ip": fila.locator("td:nth-child(3)").inner_text().strip(),
            "tipo": fila.locator("td:nth-child(4)").inner_text().strip()}


def _tipo_valor(page, etiqueta: str) -> str:
    return page.locator("#fType option", has_text=etiqueta).first.get_attribute("value")


def test_cp_ui_15_filtrar_por_severidad(analista):
    # CP-UI-15: elegir una severidad en #fSeverity deja solo filas con esa severidad.
    page = analista
    sev = _primera_fila(page)["sev"]
    page.locator("#fSeverity").select_option(sev)
    expect(page.locator(FILAS).first).to_be_visible()
    expect(page.locator(FILAS).filter(has_not=page.locator(f".badge.b-{sev}"))).to_have_count(0)


def test_cp_ui_16_filtrar_por_tipo_de_ataque(analista):
    # CP-UI-16: elegir un tipo en #fType deja solo filas de ese tipo.
    page = analista
    tipo = _primera_fila(page)["tipo"]
    page.locator("#fType").select_option(_tipo_valor(page, tipo))
    expect(page.locator(FILAS).first).to_be_visible()
    expect(page.locator(FILAS).filter(has_not=page.locator("td:nth-child(4)", has_text=tipo))).to_have_count(0)


def test_cp_ui_17_filtrar_por_ip(analista):
    # CP-UI-17: escribir una IP existente en #fSearch deja solo filas con esa IP.
    page = analista
    ip = _primera_fila(page)["ip"]
    page.locator("#fSearch").fill(ip)
    expect(page.locator(FILAS).first).to_be_visible()
    expect(page.locator(FILAS).filter(has_not=page.locator("td:nth-child(3)", has_text=ip))).to_have_count(0)


def test_cp_ui_18_filtros_combinados(analista):
    # CP-UI-18: severidad, tipo e IP combinados muestran exactamente las filas que cumplen los tres criterios.
    page = analista
    filas = list(zip(celdas(page, 2), celdas(page, 3), celdas(page, 4), strict=True))
    elegido = _primera_fila(page)
    esperadas = [f for f in filas if elegido["sev"] in f[0] and f[1] == elegido["ip"] and f[2] == elegido["tipo"]]
    page.locator("#fSeverity").select_option(elegido["sev"])
    page.locator("#fType").select_option(_tipo_valor(page, elegido["tipo"]))
    page.locator("#fSearch").fill(elegido["ip"])
    expect(page.locator(FILAS)).to_have_count(len(esperadas))
    expect(page.locator(FILAS).filter(has_not=page.locator(f".badge.b-{elegido['sev']}"))).to_have_count(0)
    # El filtro es de verdad combinado: una IP que no es la de esa severidad y tipo vacía la tabla.
    page.locator("#fSearch").fill("10.255.255.254")
    expect(page.get_by_text(VACIO)).to_be_visible()


def test_cp_ui_19_ip_inexistente_muestra_el_mensaje_de_sin_resultados(analista):
    # CP-UI-19: una IP inexistente muestra «No hay eventos que coincidan con el filtro.».
    page = analista
    page.locator("#fSearch").fill("10.255.255.254")
    expect(page.locator(".empty")).to_have_text(VACIO)
    expect(page.locator(FILAS)).to_have_count(0)


def test_cp_ui_20_los_filtros_se_conservan_tras_el_refresco(analista):
    # CP-UI-20: con un filtro aplicado se espera 16 s al refresco y se conservan los valores y el conjunto filtrado.
    # Pausa fija permitida: el caso mide el refresco automático.
    page = analista
    elegido = _primera_fila(page)
    page.locator("#fSeverity").select_option(elegido["sev"])
    page.locator("#fSearch").fill(elegido["ip"])
    antes = celdas(page, 1)
    meta = page.locator("#meta").inner_text()
    page.locator("h1").click()  # saca el foco del campo: el refresco no repinta mientras se escribe
    page.wait_for_timeout(16_000)
    assert page.locator("#meta").inner_text() != meta, "no hubo refresco en 16 s"
    expect(page.locator("#fSeverity")).to_have_value(elegido["sev"])
    expect(page.locator("#fSearch")).to_have_value(elegido["ip"])
    assert celdas(page, 1) == antes


def test_cp_ui_21_la_tabla_muestra_severidad_y_tipo_sin_abrir_el_detalle(analista):
    # CP-UI-21: cada fila muestra la etiqueta de severidad y el tipo de ataque sin abrir ninguna ficha.
    page = analista
    sin_filtro(page)
    expect(page.locator("#detailWrap .card")).to_have_count(0)
    filas = page.locator(FILAS)
    assert filas.count() >= 1
    for texto in page.locator(f"{FILAS} td:nth-child(2) .badge").all_inner_texts():
        assert texto.strip() in SEVERIDADES, texto
    for texto in celdas(page, 4):
        assert texto in TIPOS | {"Otro"}, texto
    expect(filas.filter(has_not=page.locator("td:nth-child(3):not(:empty)"))).to_have_count(0)
    expect(filas.filter(has_not=page.locator("td:nth-child(6):not(:empty)"))).to_have_count(0)
    assert re.fullmatch(r"\d+", page.locator("#summary .principal .n").inner_text().strip())
