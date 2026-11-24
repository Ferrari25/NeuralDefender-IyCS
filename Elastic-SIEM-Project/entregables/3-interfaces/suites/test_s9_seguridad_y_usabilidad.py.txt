"""Suite 9: seguridad y usabilidad transversal (P2 y P11). Casos CP-UI-48 a CP-UI-54.

Los casos 48, 53 y 54 reemplazan la respuesta de GET /api/v1/incidents con `page.route`, para que el dato sea siempre el mismo.
"""

from __future__ import annotations

import copy
import re

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import (
    FILAS,
    URL,
    abrir_desplegable,
    abrir_ficha,
    entrar,
    modificar_incidentes,
)

HOSTIL = "<img src=x onerror=alert(1)>"


def test_cp_ui_48_un_texto_hostil_se_muestra_literal_y_no_se_ejecuta(page, malla):
    # CP-UI-48: un incidente con <img src=x onerror=alert(1)> se muestra como texto, sin crear <img> ni ejecutar código.
    def hostil(datos):
        incidente = datos["incidents"][0]
        incidente["analysis"] = {**(incidente.get("analysis") or {}), "explicacion": HOSTIL}
        incidente["rule_name"] = HOSTIL
        incidente["detection_source"] = "elastic"
        incidente.setdefault("classification", {})["factores"] = [HOSTIL]

    dialogos: list[str] = []
    page.on("dialog", lambda d: (dialogos.append(d.message), d.dismiss()))
    modificar_incidentes(page, hostil)
    entrar(page, "analista")
    abrir_ficha(page)
    expect(page.locator("#detailWrap").get_by_text(HOSTIL, exact=False).first).to_be_visible()
    expect(page.locator("#eventsTableWrap img, #detailWrap img")).to_have_count(0)
    assert dialogos == []


def test_cp_ui_49_la_ayuda_se_abre_con_el_clic(analista):
    # CP-UI-49: pulsar «Cómo funciona este panel» en la cabecera muestra #aboutPanel.
    page = analista
    expect(page.locator("#aboutPanel")).to_be_hidden()
    page.locator('[data-accion="about"]').click()
    expect(page.locator("#aboutPanel")).to_be_visible()
    expect(page.locator("#aboutPanel")).to_contain_text("La IA sugiere, el humano decide")


def test_cp_ui_50_la_ayuda_se_alcanza_y_se_abre_con_el_teclado(analista):
    # CP-UI-50: la ayuda recibe el foco con Tab y Enter muestra #aboutPanel (RNF-USA-08).
    page = analista
    for _ in range(40):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.matches('[data-accion=\"about\"]')"):
            break
    else:
        raise AssertionError("la ayuda no recibe el foco con Tab: es un <span> sin tabindex ni rol (H-2)")
    page.keyboard.press("Enter")
    expect(page.locator("#aboutPanel")).to_be_visible()


def test_cp_ui_51_cada_severidad_tiene_siempre_la_misma_clase_y_color(analista):
    # CP-UI-51: todas las etiquetas de un mismo nivel de severidad comparten clase (b-<NIVEL>) y color, y los niveles difieren.
    page = analista
    etiquetas = page.locator(".badge")
    assert etiquetas.count() >= 1
    datos = etiquetas.evaluate_all(
        "els => els.map(e => ({texto: e.textContent.trim(), clase: e.className, color: getComputedStyle(e).backgroundColor}))")
    por_nivel: dict[str, set] = {}
    for d in datos:
        assert re.search(rf"(^|\s)b-{d['texto']}(\s|$)", d["clase"]), d
        por_nivel.setdefault(d["texto"], set()).add((d["clase"], d["color"]))
    assert all(len(v) == 1 for v in por_nivel.values()), por_nivel
    colores = [next(iter(v))[1] for v in por_nivel.values()]
    assert len(set(colores)) == len(colores), por_nivel


def test_cp_ui_52_los_campos_de_texto_tienen_nombre_accesible(analista):
    # CP-UI-52: #fSearch y #leccionIp tienen etiqueta (label, aria-label o aria-labelledby); el placeholder no cuenta (WCAG 3.3.2).
    page = analista
    abrir_desplegable(page, "Enseñarle algo al agente")
    etiquetado = "e => !!(e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') || (e.labels && e.labels.length))"
    for selector in ("#fSearch", "#leccionIp"):
        assert page.locator(selector).evaluate(etiquetado), f"{selector} no tiene etiqueta accesible (solo placeholder)"


def test_cp_ui_53_la_tabla_muestra_como_maximo_100_incidentes(page, malla):
    # CP-UI-53 (valor límite 100): con 150 incidentes simulados (page.route) la tabla muestra como máximo 100 filas.
    def muchos(datos):
        base = datos["incidents"][0]
        datos["incidents"] = []
        for n in range(150):
            copia = copy.deepcopy(base)
            copia["incident_id"] = f"INC-TEST-{n:03d}"
            copia["recommended_actions"] = []
            datos["incidents"].append(copia)
        datos["incident_count"] = 150

    modificar_incidentes(page, muchos)
    entrar(page, "analista")
    expect(page.locator(FILAS).first).to_be_visible()
    cantidad = page.locator(FILAS).count()
    assert cantidad <= 100, f"la tabla pinta {cantidad} filas (máximo 100)"


def test_cp_ui_54_el_origen_del_analisis_se_muestra_en_el_distintivo(page, malla):
    # CP-UI-54: con analyst_mode = gemma (page.route), #modeBadge muestra «IA (Gemma local)».
    modificar_incidentes(page, lambda datos: datos.update(analyst_mode="gemma"))
    entrar(page, "analista")
    expect(page.locator("#modeBadge")).to_contain_text("IA (Gemma local)")
    expect(page).to_have_url(f"{URL}/")
