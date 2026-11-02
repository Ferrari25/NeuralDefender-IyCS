"""El panel de supervisión, usado desde un navegador real.

Cada prueba es un recorrido de una persona: entrar, mirar la tabla, abrir un
incidente, aprobar o descartar una acción, salir. Se afirma sobre lo que se ve
en pantalla y sobre lo que quedó registrado en el sandbox.
"""

from __future__ import annotations

import json
import re

from playwright.sync_api import expect

INCIDENTES = "data/siem_incidents.json"
DECISIONES = "data/decisions.jsonl"


def _reescribir_incidentes(sandbox, cambio) -> dict:
    """Aplica `cambio(reporte)` al reporte de incidentes del sandbox."""
    ruta = sandbox / INCIDENTES
    reporte = json.loads(ruta.read_text(encoding="utf-8"))
    cambio(reporte)
    ruta.write_text(json.dumps(reporte), encoding="utf-8")
    return reporte


def _decisiones(sandbox) -> list[dict]:
    ruta = sandbox / DECISIONES
    if not ruta.exists():
        return []
    return [json.loads(linea) for linea in ruta.read_text(encoding="utf-8").splitlines() if linea]


def _abrir_primer_incidente(page):
    page.locator("table.events tbody tr").first.click()
    detalle = page.locator("#detailWrap")
    expect(detalle.locator("button.approve").first).to_be_visible()
    return detalle


# ─── Login y sesión ──────────────────────────────────────────────────────────

def test_sin_sesion_el_panel_manda_al_login(page, panel):
    page.goto(f"{panel}/")
    expect(page).to_have_url(f"{panel}/login")
    expect(page.locator("#username")).to_be_visible()


def test_contrasena_incorrecta_muestra_el_error_y_vacia_el_campo(page, panel):
    page.goto(f"{panel}/login")
    page.fill("#username", "ana")
    page.fill("#password", "no-es-la-contrasena")
    page.click("#enviar")

    expect(page.locator("#aviso")).to_have_class(re.compile(r"\berror\b"))
    expect(page.locator("#aviso")).not_to_be_empty()
    expect(page.locator("#password")).to_have_value("")
    expect(page).to_have_url(f"{panel}/login")


def test_login_correcto_muestra_usuario_rol_e_incidentes(entrar, errores_de_consola):
    page = entrar("ana")
    expect(page.locator("#sesion")).to_contain_text("ana")
    expect(page.locator("#sesion .rol")).to_have_text("analyst")
    assert page.locator("table.events tbody tr").count() >= 1
    assert errores_de_consola == []


def test_cerrar_sesion_vuelve_al_login_y_corta_el_acceso(entrar, panel):
    page = entrar("ana")
    page.click("#salir")
    expect(page).to_have_url(f"{panel}/login")
    page.goto(f"{panel}/")
    expect(page).to_have_url(f"{panel}/login")


# ─── Tabla, filtros y detalle ────────────────────────────────────────────────

def test_el_buscador_filtra_la_tabla(entrar):
    page = entrar("ana")
    filas = page.locator("table.events tbody tr")
    total = filas.count()

    page.fill("#fSearch", "203.0.113.250-no-existe")
    expect(page.locator("#eventsTableWrap .empty")).to_be_visible()

    page.fill("#fSearch", "")
    expect(filas).to_have_count(total)


def test_clic_en_una_fila_abre_el_detalle_con_sus_acciones(entrar):
    page = entrar("ana")
    fila = page.locator("table.events tbody tr").first
    incidente = fila.get_attribute("data-incidente")
    fila.click()

    detalle = page.locator("#detailWrap")
    expect(detalle).to_contain_text(incidente)
    expect(detalle.locator(".action").first).to_be_visible()
    expect(detalle.locator(".analisis-fuente")).to_contain_text("determinístico")


def test_una_fila_se_abre_con_el_teclado(entrar):
    """RNF-USA-08: Tab hasta la fila y Enter, sin mouse."""
    page = entrar("ana")
    fila = page.locator("table.events tbody tr").first
    fila.focus()
    page.keyboard.press("Enter")
    expect(page.locator("#detailWrap .action").first).to_be_visible()


# ─── Decisiones: siempre pasan por el cuadro de confirmación ────────────────

def test_cancelar_la_confirmacion_no_registra_nada(entrar, sandbox_con_incidentes):
    page = entrar("ana")
    detalle = _abrir_primer_incidente(page)

    detalle.locator("button.approve").first.click()
    dialogo = page.locator("#confirmacion")
    expect(dialogo).to_be_visible()
    expect(dialogo).to_contain_text("La acción")
    dialogo.get_by_role("button", name="Cancelar").click()

    expect(dialogo).to_be_hidden()
    expect(detalle.locator(".action .state").first).to_have_text("pendiente")
    assert _decisiones(sandbox_con_incidentes) == []


def test_aprobar_con_confirmacion_queda_en_pantalla_y_en_el_registro(entrar, sandbox_con_incidentes):
    page = entrar("ana")
    detalle = _abrir_primer_incidente(page)
    boton = detalle.locator("button.approve").first
    action_id = boton.get_attribute("data-action-id")

    boton.click()
    page.click("#confirmacionSi")

    expect(page.locator(f'#detailWrap button.approve[data-action-id="{action_id}"]')
           ).to_have_class(re.compile(r"\bon\b"))
    expect(page.locator("#detailWrap .action .state").first).to_have_text("✔ aprobada")
    registro = _decisiones(sandbox_con_incidentes)
    assert [(d["action_id"], d["decision"], d["analyst"]) for d in registro] == [
        (action_id, "approved", "ana")]


def test_descartar_pide_motivo_y_lo_guarda(entrar, sandbox_con_incidentes):
    page = entrar("ana")
    detalle = _abrir_primer_incidente(page)
    detalle.locator("button.dismiss").first.click()

    motivo = detalle.locator("textarea, input[type=text]").first
    expect(motivo).to_be_visible()
    motivo.fill("Escáner autorizado de la auditoría trimestral")
    detalle.locator('[data-accion="confirmar-descarte"]').click()
    page.click("#confirmacionSi")

    expect(detalle.locator(".action .state").first).to_have_text("✘ descartada")
    (decision,) = _decisiones(sandbox_con_incidentes)
    assert decision["decision"] == "dismissed"
    assert decision["note"] == "Escáner autorizado de la auditoría trimestral"


# ─── Roles ───────────────────────────────────────────────────────────────────

def test_un_viewer_no_ve_los_botones_de_decision(entrar):
    page = entrar("beto")
    expect(page.locator("#sesion .rol")).to_have_text("viewer")
    expect(page.locator("body")).to_have_class(re.compile(r"\bsolo-lectura\b"))
    page.locator("table.events tbody tr").first.click()
    expect(page.locator("#detailWrap .action").first).to_be_visible()
    expect(page.locator("#detailWrap button.approve").first).to_be_hidden()


# ─── Lo que escribió el Agente 2 ─────────────────────────────────────────────

def test_un_analisis_de_gemma_se_identifica_en_pantalla(page, panel, entrar, sandbox_con_incidentes):
    def gemma(reporte):
        reporte["analyst_mode"] = "gemma"
        inc = reporte["incidents"][0]
        inc["analysis"] = an = inc.get("analysis") or {}
        an.update(_source="gemma", _modelo="gemma3:4b",
                  explicacion="Gemma explicó este incidente. Segunda oración.",
                  puntos_de_investigacion=["¿La IP escaneó otros hosts?"])

    reporte = _reescribir_incidentes(sandbox_con_incidentes, gemma)
    page = entrar("ana")

    expect(page.locator("#modeBadge")).to_have_text(re.compile(r"IA \(Gemma local\)"))
    page.locator(f'tr[data-incidente="{reporte["incidents"][0]["incident_id"]}"]').click()
    fuente = page.locator("#detailWrap .analisis-fuente")
    expect(fuente).to_have_class(re.compile(r"\bes-ia\b"))
    expect(fuente).to_contain_text("Gemma local · gemma3:4b")
    expect(page.locator("#detailWrap")).to_contain_text("¿La IP escaneó otros hosts?")


def test_un_texto_hostil_del_llm_se_muestra_como_texto_y_no_se_ejecuta(
        page, panel, entrar, sandbox_con_incidentes, errores_de_consola):
    """S-02 visto desde el navegador: el HTML que traiga el análisis no se interpreta."""
    payload = '<img src=x onerror="window.__xss = 1">'

    def hostil(reporte):
        inc = reporte["incidents"][0]
        inc["analysis"] = {**(inc.get("analysis") or {}), "explicacion": payload}

    reporte = _reescribir_incidentes(sandbox_con_incidentes, hostil)
    page = entrar("ana")
    page.locator(f'tr[data-incidente="{reporte["incidents"][0]["incident_id"]}"]').click()

    expect(page.locator("#detailWrap")).to_contain_text(payload)
    assert page.locator("#detailWrap img[src=x]").count() == 0
    assert page.evaluate("window.__xss") is None
