"""Suite 8: memoria del agente (P8 y P10). Casos CP-UI-40 a CP-UI-47.

Cada prueba usa textos y títulos únicos (sufijo aleatorio) para encontrar lo que ella misma creó.
"""

from __future__ import annotations

import re
import uuid

from playwright.sync_api import expect

from tests.interfaz.ayudas_malla import abrir_desplegable, confirmar, leccion, proponer_leccion

BOTON_LECCION = "#formLeccion button[type=submit]"


def _unico(prefijo: str) -> str:
    return f"{prefijo} {uuid.uuid4().hex[:8]}"


def _registrar_posts(page, ruta: str) -> list[str]:
    posts: list[str] = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and ruta in r.url else None)
    return posts


def _subir_documento(page, titulo: str, tamano: int, nombre: str = "documento.txt") -> None:
    abrir_desplegable(page, "Cargar un documento")
    page.locator("#docTitulo").fill(titulo)
    contenido = (b"Parrafo de prueba del analista.\n\n" * (tamano // 33 + 1))[:tamano]
    page.locator("#docArchivo").set_input_files(
        files=[{"name": nombre, "mimeType": "text/plain", "buffer": contenido}])
    page.get_by_role("button", name="Cargar documento").click()


def test_cp_ui_40_proponer_una_leccion_valida(analista):
    # CP-UI-40: una lección válida muestra el aviso de confirmación y aparece en «Propuestas para revisar».
    page = analista
    texto = _unico("CP-UI-40 el escáner interno es esperable")
    proponer_leccion(page, texto)
    expect(page.locator("#toast")).to_contain_text("falta que un analista la apruebe")
    expect(leccion(page, texto)).to_have_class(re.compile(r"leccion-propuesta"))
    expect(page.locator("#memoriaLecciones")).to_contain_text("Propuestas para revisar")


def test_cp_ui_41_leccion_vacia_no_se_envia(analista):
    # CP-UI-41: con la lección vacía el formulario no se envía (campo requerido, ninguna llamada a la API).
    page = analista
    posts = _registrar_posts(page, "/api/v1/memoria/lecciones")
    abrir_desplegable(page, "Enseñarle algo al agente")
    page.get_by_role("button", name="Proponer lección").click()
    assert page.locator("#leccionTexto").evaluate("e => e.validity.valueMissing")
    expect(page.locator("#toast")).not_to_have_class(re.compile(r"visible"))
    assert posts == []


def test_cp_ui_42_leccion_de_401_caracteres_se_recorta_a_400(analista):
    # CP-UI-42 (valor límite 400/401): al tipear 401 caracteres el campo conserva solo 400.
    page = analista
    abrir_desplegable(page, "Enseñarle algo al agente")
    campo = page.locator("#leccionTexto")
    campo.press_sequentially("a" * 401)
    expect(campo).to_have_value("a" * 400)


def test_cp_ui_43_aprobar_una_leccion_con_confirmacion(analista):
    # CP-UI-43: aprobar una lección pide confirmación y la mueve a «Lo que ya aprendió».
    page = analista
    texto = _unico("CP-UI-43 lección para aprobar")
    proponer_leccion(page, texto)
    leccion(page, texto).get_by_role("button", name="Aprobar").click()
    expect(page.locator("#confirmacionTitulo")).to_have_text("Vas a aprobar esta lección")
    confirmar(page)
    expect(page.locator("#toast")).to_contain_text("✔ Lección aprobada")
    expect(leccion(page, texto)).to_have_class(re.compile(r"leccion-aprobada"))
    expect(leccion(page, texto).get_by_role("button", name="Aprobar")).to_have_count(0)


def test_cp_ui_44_rechazar_una_leccion(analista):
    # CP-UI-44: rechazar una lección la quita de «Propuestas» y no la agrega a las aprendidas.
    page = analista
    texto = _unico("CP-UI-44 lección para rechazar")
    proponer_leccion(page, texto)
    leccion(page, texto).get_by_role("button", name="Rechazar").click()
    expect(page.locator("#confirmacionTitulo")).to_have_text("Vas a rechazar esta lección")
    confirmar(page)
    expect(page.locator("#toast")).to_contain_text("✘ Lección rechazada")
    expect(leccion(page, texto)).to_have_count(0)


def test_cp_ui_45_cargar_un_documento_de_2_kb(analista):
    # CP-UI-45: un título válido y un archivo de texto de 2 KB muestran el aviso y el documento aparece en la lista.
    page = analista
    titulo = _unico("CP-UI-45 inventario de red")
    _subir_documento(page, titulo, 2 * 1024)
    expect(page.locator("#toast")).to_contain_text("Documento cargado")
    expect(page.locator("#memoriaDocumentos .memoria-docs li").filter(has_text=titulo)).to_be_visible()


def test_cp_ui_46_archivo_de_33_kb_se_rechaza(analista):
    # CP-UI-46 (valor límite 32 KB): un archivo de 33 KB muestra «El archivo supera los 32 KB.» y no se carga.
    page = analista
    titulo = _unico("CP-UI-46 archivo grande")
    posts = _registrar_posts(page, "/api/v1/memoria/documentos")
    _subir_documento(page, titulo, 33 * 1024)
    expect(page.locator("#toast")).to_have_text("El archivo supera los 32 KB.")
    expect(page.locator("#memoriaDocumentos li").filter(has_text=titulo)).to_have_count(0)
    assert posts == []


def test_cp_ui_47_titulo_vacio_no_envia_el_documento(analista):
    # CP-UI-47: con el título vacío y un archivo válido el formulario no se envía.
    page = analista
    posts = _registrar_posts(page, "/api/v1/memoria/documentos")
    abrir_desplegable(page, "Cargar un documento")
    page.locator("#docArchivo").set_input_files(
        files=[{"name": "valido.txt", "mimeType": "text/plain", "buffer": b"contenido valido"}])
    page.get_by_role("button", name="Cargar documento").click()
    assert page.locator("#docTitulo").evaluate("e => e.validity.valueMissing")
    expect(page.locator("#toast")).not_to_have_class(re.compile(r"visible"))
    assert posts == []
