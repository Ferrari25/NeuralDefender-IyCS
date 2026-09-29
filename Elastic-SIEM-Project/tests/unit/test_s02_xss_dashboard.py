"""Regresión del hallazgo **S-02** — XSS almacenado en el panel del analista.

Antes de la corrección, `esc()` escapaba `& < > "` pero **no la comilla simple**,
y los valores se interpolaban dentro de atributos `onclick="...('${...}')"`. Un
`incident_id` derivado de un `source_ip` hostil cerraba el string JavaScript:

    INC-PHISH-1');alert(document.cookie);//-c5d1fbab
    onclick="decide(event,'INC-PHISH-1');alert(document.cookie);//-…','…')"

…y ejecutaba código arbitrario en la sesión del analista, entregado por el propio
sistema de seguridad.

La corrección tiene dos capas:

1. **Estructural** — se eliminaron todos los handlers inline. Los datos viajan en
   atributos `data-*` y se leen con `dataset`, que devuelve texto plano. Ya no
   existe un contexto JavaScript donde interpolar un dato de log.
2. **Escapado** — `esc()` cubre también `' \\` = /`.

Las dos se prueban acá. La segunda se prueba **ejecutando el `esc()` real de la
plantilla en Node**, no una copia: una reimplementación en Python probaría el
test, no el código que se despliega.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PLANTILLA = PROJECT_ROOT / "templates" / "index.html"
APP_JS = PROJECT_ROOT / "static" / "app.js"

# Payloads de XSS pensados para romper cada contexto de interpolación.
PAYLOADS_XSS = [
    "1');alert(document.cookie);//",
    "');alert(1);//",
    "\" onmouseover=\"alert(1)",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "`+alert(1)+`",
    "</textarea><script>alert(1)</script>",
    "'-alert(1)-'",
    "\\'; alert(1); //",
]


@pytest.fixture(scope="module")
def html() -> str:
    """La plantilla: hoy solo marcado, sin <script> ni <style> (refactor R-05)."""
    return PLANTILLA.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def app_js() -> str:
    """El JavaScript del panel, ahora en su propio archivo y analizable."""
    return APP_JS.read_text(encoding="utf-8")


# ─── Capa 1: no queda ningún contexto JavaScript donde interpolar ────────────

def _sin_comentarios(html: str) -> str:
    """Quita los comentarios `//` del script: describen el bug corregido y
    mencionan `onclick=` literalmente."""
    return "\n".join(linea for linea in html.splitlines()
                      if not linea.strip().startswith("//"))


def test_no_quedan_handlers_inline(html):
    """Ningún atributo `on*=` en la plantilla, ni siquiera sin interpolación.

    Es la corrección de fondo: aunque `esc()` tuviera un agujero, no habría
    dónde explotarlo. La regla es absoluta a propósito — "sin handlers inline"
    se verifica de un vistazo; "sin handlers inline que interpolen datos" exige
    juzgar cada caso, y ahí es donde se cuela el próximo.
    """
    handlers = re.findall(r'\son[a-z]+\s*=\s*["\']', _sin_comentarios(html))
    assert handlers == [], f"quedaron handlers inline: {handlers}"


def test_los_datos_viajan_en_atributos_data(app_js):
    """Los handlers se reemplazaron por `data-accion` + delegación."""
    assert 'data-accion="decidir"' in app_js
    assert 'data-accion="seleccionar"' in app_js
    assert 'document.addEventListener("click", delegar)' in app_js


def test_la_delegacion_lee_dataset_no_evalua(app_js):
    """`dataset` devuelve texto plano; nunca se evalúa como código."""
    delegar = app_js.split("function delegar(")[1].split("\n}")[0]
    assert "el.dataset" in delegar
    for peligro in ("eval", "new Function", "innerHTML", "setTimeout(", "Function("):
        assert peligro not in delegar


def test_decide_ya_no_recibe_el_objeto_event_interpolado(app_js):
    """La firma vieja `decide(event, '…')` obligaba a interpolar en un onclick.

    `note` se sumó como cuarto parámetro cuando el motivo de descarte pasó de un
    `prompt()` del navegador a un campo del propio panel — sigue viajando como
    dato explícito, nunca como el `event` interpolado que esta prueba prohíbe.
    """
    assert "async function decide(incident_id, action_id, decision, note = \"\")" in app_js
    assert "decide(event," not in app_js


# ─── Capa 2: el esc() real de la plantilla, ejecutado en Node ────────────────

def _extraer_saneamiento(app_js: str) -> str:
    """Saca el bloque de saneamiento real de `static/app.js`, sin reescribirlo.

    Va desde `ESC_MAP` hasta el final de `pintar()`: incluye `esc`, la clase
    `FragmentoSeguro`, `interpolar`, el tag `html` y el asignador.
    """
    inicio = app_js.index("const ESC_MAP")
    fin = app_js.index("const hhmmss")
    return app_js[inicio:fin]


@pytest.fixture(scope="module")
def js(app_js):
    """Ejecuta el código de saneamiento REAL en Node.

    Devuelve una función que evalúa una expresión con `esc`, `html` y
    `FragmentoSeguro` en el alcance, y devuelve el resultado como texto.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node no está disponible en este entorno")

    fuente = _extraer_saneamiento(app_js)

    def _evaluar(expresion: str, entrada=None) -> str:
        script = (
            f"{fuente}\n"
            "const entrada = JSON.parse(process.argv[1]);\n"
            f"process.stdout.write(String({expresion}));\n"
        )
        salida = subprocess.run(
            [node, "-e", script, json.dumps(entrada)],
            capture_output=True, text=True, timeout=30, check=True,
        )
        return salida.stdout

    return _evaluar


@pytest.fixture(scope="module")
def esc_en_node(js):
    """`esc()` real, como función Python."""
    return lambda valor: js("esc(entrada)", valor)


def test_el_bloque_de_saneamiento_es_el_que_se_despliega(app_js):
    """Blindaje: si el bloque cambia de forma, este test avisa antes que los otros."""
    fuente = _extraer_saneamiento(app_js)
    for pieza in ("const ESC_MAP", "const esc =", "class FragmentoSeguro",
                  "function interpolar", "function html(", "function pintar("):
        assert pieza in fuente, f"falta {pieza} en el bloque de saneamiento"


@pytest.mark.parametrize("caracter,esperado", [
    ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&quot;"),
    ("'", "&#39;"), ("`", "&#96;"), ("=", "&#61;"), ("/", "&#47;"),
])
def test_esc_escapa_cada_caracter_peligroso(esc_en_node, caracter, esperado):
    assert esc_en_node(caracter) == esperado


def test_esc_escapa_la_comilla_simple(esc_en_node):
    """El carácter exacto del hallazgo: antes pasaba sin tocar."""
    assert esc_en_node("'") == "&#39;"
    assert "'" not in esc_en_node("1');alert(document.cookie);//")


@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_ningun_payload_sobrevive_a_esc(esc_en_node, payload):
    """Tras escapar, no queda ningún carácter capaz de abrir un contexto nuevo."""
    escapado = esc_en_node(payload)
    for peligroso in ("<", ">", '"', "'", "`"):
        assert peligroso not in escapado, f"{peligroso!r} sobrevivió en {escapado!r}"


def test_esc_tolera_vacios(esc_en_node):
    assert esc_en_node(None) == ""
    assert esc_en_node("") == ""


def test_esc_no_rompe_texto_normal(esc_en_node):
    """Escapar no puede arruinar la legibilidad del panel."""
    assert esc_en_node("172.18.0.3") == "172.18.0.3"
    assert esc_en_node("Failed password for testuser") == "Failed password for testuser"
    assert esc_en_node("clasificación") == "clasificación"


# ─── El vector completo, de punta a punta ────────────────────────────────────

def test_el_incident_id_hostil_ya_no_llega_al_panel(malicious_dir):
    """Cadena completa: evento hostil → clasificador → JSON que consume el panel.

    Tras S-01 el `incident_id` ya no lleva el payload (se agrupa bajo el
    sentinela). Este test cubre la unión de las dos correcciones: aunque S-01 se
    revirtiera, S-02 impediría la ejecución — y viceversa.
    """
    import classifier
    from tests.conftest import eventos_de_red

    incidentes = classifier.detect_phishing(eventos_de_red(malicious_dir))
    serializado = json.dumps(incidentes, ensure_ascii=False)

    assert "alert(document.cookie)" not in serializado
    for inc in incidentes:
        assert "'" not in inc["incident_id"]
        for accion in inc["recommended_actions"]:
            assert "'" not in accion["action_id"]


def test_el_panel_sigue_sin_ejecutar_nada(app_js, html):
    """No-autonomía del lado del cliente: se mantiene tras el refactor R-05."""
    for peligro in ("eval(", "new Function(", "execCommand", "child_process",
                    "document.write"):
        assert peligro not in app_js
        assert peligro not in html

    destinos_post = set(re.findall(r'fetch\("([^"]+)",\s*\{\s*\n?\s*method:\s*"POST"',
                                   app_js))
    assert destinos_post == {"/api/v1/decision", "/api/v1/logout"}


# ─── Capa 3: escape por construcción (refactor R-05) ────────────────────────

def test_el_tag_escapa_todo_lo_interpolado(js):
    """La diferencia con `esc()` a mano: acá olvidarse no es posible."""
    assert js("html`<td>${entrada}</td>`", "<img src=x onerror=alert(1)>") == \
        "<td>&lt;img src&#61;x onerror&#61;alert(1)&gt;</td>"


@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_ningun_payload_sobrevive_al_tag(js, payload):
    """El mismo barrido que sobre `esc()`, pero por el camino que usa el panel."""
    salida = js("html`<div class='x'>${entrada}</div>`", payload)
    cuerpo = salida.split(">", 1)[1].rsplit("<", 1)[0]
    for peligroso in ("<", ">", '"', "'", "`"):
        assert peligroso not in cuerpo, f"{peligroso!r} sobrevivió en {cuerpo!r}"


def test_un_fragmento_del_propio_tag_no_se_re_escapa(js):
    """Componer vistas tiene que seguir funcionando: si no, nadie usaría el tag."""
    assert js("html`<div>${html`<b>ok</b>`}</div>`") == "<div><b>ok</b></div>"


def test_un_string_suelto_si_se_escapa(js):
    """La distinción es el corazón del mecanismo: solo el tag produce HTML."""
    assert js("html`<div>${'<b>no</b>'}</div>`") == "<div>&lt;b&gt;no&lt;&#47;b&gt;</div>"


def test_los_arrays_se_interpolan_elemento_por_elemento(js):
    assert js("html`<ul>${[1,2].map(n => html`<li>${n}</li>`)}</ul>`") == \
        "<ul><li>1</li><li>2</li></ul>"


def test_un_array_de_strings_se_escapa(js):
    assert js("html`<p>${['<a>', '<b>']}</p>`") == "<p>&lt;a&gt;&lt;b&gt;</p>"


@pytest.mark.parametrize("vacio", ["null", "undefined", "false"])
def test_los_vacios_no_imprimen_nada(js, vacio):
    """Permite `${cond ? html`…` : ""}` sin ensuciar la salida."""
    assert js(f"html`[${{{vacio}}}]`") == "[]"


def test_pintar_rechaza_lo_que_no_venga_del_tag(js):
    """Un string suelto no se asigna al DOM: nadie garantizó que esté escapado."""
    salida = js("(() => { try { pintar({}, '<b>x</b>'); return 'NO FALLÓ'; } "
                "catch (e) { return e.constructor.name; } })()")
    assert salida == "TypeError"


def test_pintar_acepta_un_fragmento(js):
    salida = js("(() => { const n = {}; pintar(n, html`<b>${'<x>'}</b>`); "
                "return String(n.innerHTML); })()")
    assert salida == "<b>&lt;x&gt;</b>"


# ─── El refactor R-05 en sí ─────────────────────────────────────────────────

def test_la_plantilla_no_tiene_javascript_embebido(html):
    """F-03: mientras el script viviera dentro del HTML, ESLint no lo veía.

    Es la razón de ser del refactor: de los dos linters de código estático que el
    proyecto se propuso demostrar, el de JavaScript corría sobre cero archivos.
    """
    assert "<script>" not in html, "volvió a aparecer un <script> embebido"
    assert "<style>" not in html, "volvió a aparecer un <style> embebido"
    assert "url_for('static', filename='app.js')" in html
    assert "url_for('static', filename='app.css')" in html


def test_eslint_analiza_archivos_reales():
    """La configuración apunta a archivos que existen y tienen contenido."""
    estaticos = sorted((PROJECT_ROOT / "static").glob("*.js"))
    assert len(estaticos) >= 2, "ESLint no tendría nada que analizar"
    for archivo in estaticos:
        assert len(archivo.read_text(encoding="utf-8").splitlines()) > 20


def test_los_elementos_interactivos_son_alcanzables_por_teclado(app_js):
    """RNF-USA-08: antes, las filas y los desplegables eran <tr>/<span> con un
    manejador — invisibles para quien navega con teclado o lector de pantalla."""
    fila = app_js.split("function rowHtml(")[1].split("\n}")[0]
    assert 'role="button"' in fila and 'tabindex="0"' in fila
    assert "aria-label=" in fila

    evidencia = app_js.split("function renderEvidence(")[1].split("\n}")[0]
    assert "<button class=\"ev-head\"" in evidencia
    assert "aria-expanded=" in evidencia and "aria-controls=" in evidencia
