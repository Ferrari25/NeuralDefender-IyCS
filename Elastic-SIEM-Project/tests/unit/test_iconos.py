"""Los iconos de la interfaz son SVG monocromos, no emoji (tarea **G3**).

Un emoji se dibuja como un **mapa de bits multicolor** que aporta cada sistema
operativo: 🛰️ no se parece en Windows, macOS y Linux, su tamaño y línea base no se
controlan, y —lo que más pesa acá— **no hereda el color del texto**.

En este panel el color *significa* algo: severidad, estado del análisis, decisión.
Un glifo que trae su propia paleta compite con esa información en lugar de
acompañarla. El 🟥 del panel de eventos activos ni siquiera era un icono: era un
cuadrado de color.

El sprite vive embebido en `templates/_iconos.html` —`<use>` apuntando a un SVG
externo no funciona en todos los navegadores— y los símbolos usan `currentColor`,
así que toman el color de donde estén y se escalan con `font-size`.

Se dejaron como texto los glifos **tipográficos** (`→ ▸ ▾ ✕ ✔ ✘ ↻`): ya son
monocromos y ya heredan el color. Pasarlos a SVG sería más marcado sin ninguna
ganancia.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent.parent
PLANTILLAS = RAIZ / "templates"
SPRITE = PLANTILLAS / "_iconos.html"
APP_JS = RAIZ / "static" / "app.js"
ICONOS_CSS = RAIZ / "static" / "iconos.css"

FUENTE_SPRITE = SPRITE.read_text(encoding="utf-8")
FUENTE_JS = APP_JS.read_text(encoding="utf-8")

SIMBOLOS = set(re.findall(r'<symbol id="([\w-]+)"', FUENTE_SPRITE))

# Glifos que se dejan como texto a propósito: monocromos y heredan el color.
TIPOGRAFICOS = set("─→▸▾✕✔✘↻←↑↓·—")

# Emoji de color: los bloques donde viven los pictogramas con paleta propia.
EMOJI_DE_COLOR = re.compile(
    "[\U0001F300-\U0001FAFF\U0001F000-\U0001F2FF☀-➿⬀-⯿]")


def _consumidores() -> list[Path]:
    return [*PLANTILLAS.glob("*.html"), APP_JS, RAIZ / "static" / "login.js"]


def sin_comentarios(texto: str) -> str:
    """Quita comentarios de Jinja, HTML y JavaScript.

    Un comentario no es interfaz: el sprite explica en el suyo que `i-actividad`
    reemplaza al 🟥, y esa frase no es un emoji dibujándose en pantalla. Los `//`
    se quitan solo cuando abren la línea, para no romper un `https://`.
    """
    texto = re.sub(r"\{#.*?#\}", "", texto, flags=re.S)
    texto = re.sub(r"<!--.*?-->", "", texto, flags=re.S)
    texto = re.sub(r"/\*.*?\*/", "", texto, flags=re.S)
    return "\n".join(linea for linea in texto.splitlines()
                  if not linea.lstrip().startswith("//"))


# ─── El sprite y quienes lo usan ─────────────────────────────────────────────

def test_hay_simbolos_en_el_sprite():
    """Blindaje: si el sprite cambia de forma, el resto pasaría por vacío."""
    assert len(SIMBOLOS) >= 10, f"solo encontré {len(SIMBOLOS)} símbolos"


def test_el_sprite_es_xml_bien_formado():
    """Un `<path>` mal cerrado no rompe la página: el navegador salta lo que no
    entiende y el icono simplemente no aparece.

    El corte empieza tras quitar los comentarios: el primer `<svg` del archivo está
    dentro del comentario de cabecera, que muestra cómo usarlo. (Lo descubrí
    parseando 0 símbolos.)
    """
    import xml.etree.ElementTree as ET

    limpio = sin_comentarios(FUENTE_SPRITE)
    svg = limpio[limpio.index("<svg"):limpio.rindex("</svg>") + 6]
    # `hidden` sin valor es HTML válido pero no XML; el sprite se sirve como HTML.
    raiz = ET.fromstring(svg.replace(" hidden ", ' hidden="hidden" '))

    NS = "{http://www.w3.org/2000/svg}"
    assert len(raiz.findall(f".//{NS}symbol")) == len(SIMBOLOS)


@pytest.mark.parametrize("simbolo", sorted(SIMBOLOS))
def test_los_path_solo_usan_comandos_svg_validos(simbolo: str):
    """Un comando inventado hace que el navegador descarte el resto del trazo."""
    bloque = re.search(rf'<symbol id="{simbolo}".*?</symbol>', FUENTE_SPRITE, re.S)
    assert bloque

    for d in re.findall(r'\sd="([^"]+)"', bloque.group(0)):
        assert re.fullmatch(r"[MmLlHhVvCcSsQqTtAaZz0-9\s.,-]+", d), (
            f"#{simbolo} tiene un comando raro en su path: {d}")


def test_cada_icono_referenciado_existe_en_el_sprite():
    """**La prueba que evita el icono invisible.**

    Un `<use href="#i-candadito">` mal escrito no falla ni avisa: el navegador
    dibuja nada y el hueco queda ahí.
    """
    faltan = {}
    for archivo in _consumidores():
        usados = set(re.findall(r'href="#([\w-]+)"', archivo.read_text(encoding="utf-8")))
        if usados - SIMBOLOS:
            faltan[archivo.name] = sorted(usados - SIMBOLOS)

    assert not faltan, f"iconos referenciados que no existen: {faltan}"


def test_no_quedan_simbolos_sin_usar():
    """Un icono que nadie dibuja es peso muerto en cada carga de página."""
    usados: set[str] = set()
    for archivo in _consumidores():
        usados |= set(re.findall(r'href="#([\w-]+)"', archivo.read_text(encoding="utf-8")))
    usados |= set(re.findall(r'"(i-[a-z]+)"', FUENTE_JS))  # los del mapa de ataques

    assert usados >= SIMBOLOS, f"símbolos definidos y sin usar: {sorted(SIMBOLOS - usados)}"


@pytest.mark.parametrize("simbolo", sorted(SIMBOLOS))
def test_cada_simbolo_respeta_el_patron_que_valida_el_codigo(simbolo: str):
    """`ico()` rechaza lo que no case con `^i-[a-z]+$`. Un símbolo con otro nombre
    no se podría dibujar desde JavaScript."""
    assert re.fullmatch(r"i-[a-z]+", simbolo), f"«{simbolo}» no pasaría la validación"


@pytest.mark.parametrize("simbolo", sorted(SIMBOLOS))
def test_cada_simbolo_declara_su_viewbox(simbolo: str):
    """Sin `viewBox`, el símbolo no escala: se dibuja a su tamaño intrínseco y se
    ignora el `width`/`height` en `em` que le da `.ico`."""
    m = re.search(rf'<symbol id="{simbolo}"([^>]*)>', FUENTE_SPRITE)
    assert m and "viewBox=" in m.group(1), f"#{simbolo} no declara viewBox"


def test_las_dos_pantallas_incluyen_el_sprite_y_su_hoja():
    """`<use>` solo resuelve contra un símbolo presente en el MISMO documento."""
    for nombre in ("index.html", "login.html"):
        texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
        assert "_iconos.html" in texto, f"{nombre} no incluye el sprite"
        assert "iconos.css" in texto, f"{nombre} no enlaza iconos.css"


# ─── No quedan emoji de color ────────────────────────────────────────────────

@pytest.mark.parametrize("archivo", _consumidores(), ids=lambda p: p.name)
def test_no_quedan_emoji_de_color(archivo: Path):
    encontrados = {e for e in EMOJI_DE_COLOR.findall(sin_comentarios(
                       archivo.read_text(encoding="utf-8")))
                   if e not in TIPOGRAFICOS}

    assert not encontrados, (
        f"{archivo.name} todavía usa emoji: {sorted(encontrados)}. Se dibujan con la "
        f"paleta del sistema operativo y no heredan el color del texto.")


# ─── El estilo común ─────────────────────────────────────────────────────────

def test_los_iconos_heredan_el_color_del_texto():
    """Es la razón de haberlos pasado a SVG: si se fija un color, vuelve el
    problema del emoji con paleta propia."""
    css = ICONOS_CSS.read_text(encoding="utf-8")
    regla = re.search(r"\.ico\s*\{([^}]*)\}", css)
    assert regla, "no encontré la regla .ico"

    assert "currentColor" in regla.group(1)
    assert not re.search(r"stroke:\s*#", regla.group(1)), "el trazo tiene un color fijo"


def test_el_punto_de_estado_hereda_el_color():
    """Era 🟢 / 🟡: el verde y el ámbar los ponía el sistema operativo, no el
    significado. Ahora lo pinta la clase del modo."""
    regla = re.search(r"\.punto\s*\{([^}]*)\}", ICONOS_CSS.read_text(encoding="utf-8"))
    assert regla and "currentColor" in regla.group(1)


def test_los_iconos_no_se_anuncian_al_lector_de_pantalla():
    """Cada icono va al lado de su texto. Sin `aria-hidden`, un lector de pantalla
    anunciaría el nombre del SVG además de la etiqueta: se oye todo dos veces."""
    usos = re.findall(r"<svg class=\"ico\"([^>]*)>", FUENTE_JS)
    assert usos, "no encontré iconos generados desde JavaScript"
    for atributos in usos:
        assert "aria-hidden" in atributos, "un icono de JavaScript no está oculto al lector"

    assert 'hidden aria-hidden="true"' in FUENTE_SPRITE, (
        "el sprite tiene que estar oculto: si no, se dibuja al principio de la página")


def test_el_javascript_no_genera_declaraciones_css_en_linea():
    """Misma regla que para las plantillas: un `style=` construido en JavaScript no lo
    ve ninguna herramienta. Fue lo que quedaba del colapso de evidencia
    (`style="display:none"`), hoy resuelto con la clase `.oculto`.

    **La excepción, y por qué es una excepción y no un agujero:** se permite un
    `style="--dato-x: valor"`. Una proporción calculada —el ancho de cada segmento de
    la barra de severidad— es un **dato**, no un estilo: depende de cuántos incidentes
    hay y no puede vivir en una hoja estática. La propiedad personalizada la lleva con
    nombre, y la hoja decide qué hacer con ella. Lo que sigue prohibido es una
    declaración CSS: `display`, `color`, `width` y compañía.
    """
    infractores = []
    for m in re.finditer(r'style="([^"]*)"', FUENTE_JS):
        contenido = m.group(1).strip()
        # Solo propiedades personalizadas con el prefijo de dato, una o varias.
        if not re.fullmatch(r"(--dato-[\w-]+:[^;\"]*;?\s*)+", contenido):
            infractores.append(contenido)

    assert not infractores, (
        f"app.js construye declaraciones CSS en línea: {infractores}. Si es un dato "
        f"calculado, va como `--dato-…`; si es estilo, va en la hoja.")


# ─── Cruce con el clasificador ───────────────────────────────────────────────

def _tipos_de_ataque_del_clasificador() -> set[str]:
    """Los tipos que `_classification` sabe nombrar, leídos de su propia tabla."""
    fuente = (RAIZ / "src" / "classifier.py").read_text(encoding="utf-8")
    bloque = fuente[fuente.index("    table = {"):]
    bloque = bloque[:bloque.index("\n    }")]
    return set(re.findall(r'^\s{8}"(\w+)":', bloque, re.M))


def test_cada_tipo_de_ataque_tiene_su_icono():
    """**El cruce entre capas.**

    `RNF-USA-07` pide un icono estable por tipo de ataque: el analista lo reconoce
    de un vistazo antes de leer la etiqueta. Si alguien agrega un detector al
    clasificador sin agregar su icono, el incidente aparece con el de advertencia
    genérico y esa estabilidad se pierde en silencio.
    """
    tipos = _tipos_de_ataque_del_clasificador()
    assert len(tipos) >= 4, f"no pude leer la tabla del clasificador: {tipos}"

    con_icono = set(re.findall(r'\["(\w+)", "i-[a-z]+"\]', FUENTE_JS))
    assert tipos <= con_icono, f"tipos de ataque sin icono propio: {sorted(tipos - con_icono)}"


def test_hay_un_icono_de_reserva_para_un_tipo_desconocido():
    """Y si aparece uno que nadie previó, que se vea algo."""
    assert 'ico(ATTACK_ICONS.get(t) || "i-advertencia")' in FUENTE_JS


# ─── `ico()` ejecutado de verdad, en Node ────────────────────────────────────

@pytest.fixture(scope="module")
def js():
    """Ejecuta el `ico()` real de `static/app.js`, no una reimplementación.

    El bloque va de `ESC_MAP` a `hhmmss`, el mismo que usa
    `test_s02_xss_dashboard.py`: incluye `FragmentoSeguro`, de la que `ico` depende.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node no está disponible en este entorno")

    fuente = FUENTE_JS[FUENTE_JS.index("const ESC_MAP"):FUENTE_JS.index("const hhmmss")]

    def _evaluar(expresion: str, entrada=None):
        script = (f"{fuente}\n"
                  "const entrada = JSON.parse(process.argv[1]);\n"
                  f"try {{ process.stdout.write(String({expresion})); }}\n"
                  "catch (e) { process.stdout.write('ERROR:' + e.message); }\n")
        return subprocess.run([node, "-e", script, json.dumps(entrada)],
                              capture_output=True, text=True, timeout=30,
                              check=True).stdout

    return _evaluar


def test_ico_produce_el_marcado_esperado(js):
    salida = js('ico("i-candado")')
    assert salida == '<svg class="ico" aria-hidden="true"><use href="#i-candado"></use></svg>'


def test_ico_devuelve_un_fragmento_seguro_y_no_se_escapa(js):
    """Si devolviera un string, el tag `html` lo escaparía y en pantalla se leería
    el código del SVG en lugar del dibujo."""
    assert js('html`${ico("i-lupa")}`').startswith("<svg")


@pytest.mark.parametrize("malo", ["i-Candado", "../x", "i-", "i-candado onload=x",
                                  "<script>", "i-candado#", ""])
def test_ico_rechaza_un_identificador_que_no_sea_de_icono(js, malo: str):
    """El identificador sale siempre de un mapa cerrado de `app.js`, así que hoy no
    puede llegar basura. La validación deja escrito que eso es una condición, no una
    casualidad — y si alguien mañana lo alimenta con datos del servidor, revienta en
    vez de inyectar marcado."""
    assert js("ico(entrada)", malo).startswith("ERROR:")
