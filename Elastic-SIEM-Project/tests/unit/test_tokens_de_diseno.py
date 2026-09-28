"""La interfaz usa tokens, no valores sueltos (tarea **G2**).

Antes de esto, `static/app.css` tenía **10 tamaños de fuente** para 53 usos (12.5px y
13.5px entre ellos), **7 radios** y **29 combinaciones de padding** para 39 usos: casi
cada regla inventaba la suya. Y `templates/login.html` seguía con 37 líneas de CSS
embebido y su **propio `:root`** — el refactor R-05 extrajo el CSS del panel y dejó el
login atrás.

Eso ya había producido una colisión real: `--ok` valía `#238636` en el panel y
`#3fb950` en el login. Un nombre con dos colores no es un token.

El problema de fondo no era la cantidad de valores: era que **la intención no estaba
escrita en ningún lado**. Nadie podía saber si 13.5px era un paso de la escala o el
apuro de alguien, así que la regla siguiente inventaba el valor 11.º.

Estas pruebas cierran el conjunto. No opinan sobre estética: verifican una propiedad
estructural — que la interfaz tenga un vocabulario finito, declarado en un solo lugar.
"""

from __future__ import annotations

import re

import pytest

from tests.unit.hojas_de_estilo import (
    ALIAS,
    DEFINIDOS,
    HOJAS_QUE_CONSUMEN,
    MEDIDAS,
    TOKENS_CSS,
    cuerpos,
    declaraciones,
    medida,
    sin_comentarios,
    texto_de_la_raiz,
)

# Propiedades cuyo valor tiene que venir de un token. Quedan afuera a propósito
# `border`, `line-height`, `min-width`, `max-width` y `top/left`: son estructura o
# tipografía relativa, no el ritmo del diseño.
PROPIEDADES = ("font-size", "border-radius", "padding", "margin", "gap",
               "padding-top", "padding-bottom", "padding-left", "padding-right",
               "margin-top", "margin-bottom", "margin-left", "margin-right")


# ─── Un solo lugar declara ───────────────────────────────────────────────────

def test_solo_tokens_css_declara_la_paleta():
    """**La prueba que evita que el login vuelva a tener su propia paleta.**

    Dos `:root` es cómo `--ok` terminó significando dos colores distintos.
    """
    culpables = [h.name for h, cuerpo in cuerpos() if ":root" in cuerpo]
    assert not culpables, (
        f"{culpables} declara(n) un :root propio. Los tokens van en tokens.css.")


def test_ninguna_plantilla_trae_css_embebido():
    """`login.html` tenía 37 líneas en un `<style>`: sin caché, sin análisis
    estático y sin los tokens compartidos."""
    from tests.unit.hojas_de_estilo import ESTATICOS

    plantillas = (ESTATICOS.parent / "templates")
    for plantilla in plantillas.glob("*.html"):
        texto = plantilla.read_text(encoding="utf-8")
        assert "<style" not in texto, f"{plantilla.name} trae un <style> embebido"
        assert 'style="' not in texto, f"{plantilla.name} trae un style= en línea"


def test_las_dos_pantallas_enlazan_los_tokens():
    from tests.unit.hojas_de_estilo import ESTATICOS

    for nombre, hoja in (("index.html", "app.css"), ("login.html", "login.css")):
        texto = (ESTATICOS.parent / "templates" / nombre).read_text(encoding="utf-8")
        assert "tokens.css" in texto, f"{nombre} no enlaza tokens.css"
        assert hoja in texto, f"{nombre} no enlaza {hoja}"
        assert texto.index("tokens.css") < texto.index(hoja), (
            f"{nombre} carga {hoja} antes que los tokens")


# ─── El conjunto está cerrado ────────────────────────────────────────────────

@pytest.mark.parametrize("hoja", HOJAS_QUE_CONSUMEN, ids=lambda h: h.name)
def test_ninguna_propiedad_de_ritmo_usa_un_valor_en_px_suelto(hoja):
    """**La prueba que evita el valor 11.º.**

    Cualquier `font-size`, `border-radius`, `padding`, `margin` o `gap` con un px
    escrito a mano queda señalado, con su línea.
    """
    cuerpo = sin_comentarios(hoja.read_text(encoding="utf-8"))
    sueltos = [(ln, p, v) for ln, p, v in declaraciones(cuerpo, PROPIEDADES)
               if re.search(r"\d+(\.\d+)?px", v)]

    assert not sueltos, f"valores en px sin token en {hoja.name}:\n" + "\n".join(
        f"  {hoja.name}:{ln}  {p}: {v}" for ln, p, v in sueltos)


def test_todos_los_tokens_usados_existen():
    """Un `var(--sp-9)` que nadie definió no falla ruidosamente: el navegador ignora
    la declaración y el elemento queda sin espaciado.

    Se exceptúan las propiedades `--dato-*`: no son tokens de diseño sino datos que
    el JavaScript pone en el elemento (la proporción de cada segmento de la barra de
    severidad). Que existan se verifica aparte, contra el JavaScript.
    """
    for hoja, cuerpo in cuerpos():
        usados = {t for t in re.findall(r"var\(--([\w-]+)\)", cuerpo)
                  if not t.startswith("dato-")}
        assert usados <= DEFINIDOS, (
            f"{hoja.name} usa tokens que no existen: {usados - DEFINIDOS}")


def test_cada_dato_que_consume_el_css_lo_define_el_javascript():
    """Lo contrario de la prueba anterior, para el otro tipo de propiedad.

    Un `var(--dato-n)` que nadie asigna no falla: el navegador descarta la
    declaración y el segmento queda sin medida. La convención `--dato-*` existe
    justamente para poder verificarlo.
    """
    from tests.unit.hojas_de_estilo import ESTATICOS

    js = "".join(f.read_text(encoding="utf-8") for f in ESTATICOS.glob("*.js"))
    for _, cuerpo in cuerpos():
        for dato in set(re.findall(r"var\(--(dato-[\w-]+)\)", cuerpo)):
            assert f"--{dato}:" in js, (
                f"el CSS consume --{dato} y ningún JavaScript lo define")


def test_no_quedan_tokens_definidos_sin_usar():
    """Un token que nadie usa es una decisión abandonada que confunde al que lee.

    Se mira el conjunto de las dos hojas: `--panel3` lo usa solo el panel y
    `--err-fondo` solo el login, y las dos cosas están bien.
    """
    usados = set(ALIAS)  # un alias cuenta como usado por su propia definición
    for _, cuerpo in cuerpos():
        usados |= set(re.findall(r"var\(--([\w-]+)\)", cuerpo))

    assert usados >= DEFINIDOS, f"tokens definidos y sin usar: {sorted(DEFINIDOS - usados)}"


# ─── La escala de espaciado es una grilla ────────────────────────────────────

def test_el_espaciado_es_una_grilla_de_2px():
    """El archivo ya seguía casi entero una grilla de 2px; tenía 1, 3, 5, 7 y 9px
    sueltos en 14 lugares. Un impar nuevo rompe el ritmo sin que se note al
    escribirlo."""
    impares = {n: v for n, v in MEDIDAS.items()
               if n.startswith("sp-") and float(v.removesuffix("px")) % 2}

    assert not impares, f"espaciado fuera de la grilla de 2px: {impares}"


def test_cada_token_de_espaciado_se_llama_por_su_valor():
    """`--sp-10: 10px`. Si el nombre y el valor se separan, la hoja deja de leerse."""
    for nombre, valor in MEDIDAS.items():
        if nombre.startswith("sp-"):
            assert nombre == f"sp-{valor.removesuffix('px')}", (
                f"--{nombre} vale {valor}: el nombre miente")


def test_la_escala_tipografica_no_se_desborda():
    """Nueve pasos alcanzan para dos pantallas. Si hacen falta más, probablemente
    sobra uno de los que ya están."""
    fuentes = [n for n in MEDIDAS if n.startswith("fs-")]
    assert len(fuentes) <= 9, f"{len(fuentes)} tamaños de fuente: {sorted(fuentes)}"


def test_los_radios_tienen_una_jerarquia_de_tamaño():
    """xs < sm < md < lg, y la píldora aparte. Si se cruzan, un contenedor chico
    queda más redondeado que el grande y el panel se ve desprolijo."""
    def px(n):
        return float(MEDIDAS[n].removesuffix("px"))

    assert px("r-xs") < px("r-sm") < px("r-md") < px("r-lg"), "la jerarquía se cruzó"
    assert px("r-pill") > px("r-lg"), "la píldora tiene que ser la más redondeada"


# ─── El monoespaciado y su medio píxel ───────────────────────────────────────

def test_el_monoespaciado_es_medio_pixel_menor_que_el_cuerpo():
    """**El único valor no entero, y es a propósito.**

    Una tipografía monoespaciada se ve más grande que una proporcional al mismo
    tamaño. `--fs-mono: 12.5px` se lee como `--fs-md: 13px` al lado. Redondearlo a 13
    haría que las IP y los comandos se vieran más grandes que el texto que los rodea.
    """
    mono = float(MEDIDAS["fs-mono"].removesuffix("px"))
    md = float(MEDIDAS["fs-md"].removesuffix("px"))

    assert mono == md - 0.5, (
        "si esto cambia, revisar que las IP y los comandos no se vean más grandes "
        "que el texto de al lado")


def test_solo_el_monoespaciado_usa_medio_pixel():
    fraccionarios = {n for n, v in MEDIDAS.items() if float(v.removesuffix("px")) % 1}
    assert fraccionarios == {"fs-mono"}, (
        f"medios píxeles inesperados: {fraccionarios - {'fs-mono'}}. Renderizan "
        f"distinto en cada navegador; el único justificado es el monoespaciado.")


# ─── Los tokens están documentados ───────────────────────────────────────────

def test_cada_grupo_de_tokens_explica_para_que_es():
    """Un token sin comentario es un valor suelto con nombre más largo: el próximo
    que lea la hoja no sabrá cuál le toca y agregará el siguiente."""
    raiz = texto_de_la_raiz()
    for grupo in ("Superficies y texto", "Severidad", "Decisión del analista",
                  "Alias semánticos", "Escala tipográfica", "Radios", "Espaciado"):
        assert grupo in raiz, f"falta el comentario de «{grupo}»"


def test_los_alias_se_escriben_como_alias_y_no_repitiendo_el_hex():
    """`--err: var(--crit)` en lugar de `--err: #f85149`. Si se repite el hex, nada
    impide que uno de los dos cambie y el otro no."""
    assert ALIAS, "no hay ningún alias declarado; ¿se reemplazaron por hex?"
    for alias, destino in ALIAS.items():
        assert destino in DEFINIDOS, f"--{alias} apunta a --{destino}, que no existe"


def test_tokens_css_no_tiene_reglas_ademas_del_root():
    """Es un archivo de declaraciones. Si empieza a traer estilos, las dos pantallas
    se acoplan por la puerta de atrás."""
    cuerpo = sin_comentarios(TOKENS_CSS.read_text(encoding="utf-8"))
    selectores = re.findall(r"(?m)^([^{}\n]+)\{", cuerpo)

    assert [s.strip() for s in selectores] == [":root"], (
        f"tokens.css define además: {[s.strip() for s in selectores[1:]]}")


# ─── Resolución ──────────────────────────────────────────────────────────────

def test_las_medidas_se_resuelven_a_pixeles():
    """Blindaje del andamiaje: si `medida()` deja de resolver, las pruebas de arriba
    pasarían por no encontrar nada."""
    assert medida("var(--sp-10) var(--sp-14)") == "10px 14px"
    assert medida("var(--fs-mono)") == "12.5px"
