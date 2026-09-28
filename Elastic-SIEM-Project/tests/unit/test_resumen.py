"""La fila de resumen destaca lo que pide una decisión (tarea **G5**).

Había **siete recuadros** del mismo tamaño y el mismo peso:

    [ 5 ]        [ 12 ]     [ 7 ]        [ 0 ]      [ 5 ]    [ 0 ]     [ 0 ]
    Incidentes   Acciones   Pendientes   Críticos   Altos    Medios    Bajos

Nada estaba destacado, así que nada guiaba la mirada. Y como las severidades suelen
concentrarse en una o dos, **tres de los siete mostraban 0** con la misma prominencia
que el número que importa.

Ese número es uno: **cuántas acciones esperan una decisión humana**. Es lo que este
panel existe para resolver — «la IA sugiere, el humano decide». El resto es contexto.

La jerarquía se consigue degradando el contexto, no inflando el número: un dígito de
32px sería ajeno a un tablero denso de 13px. Y la distribución de severidad pasó de
cuatro recuadros a una barra apilada con su leyenda, que ocupa una fracción del
espacio y se lee de un vistazo.

**Los ceros no se esconden.** Un cero informa: «miramos y no hay críticos». Lo que
cambia es que deja de competir — la leyenda los lista igual, sin resaltar su número.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import siem_agent

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")
APP_CSS = (RAIZ / "static" / "app.css").read_text(encoding="utf-8")

RESUMEN = APP_JS[APP_JS.index("function renderSummary"):
                 APP_JS.index("function renderRecentAttacks")]

SEVERIDADES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ─── Lo que se destaca ───────────────────────────────────────────────────────

def test_el_numero_grande_es_el_que_pide_una_decision():
    """**El cambio, en una prueba.**

    Si el número principal vuelve a ser el total de incidentes, el panel deja de
    señalar lo único que requiere a una persona.
    """
    principal = re.search(r'<div class="principal[^>]*>\s*<div class="n">\$\{([\w.]+)\}</div>',
                          RESUMEN)
    assert principal, "no encontré el número principal del resumen"
    assert principal.group(1) == "pending", (
        f"el número destacado es «{principal.group(1)}» y tiene que ser el de acciones "
        f"pendientes de decisión")


def test_el_numero_principal_se_enciende_solo_si_hay_pendientes():
    """Con cero pendientes no hay nada que hacer, y el panel no debería gritarlo."""
    assert 'class="principal ${pending ? "hay-pendientes" : ""}"' in RESUMEN

    encendido = re.search(r"\.principal\.hay-pendientes \.n \{([^}]*)\}", APP_CSS)
    apagado = re.search(r"\.principal \.n \{([^}]*)\}", APP_CSS)
    assert encendido and apagado, "faltan las reglas del número principal"
    assert "var(--accent)" in encendido.group(1)
    assert "var(--muted)" in apagado.group(1), "sin pendientes el número queda atenuado"


def test_el_contexto_va_mas_chico_que_el_numero_principal():
    """La jerarquía sale de degradar el contexto, no de inflar el número."""
    principal = re.search(r"\.principal \.n \{([^}]*)\}", APP_CSS).group(1)
    secundarias = re.search(r"\.secundarias \{([^}]*)\}", APP_CSS).group(1)

    assert "var(--fs-2xl)" in principal
    assert "var(--fs-sm)" in secundarias, "el contexto no está degradado"


def test_ya_no_quedan_siete_recuadros_iguales():
    """Las reglas `.stat` eran las de los siete recuadros. Si vuelven, volvió el
    problema."""
    assert not re.search(r"(?m)^\.stat[\s.{]", APP_CSS), "reaparecieron las reglas .stat"
    assert '<div class="stat"' not in APP_JS


# ─── La barra de severidad ───────────────────────────────────────────────────

@pytest.mark.parametrize("sev", SEVERIDADES)
def test_cada_severidad_tiene_color_en_la_barra_y_en_la_leyenda(sev: str):
    assert re.search(rf"\.barra \.sev-{sev} \{{[^}}]*background:", APP_CSS), (
        f"la barra no sabe pintar {sev}")
    assert re.search(rf"\.leyenda \.sev-{sev} \{{[^}}]*color:", APP_CSS), (
        f"la leyenda no sabe pintar {sev}")


def test_las_severidades_del_resumen_son_las_que_produce_el_agente():
    """Cruce con el Agente 2: si aparece una severidad nueva, el resumen la cuenta y
    la barra la pinta. Si no, quedaría fuera del total sin que nadie lo note."""
    contadas = set(re.findall(r'\["(\w+)", 0\]', RESUMEN))
    assert contadas == siem_agent._SEV_VALIDAS, (
        f"el resumen cuenta {sorted(contadas)} y el agente puede emitir "
        f"{sorted(siem_agent._SEV_VALIDAS)}")


def test_la_barra_solo_dibuja_los_segmentos_con_conteo():
    """Un segmento de ancho cero es una astilla de un píxel que ensucia la barra."""
    assert "filter(([, n]) => n > 0)" in RESUMEN, (
        "la barra dibuja segmentos vacíos")


def test_la_proporcion_viaja_como_dato_y_no_como_estilo():
    """`--dato-n` en vez de `width:20%`: el ancho depende de cuántos incidentes hay,
    así que es dato. El prefijo lo distingue de un token de diseño y permite
    verificar, desde otra prueba, que el JavaScript lo defina de verdad."""
    assert 'style="--dato-n:${n}"' in RESUMEN
    assert "flex: var(--dato-n)" in APP_CSS, "la hoja no consume el dato"


def test_la_barra_no_se_anuncia_y_la_leyenda_si():
    """La barra es una representación visual de lo que la leyenda ya dice en texto.
    Anunciar las dos cosas sería repetir; no anunciar ninguna sería perder el dato."""
    assert '<div class="barra" aria-hidden="true">' in RESUMEN
    assert '<ul class="leyenda">' in RESUMEN
    assert "aria-hidden" not in RESUMEN[RESUMEN.index('class="leyenda"'):]


# ─── Los ceros siguen estando ────────────────────────────────────────────────

def test_la_leyenda_lista_las_cuatro_severidades_incluidas_las_de_cero():
    """**Lo que NO se hizo, y es deliberado.**

    Esconder las severidades en cero habría dejado un resumen más limpio y menos
    informativo: un cero dice «miramos y no hay críticos», que en un panel de
    seguridad no es lo mismo que no decir nada.
    """
    leyenda = RESUMEN[RESUMEN.index("const leyenda"):RESUMEN.rindex("pintar(caja")]

    assert "[...porSeveridad]" in leyenda, "la leyenda filtra severidades"
    assert ".filter(" not in leyenda, "la leyenda esconde las severidades en cero"


def test_el_cero_se_lista_pero_no_se_resalta():
    """Deja de competir sin desaparecer: su número no toma el color del texto."""
    assert 'class="${n ? "" : "cero"}"' in RESUMEN

    assert re.search(r"\.leyenda b \{[^}]*var\(--muted\)", APP_CSS), (
        "el número de la leyenda arranca atenuado")
    assert re.search(r"\.leyenda li:not\(\.cero\) b \{[^}]*var\(--text\)", APP_CSS), (
        "los conteos distintos de cero no se resaltan")


def test_el_cero_no_se_atenua_con_opacity():
    """`opacity` sobre texto ya atenuado hunde el contraste por debajo de AA, y el
    barrido de contraste no modela la opacidad: no lo detectaría."""
    for regla in re.findall(r"\.leyenda[^{]*\{([^}]*)\}", APP_CSS):
        assert "opacity" not in regla, (
            "la leyenda usa opacity: atenuar así rompe el contraste sin que se note")


# ─── El estado vacío ─────────────────────────────────────────────────────────

def test_hay_un_estado_vacio_que_dice_que_hacer():
    """Antes, sin incidentes, el resumen mostraba siete ceros: correcto y mudo."""
    assert "if (!incs.length)" in RESUMEN, "no hay estado vacío"

    vacio = RESUMEN[RESUMEN.index("if (!incs.length)"):RESUMEN.index("const totalActions")]
    assert "demo-ataque.sh" in vacio, (
        "el estado vacío no dice cómo generar un incidente")
    assert "24 horas" in vacio, (
        "el estado vacío no menciona la ventana: sin eso parece que el sistema no anda")


def test_el_estado_vacio_conserva_el_aviso_de_refresco():
    """Es el momento en que más importa saber que el panel se actualiza solo."""
    vacio = RESUMEN[RESUMEN.index("if (!incs.length)"):RESUMEN.index("const totalActions")]
    assert "${barra}" in vacio


# ─── Plural ──────────────────────────────────────────────────────────────────

def test_los_conteos_se_escriben_en_plural_correcto():
    """«1 incidentes» en la pantalla de una defensa se nota."""
    assert "n === 1 ? singular : plural_" in APP_JS, "falta la rama del singular"

    llamadas = dict(re.findall(r'plural\([\w.]+, "([^"]+)", "([^"]+)"\)', RESUMEN))
    assert llamadas, "no encontré las llamadas a plural()"
    for singular, plural_ in llamadas.items():
        assert singular != plural_, f"«{singular}» no cambia en plural"


def test_el_texto_del_numero_principal_tambien_concuerda():
    """Tres casos, no dos. Con cero pendientes, «0 acciones esperan tu decisión» bajo
    un cero grande se lee raro; conviene decir que no hay nada que hacer.

    Lo detecté renderizando el resumen en Node con un DOM simulado: leer el HTML de
    los cuatro casos mostró el rótulo que en la lectura del código pasaba bien.
    """
    assert 'pending === 0 ? "sin decisiones pendientes"' in RESUMEN
    assert 'pending === 1 ? "acción espera tu decisión"' in RESUMEN
    assert '"acciones esperan tu decisión"' in RESUMEN
