"""Un estado no se pinta como una acción (tarea **G4**).

En la fila de cada acción recomendada convivían dos pastillas:

    [ approved ]   …descripción…        [ Aprobar ] [ Descartar ]
      ↑ estado                            ↑ acción

Las dos eran **relleno verde saturado con texto blanco**. Una informa qué pasó; la
otra ofrece hacer algo. Un relleno saturado dice "apretame", así que el chip invitaba
a un clic que no existe — y peor: el analista podía leer «aprobada» como si todavía
tuviera que aprobar.

La corrección separa los dos lenguajes:

* **Estado** → tinte con borde. Se lee como etiqueta.
* **Acción** → relleno sólido. Se lee como control.

Y el chip lleva una marca (`✔` / `✘`), así la distinción no depende solo del color:
quien no distingue verde de rojo igual lo lee. Eso es `RNF-USA-08`, no un adorno.

De paso salió que el chip mostraba el **valor crudo de la API** (`approved`,
`pending`) en un panel en español, mientras el historial de decisiones —unas líneas
más abajo en el mismo archivo— ya traducía.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import dashboard
from tests.unit.hojas_de_estilo import color, regla, sin_comentarios

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_CSS = sin_comentarios((RAIZ / "static" / "app.css").read_text(encoding="utf-8"))
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")

# `pending` es el estado por defecto cuando no hay decisión registrada
# (`dashboard.py`: `act["status"] = rec["decision"] if rec else "pending"`).
ESTADOS = ("pending", *dashboard.DECISIONES_VALIDAS)


def test_los_estados_salen_del_codigo_y_no_de_una_lista_copiada():
    """Blindaje: si `DECISIONES_VALIDAS` cambia, estas pruebas tienen que enterarse."""
    assert dashboard.DECISIONES_VALIDAS == ("approved", "dismissed")
    assert len(ESTADOS) == 3


# ─── La separación de lenguajes ──────────────────────────────────────────────

def _fondos_de_boton_activo() -> dict[str, str]:
    """El fondo de cada `button.<algo>.on`: los botones que están "puestos"."""
    return {m.group(1): color(m.group(2))
            for m in re.finditer(r"button\.(\w+)\.on\s*\{[^}]*background:\s*([^;}]+)", APP_CSS)}


@pytest.mark.parametrize("estado", ESTADOS)
def test_ningun_estado_se_pinta_como_un_boton_activo(estado: str):
    """**El defecto, en una prueba.**

    `.s-approved` y `button.approve.on` compartían `var(--ok)` como fondo. Si
    alguien los vuelve a igualar, esto falla con los dos colores a la vista.
    """
    fondo_estado = color(regla(APP_CSS, f".s-{estado}")["background"])
    assert fondo_estado, f"no pude resolver el fondo de .s-{estado}"

    choques = {nombre: fondo for nombre, fondo in _fondos_de_boton_activo().items()
               if fondo == fondo_estado}

    assert not choques, (
        f".s-{estado} usa {fondo_estado}, el mismo fondo que "
        f"{', '.join(f'button.{n}.on' for n in choques)}. Un estado y una acción no "
        f"pueden pintarse igual: conviven en la misma fila.")


@pytest.mark.parametrize("estado", ESTADOS)
def test_los_chips_de_estado_se_leen_como_etiqueta(estado: str):
    """Un borde y un tinte los separan del relleno sólido de los botones."""
    base = regla(APP_CSS, ".state")
    propia = regla(APP_CSS, f".s-{estado}")

    assert "border" in base, ".state perdió su borde: vuelve a parecer un botón"
    fondo = color(propia["background"])
    texto = color(propia["color"])
    assert fondo and texto, f".s-{estado} no define fondo y color"
    assert texto != "#fff", (
        f".s-{estado} volvió al texto blanco, que es el del relleno sólido de los "
        f"botones")


def test_los_botones_activos_conservan_el_relleno_solido():
    """La otra mitad de la separación: si los botones también se atenuaran, se
    perdería la señal de "acá se puede hacer algo"."""
    fondos = _fondos_de_boton_activo()
    assert set(fondos) == {"approve", "dismiss"}, f"botones inesperados: {set(fondos)}"

    for nombre in fondos:
        assert color(regla(APP_CSS, f"button.{nombre}.on")["color"]) in ("#fff", "#ffffff"), (
            f"button.{nombre}.on dejó de usar texto blanco sobre relleno sólido")


# ─── Cada estado tiene su regla y su etiqueta ────────────────────────────────

@pytest.mark.parametrize("estado", ESTADOS)
def test_cada_estado_posible_tiene_su_regla_css(estado: str):
    """La clase se arma como `s-${a.status}`. Un estado sin regla queda sin pintar."""
    assert re.search(rf"\.s-{estado}\s*\{{", APP_CSS), f"falta la regla .s-{estado}"


@pytest.mark.parametrize("estado", ESTADOS)
def test_cada_estado_posible_tiene_su_etiqueta_en_español(estado: str):
    assert re.search(rf'\["{estado}", "[^"]+"\]', APP_JS), (
        f"«{estado}» no está en ESTADO_TEXTO: el panel mostraría el valor crudo")


def test_el_chip_no_muestra_el_valor_crudo_de_la_api():
    """Se interpola la etiqueta, no el estado. La CLASE sí usa el valor crudo, y
    tiene que seguir haciéndolo: es lo que selecciona el color."""
    chips = re.findall(r'<span class="state s-\$\{([^}]+)\}">\$\{([^}]+)\}</span>', APP_JS)
    assert chips, "no encontré ningún chip de estado en el marcado"

    for clase, contenido in chips:
        assert "estadoTexto(" in contenido, (
            f"el chip interpola «{contenido}» como texto: es el valor de la API")
        assert "estadoTexto" not in clase, (
            "la clase tiene que usar el estado crudo, que es lo que elige el color")


def test_los_estados_decididos_se_distinguen_sin_color():
    """`RNF-USA-08`. Verde y rojo no alcanzan: alrededor del 8 % de los varones tiene
    alguna deficiencia en la visión del rojo y el verde. La marca lo resuelve sin
    ocupar espacio."""
    etiquetas = dict(re.findall(r'\["(\w+)", "([^"]+)"\]', APP_JS))

    for estado, marca in (("approved", "✔"), ("dismissed", "✘")):
        assert marca in etiquetas.get(estado, ""), (
            f"«{estado}» se distingue solo por el color: su etiqueta es "
            f"«{etiquetas.get(estado)}»")

    assert "pendiente" in etiquetas.get("pending", ""), (
        "el estado pendiente no lleva marca a propósito: es la ausencia de decisión")


def test_la_etiqueta_del_chip_coincide_con_la_del_historial():
    """El historial de decisiones ya traducía a español con marca. Dos vocabularios
    para lo mismo, en la misma pantalla, es lo que había."""
    etiquetas = dict(re.findall(r'\["(\w+)", "([^"]+)"\]', APP_JS))
    historial = re.search(r'"(✔ \w+)" : "(✘ \w+)"', APP_JS)
    assert historial, "cambió la forma del historial de decisiones"

    for chip, hist in ((etiquetas["approved"], historial.group(1)),
                       (etiquetas["dismissed"], historial.group(2))):
        assert chip.lower() == hist.lower(), (
            f"el chip dice «{chip}» y el historial «{hist}»")


# ─── El rol viewer ve estados, no controles ──────────────────────────────────

def test_el_rol_de_solo_lectura_esconde_los_controles_no_los_estados():
    """Para un `viewer` el panel es lectura pura. Con los estados atenuados eso se
    refuerza: no quedan rellenos sólidos invitando a un clic que el rol no tiene.

    La no-autonomía va por otro lado —ningún rol ejecuta contención—, pero que la
    interfaz no ofrezca lo que no se puede hacer es parte de lo mismo.
    """
    assert re.search(r"body\.solo-lectura[^{]*\.ctrl", APP_CSS), (
        "se perdió la regla que esconde los controles en modo solo lectura")
    assert not re.search(r"body\.solo-lectura[^{]*\.state", APP_CSS), (
        "el modo solo lectura esconde los estados: el viewer se queda sin saber qué "
        "se decidió")
