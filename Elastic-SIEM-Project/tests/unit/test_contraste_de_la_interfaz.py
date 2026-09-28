"""Contraste de la interfaz según WCAG 2.1 (tarea **G1**, requisito `RNF-USA-08`).

El panel es la herramienta de trabajo de un analista que mira severidades durante
horas. Una insignia ilegible no es un detalle estético: es la diferencia entre ver y
no ver que un incidente es crítico.

Lo que encontraron estas pruebas, en orden:

1. **Las insignias de severidad.** `color: #fff` daba **3.35:1** en `CRITICAL` y
   **3.37:1** en `HIGH`, por debajo del 4.5:1 de AA. `MEDIUM` y `LOW` ya usaban texto
   oscuro y cumplían: la incoherencia era la pista.
2. **Una insignia que podía quedar invisible.** `.badge` fijaba `color:#fff` sin
   fondo, y el panel arma la clase como `"b-" + sev.toUpperCase()`. Una severidad
   fuera de las cuatro dejaba letras blancas sobre el fondo del panel.
3. **El hover del botón de login.** Aclaraba el fondo, y con texto blanco eso bajaba
   de 4.63:1 a **3.37:1**: el botón se volvía menos legible justo cuando estabas por
   apretarlo.

Un detalle que decide el umbral: las insignias son de **11px bold** y el botón de
**14px bold**. El nivel relajado de 3:1 ("texto grande") empieza en 18.66px bold — no
califica ninguno de los dos.

Todo se calcula leyendo las hojas. Es análisis estático: sin navegador ni capturas.
"""

from __future__ import annotations

import re

import pytest

from tests.unit.hojas_de_estilo import (
    COLORES,
    HOJAS_QUE_CONSUMEN,
    color,
    cuerpos,
    regla,
    sin_comentarios,
)

AA_NORMAL = 4.5   # texto normal
AA_GRANDE = 3.0   # >= 18.66px bold o >= 24px

APP = next(h for h in HOJAS_QUE_CONSUMEN if h.name == "app.css")
LOGIN = next(h for h in HOJAS_QUE_CONSUMEN if h.name == "login.css")


# ─── WCAG 2.1, §1.4.3 ────────────────────────────────────────────────────────

def _canal(v: float) -> float:
    return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4


def luminancia(hexa: str) -> float:
    h = hexa.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r, g, b = (_canal(int(h[i:i + 2], 16) / 255) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contraste(a: str, b: str) -> float:
    la, lb = luminancia(a), luminancia(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def test_la_formula_de_contraste_es_la_de_wcag():
    """Referencias conocidas: si esto falla, el resto de las pruebas miente."""
    assert contraste("#ffffff", "#000000") == pytest.approx(21.0, abs=0.01)
    assert contraste("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.01)
    assert contraste("#777777", "#ffffff") == pytest.approx(4.48, abs=0.02)
    assert contraste("#fff", "#ffffff") == pytest.approx(1.0, abs=0.01), "forma corta"


def test_los_tokens_de_color_se_leen():
    """Blindaje del andamiaje: si `tokens.css` cambia de forma, las pruebas de abajo
    pasarían por no encontrar nada que revisar."""
    assert {"bg", "panel", "text", "crit", "high", "med", "low"} <= set(COLORES)
    assert color("var(--err)") == COLORES["crit"], "no se resolvió el alias"


# ─── Las insignias de severidad ──────────────────────────────────────────────

SEVERIDADES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
CUERPO_APP = sin_comentarios(APP.read_text(encoding="utf-8"))
CUERPO_LOGIN = sin_comentarios(LOGIN.read_text(encoding="utf-8"))


@pytest.mark.parametrize("sev", SEVERIDADES)
def test_cada_insignia_de_severidad_cumple_aa(sev: str):
    reglas = regla(CUERPO_APP, f".b-{sev}")
    fondo = color(reglas["background"])
    texto = color(reglas.get("color") or regla(CUERPO_APP, ".badge")["color"])

    assert fondo and texto, f"no pude resolver los colores de .b-{sev}"
    ratio = contraste(fondo, texto)

    assert ratio >= AA_NORMAL, (
        f".b-{sev}: {texto} sobre {fondo} da {ratio:.2f}:1, por debajo de "
        f"{AA_NORMAL}:1. La insignia es 11px bold — no califica como texto grande. "
        f"Usar texto oscuro, como MEDIUM y LOW.")


@pytest.mark.parametrize("sev", SEVERIDADES)
def test_el_ratio_anotado_en_el_css_es_el_real(sev: str):
    """Cada regla lleva su ratio en un comentario. Un número viejo es peor que
    ninguno: alguien lo lee y confía."""
    m = re.search(rf"\.b-{sev}\s*\{{[^}}]*\}}\s*/\*\s*([\d.]+):1", APP.read_text(encoding="utf-8"))
    if not m:
        pytest.skip(f".b-{sev} no anota su ratio")

    reglas = regla(CUERPO_APP, f".b-{sev}")
    real = contraste(color(reglas["background"]), color(reglas["color"]))
    assert float(m.group(1)) == pytest.approx(real, abs=0.05), (
        f"el comentario dice {m.group(1)}:1 y el real es {real:.2f}:1")


def test_una_severidad_desconocida_sigue_siendo_legible():
    """`sevClass` arma la clase como `"b-" + sev.toUpperCase()`. Si llega un valor
    fuera de los cuatro, no hay regla `.b-*` y solo queda `.badge`: tiene que traer
    relleno y color propios, o la insignia se dibuja invisible."""
    badge = regla(CUERPO_APP, ".badge")

    fondo, texto = color(badge.get("background", "")), color(badge.get("color", ""))
    assert fondo and texto, ".badge no define fondo y color propios"
    assert contraste(fondo, texto) >= AA_NORMAL


# ─── Texto sobre los fondos ──────────────────────────────────────────────────

FONDOS = ["bg", "panel", "panel2", "panel3"]
COLORES_DE_TEXTO = ["text", "muted", "accent", "crit", "high", "med", "low", "ok-texto"]


@pytest.mark.parametrize("token", COLORES_DE_TEXTO)
@pytest.mark.parametrize("fondo", FONDOS)
def test_los_colores_de_texto_cumplen_aa_sobre_los_fondos(token: str, fondo: str):
    ratio = contraste(COLORES[token], COLORES[fondo])
    assert ratio >= AA_NORMAL, f"--{token} sobre --{fondo} da {ratio:.2f}:1"


# ─── Rellenos con texto ──────────────────────────────────────────────────────

@pytest.mark.parametrize("selector", [".s-approved", ".s-dismissed", ".s-pending"])
def test_los_chips_de_estado_cumplen_aa(selector: str):
    reglas = regla(CUERPO_APP, selector)
    ratio = contraste(color(reglas["background"]), color(reglas["color"]))
    assert ratio >= AA_NORMAL, f"{selector} da {ratio:.2f}:1"


@pytest.mark.parametrize("selector", [".aviso.error", ".aviso.espera"])
def test_los_avisos_del_login_cumplen_aa(selector: str):
    """El aviso de error y el de espera por intentos fallidos: texto teñido sobre
    fondo teñido, que es donde es fácil quedarse corto."""
    reglas = regla(CUERPO_LOGIN, selector)
    ratio = contraste(color(reglas["background"]), color(reglas["color"]))
    assert ratio >= AA_NORMAL, f"{selector} da {ratio:.2f}:1"


def test_el_boton_de_login_cumple_aa():
    reglas = regla(CUERPO_LOGIN, "button")
    ratio = contraste(color(reglas["background"]), color(reglas["color"]))
    assert ratio >= AA_NORMAL, f"el botón de login da {ratio:.2f}:1"


# ─── Los estados :hover, que heredan el color del texto ──────────────────────

def _color_heredado(cuerpo: str, selector_base: str) -> str:
    """El `color` de la regla base, o `--text` si no lo fija: `body` lo establece."""
    m = re.search(re.escape(selector_base) + r"\s*\{([^}]*)\}", cuerpo)
    if m:
        for d in m.group(1).split(";"):
            if ":" in d and d.split(":", 1)[0].strip() == "color":
                resuelto = color(d.split(":", 1)[1])
                if resuelto:
                    return resuelto
    return COLORES["text"]


@pytest.mark.parametrize("hoja", HOJAS_QUE_CONSUMEN, ids=lambda h: h.name)
def test_ningun_hover_empeora_la_legibilidad(hoja):
    """**El defecto que encontró esta prueba.**

    Una regla `:hover` que solo cambia el fondo hereda el color del texto de su
    regla base. El botón de login aclaraba el fondo en hover y con texto blanco
    pasaba de 4.63:1 a 3.37:1 — menos legible justo antes del clic.

    Oscurecer da la misma señal de interacción sin perder contraste.
    """
    cuerpo = sin_comentarios(hoja.read_text(encoding="utf-8"))
    fallan = []

    for m in re.finditer(r"(?m)^([^{}\n]*:hover[^{}\n]*)\{([^}]*)\}", cuerpo):
        selector, declaraciones = m.group(1).strip(), m.group(2)
        fondo = next((color(d.split(":", 1)[1]) for d in declaraciones.split(";")
                      if ":" in d and d.split(":", 1)[0].strip() == "background"), None)
        if not fondo:
            continue

        base = re.sub(r":hover.*", "", selector).strip()
        ratio = contraste(fondo, _color_heredado(cuerpo, base))
        if ratio < AA_NORMAL:
            fallan.append(f"{selector} → {ratio:.2f}:1 (base: {base})")

    assert not fallan, f"hovers por debajo de AA en {hoja.name}: " + "; ".join(fallan)


# ─── Barrido general ─────────────────────────────────────────────────────────

def test_ninguna_regla_combina_fondo_y_texto_ilegibles():
    """La que atrapa un estilo nuevo que nadie pensó en revisar, en cualquier hoja."""
    fallan = []
    for hoja, cuerpo in cuerpos():
        for m in re.finditer(r"([^{}]+)\{([^}]*)\}", cuerpo):
            selector = m.group(1).strip().splitlines()[-1].strip()
            d = {k.strip(): v.strip() for k, v in
                 (x.split(":", 1) for x in m.group(2).split(";") if ":" in x)}
            fondo, texto = color(d.get("background", "")), color(d.get("color", ""))
            if fondo and texto and contraste(fondo, texto) < AA_GRANDE:
                fallan.append(f"{hoja.name} · {selector}: {contraste(fondo, texto):.2f}:1")

    assert not fallan, (
        "reglas con fondo y texto por debajo incluso de 3:1: " + ", ".join(fallan))
