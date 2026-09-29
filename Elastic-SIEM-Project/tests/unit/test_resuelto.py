"""La tabla de eventos activos marca "resuelto" cuando ya se aprobó algo
(pedido directo del analista).

No hay un campo `resuelto` en los datos: se deriva de si ALGUNA acción
sugerida del incidente tiene `status === "approved"`. No hace falta trackear
"visto" por separado — aprobar una acción solo es posible con el detalle del
incidente abierto (el botón vive adentro de la tarjeta), así que ya implica
que un analista lo revisó.

La insignia reutiliza `.state.s-approved`, el mismo tinte que ya se usa para el
chip "aprobada" de una acción individual — mismo significado, mismo color, en
vez de inventar uno nuevo para decir lo mismo.
"""

from __future__ import annotations

from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")
APP_CSS = (RAIZ / "static" / "app.css").read_text(encoding="utf-8")


def _cuerpo_de(nombre_funcion: str) -> str:
    inicio = APP_JS.index(f"function {nombre_funcion}(")
    return APP_JS[inicio:APP_JS.index("\n}", inicio)]


def test_resuelto_se_deriva_de_una_accion_aprobada():
    assert 'inc => (inc.recommended_actions || []).some(a => a.status === "approved")' in APP_JS


def test_la_fila_de_la_tabla_pinta_el_tag_de_resuelto():
    cuerpo = _cuerpo_de("rowHtml")
    assert "tieneAccionAprobada(inc)" in cuerpo
    assert "resuelto-tag" in cuerpo


def test_resuelto_reusa_el_tinte_de_aprobada_no_inventa_uno():
    """Mismo criterio que el resto del panel: un significado, un color."""
    assert '"state s-approved resuelto-tag"' in APP_JS
    assert not any(feo in APP_CSS for feo in (".resuelto-tag { background:", ".resuelto-tag{background:")), (
        "el tag de resuelto define su propio fondo en vez de heredar .s-approved")


def test_resuelto_no_depende_de_un_campo_que_no_manda_el_servidor():
    """Si esto dejara de leer `recommended_actions`, dependería de algún campo
    'visto'/'resuelto' inventado del lado del cliente sin respaldo en los datos."""
    cuerpo = _cuerpo_de("rowHtml")
    assert "inc.resuelto" not in cuerpo and "inc.visto" not in cuerpo
