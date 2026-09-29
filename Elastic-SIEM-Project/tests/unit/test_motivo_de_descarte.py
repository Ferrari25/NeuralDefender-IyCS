"""Descartar pide el motivo dentro del panel, no con un `prompt()` (sin tarea
asociada — pedido directo del analista).

Antes, `decide()` mostraba `prompt("Motivo (opcional) para descartar:")`: un
cuadro nativo del navegador, fuera del flujo visual del panel, fácil de cerrar
sin escribir nada y sin ningún indicio de para qué sirve ese texto.

Sirve para algo concreto: `siem_agent.historical_context()` se lo muestra al
analista la próxima vez que la MISMA IP aparezca en otro incidente ("¿ya la
descartamos antes, y por qué?"). Tratarlo como un detalle opcional de un cuadro
nativo escondía esa conexión.

Ahora "Descartar" abre un formulario dentro de la propia tarjeta de la acción
(`renderMotivoForm`) con un campo de texto y un hint que dice en voz alta para
qué se usa ese motivo. Recién al confirmar se llama a `decide()`.
"""

from __future__ import annotations

from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")
LOGIN_JS = (RAIZ / "static" / "login.js").read_text(encoding="utf-8")
APP_CSS = (RAIZ / "static" / "app.css").read_text(encoding="utf-8")
ESLINT_CONFIG = (RAIZ / "eslint.config.js").read_text(encoding="utf-8")


def _cuerpo_de(nombre_funcion: str) -> str:
    inicio = APP_JS.index(f"function {nombre_funcion}(")
    return APP_JS[inicio:APP_JS.index("\n}", inicio)]


def _sin_comentarios(texto: str) -> str:
    """Quita los `//` de línea: los comentarios de acá explican el propio
    cambio y mencionan `prompt()`/`alert()` al contarlo, sin ser una llamada."""
    return "\n".join(linea for linea in texto.splitlines() if not linea.strip().startswith("//"))


# ─── `prompt()` ya no decide si hay motivo o no ──────────────────────────────

def test_decide_ya_no_usa_prompt():
    """El cuadro nativo desapareció: el motivo entra por el formulario propio."""
    assert "prompt(" not in _cuerpo_de("decide")


def test_alert_y_prompt_ya_no_estan_permitidos_en_eslint():
    """Con el formulario propio, `decide()` dejó de usar `prompt()` — y ya antes
    había dejado de usar `alert()` (los errores van al toast). Dejar esos dos
    globals en el allowlist de ESLint sería una puerta abierta para el próximo
    `alert()` de apuro, sin que ningún test lo note.
    """
    app_js_sin_comentarios = _sin_comentarios(APP_JS)
    assert "prompt(" not in app_js_sin_comentarios and "prompt(" not in LOGIN_JS
    assert "alert(" not in app_js_sin_comentarios and "alert(" not in LOGIN_JS

    globals_bloque = ESLINT_CONFIG[ESLINT_CONFIG.index("globals: {"):
                                   ESLINT_CONFIG.index("},", ESLINT_CONFIG.index("globals: {"))]
    assert '"alert"' not in globals_bloque and "alert:" not in globals_bloque
    assert '"prompt"' not in globals_bloque and "prompt:" not in globals_bloque


# ─── El formulario existe y pide el motivo con contexto ──────────────────────

def test_el_formulario_de_motivo_existe():
    assert "function renderMotivoForm(" in APP_JS


def test_el_formulario_tiene_un_campo_de_texto():
    cuerpo = _cuerpo_de("renderMotivoForm")
    assert "<textarea" in cuerpo


def test_el_formulario_explica_para_que_sirve_el_motivo():
    """No alcanza con pedirlo: tiene que decir por qué importa, o vuelve a leerse
    como un campo opcional que no cambia nada."""
    cuerpo = _cuerpo_de("renderMotivoForm")
    assert "Agente 2" in cuerpo or "contexto" in cuerpo.lower(), (
        "el formulario no explica que el motivo alimenta el contexto histórico")


def test_el_formulario_se_puede_cancelar_sin_decidir():
    """Abrir el formulario no puede forzar la decisión: tiene que poder cerrarse
    sin descartar nada."""
    assert "function cancelarMotivo(" in APP_JS
    cuerpo = _cuerpo_de("cancelarMotivo")
    assert "decide(" not in cuerpo, "cancelar no puede terminar llamando a decide()"


# ─── El flujo completo: pedir → confirmar ────────────────────────────────────

def test_descartar_abre_el_formulario_en_vez_de_decidir_al_toque():
    """El botón "Descartar" ya no dispara `decidir` directamente."""
    boton = APP_JS[APP_JS.index('class="dismiss'):APP_JS.index("</button>",
                                 APP_JS.index('class="dismiss'))]
    assert 'data-accion="pedir-motivo"' in boton
    assert 'data-decision="dismissed"' not in boton, (
        "Descartar sigue decidiendo directo: no pasa por el formulario")


def test_confirmar_descarte_lee_el_textarea_y_llama_a_decide():
    cuerpo = _cuerpo_de("confirmarDescarte")
    assert "getElementById" in cuerpo and ".value" in cuerpo
    assert 'decide(incident_id, action_id, "dismissed"' in cuerpo


def test_la_delegacion_conoce_las_tres_acciones_nuevas():
    for accion in ("pedir-motivo", "confirmar-descarte", "cancelar-motivo"):
        assert f'"{accion}"' in APP_JS, f"delegar() no reconoce '{accion}'"


# ─── El estado de "qué formulario está abierto" no se pierde en un re-render ─

def test_el_estado_de_motivo_pendiente_es_una_variable_de_modulo():
    """`render()` se llama todo el tiempo (auto-refresco de 15s); si el estado
    viviera en el DOM en vez de en una variable, un refresco lo perdería a mitad
    de escribir el motivo."""
    assert "let pidiendoMotivo" in APP_JS


# ─── Aprobar / Descartar siguen sin ejecutar nada ────────────────────────────

def test_el_formulario_no_agrega_ninguna_via_de_ejecucion():
    """Mismo blindaje que el resto del panel: nada de innerHTML, eval ni
    handlers inline en el camino nuevo."""
    for nombre in ("renderMotivoForm", "pedirMotivo", "confirmarDescarte", "cancelarMotivo"):
        cuerpo = _cuerpo_de(nombre)
        for peligro in ("innerHTML", "eval(", "new Function"):
            assert peligro not in cuerpo, f"{nombre} usa {peligro}"
