"""El historial de decisiones se agrupa por incidente, no por acción (pedido
directo del analista: "genera muchísima información para solo 4 eventos").

`decisions.jsonl` es append-only y por acción: un incidente con 3 acciones
decididas dejaba 3 líneas en el historial, cada una repitiendo el mismo
`incident_id`. Con pocos incidentes activos, eso ya alcanzaba para una lista
larga y ruidosa.

Ahora es una línea por incidente (colapsada), con el desglose de
aprobadas/descartadas, que se puede abrir para ver cada acción — no se pierde
nada, se resume la vista por defecto.
"""

from __future__ import annotations

from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")


def _cuerpo_de(nombre_funcion: str) -> str:
    inicio = APP_JS.index(f"function {nombre_funcion}(")
    return APP_JS[inicio:APP_JS.index("\n}", inicio)]


def test_el_historial_agrupa_por_incidente():
    cuerpo = _cuerpo_de("renderDecisionHistory")
    assert "porIncidente" in cuerpo
    assert "d.incident_id" in cuerpo


def test_el_grupo_resume_aprobadas_y_descartadas():
    cuerpo = _cuerpo_de("renderDecisionHistory")
    assert "g.aprobadas" in cuerpo and "g.descartadas" in cuerpo


def test_el_grupo_se_puede_abrir_sin_perder_el_detalle():
    """Colapsar la vista no puede significar tirar el dato: cada acción
    decidida individualmente tiene que seguir estando, solo que adentro del
    detalle expandible."""
    assert "let decisionesAbiertas" in APP_JS or "const decisionesAbiertas" in APP_JS
    assert "function toggleDecisiones(" in APP_JS
    cuerpo = _cuerpo_de("renderDecisionHistory")
    assert "g.items.map(d =>" in cuerpo, "el detalle por acción ya no se arma"


def test_el_toggle_es_un_boton_real_no_un_div_con_click():
    """Mismo criterio de accesibilidad que `.ev-head`: un control que se puede
    alcanzar con el tabulador, no un <div> con un manejador."""
    assert '<button type="button" class="decision-head"' in APP_JS
    assert 'aria-expanded="${abierto' in APP_JS


def test_la_delegacion_conoce_toggle_decisiones():
    assert '"toggle-decisiones"' in APP_JS


def test_el_texto_de_la_accion_se_resuelve_desde_los_incidentes_cargados():
    """`decisions.jsonl` solo guarda `action_id` (un hash corto) — sin esto, el
    detalle mostraría el id en vez de qué acción fue."""
    assert "function _accionTexto(" in APP_JS
    cuerpo = _cuerpo_de("_accionTexto")
    assert "lastData.incidents" in cuerpo
