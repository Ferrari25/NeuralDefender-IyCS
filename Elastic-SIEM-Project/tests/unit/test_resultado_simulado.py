"""Vista previa simulada de una acción aprobada — nunca una ejecución real.

El analista pidió poder ver "qué pasaría" al aprobar una acción, sin que eso
implicara agregar una ruta de ejecución real (el proyecto entero está
construido, y probado, sobre que el sistema no ejecuta nada — ver
`tests/test_no_autonomy.py`). La respuesta es texto escrito a mano en el
playbook de `classifier.py`, igual que `comando_explicacion`, mostrado en el
panel SOLO después de aprobar y con un rótulo "SIMULADO" que no deja lugar a
confundirlo con un registro de auditoría real.
"""

from __future__ import annotations

from pathlib import Path

import classifier

RAIZ = Path(__file__).resolve().parent.parent.parent
APP_JS = (RAIZ / "static" / "app.js").read_text(encoding="utf-8")


def _todas_las_acciones() -> list[dict]:
    """El playbook completo, para los tres tipos de ataque con IP y usuario."""
    acciones = []
    for attack_type in ("ssh_brute_force", "port_scan", "credential_harvesting"):
        acciones += classifier._playbook(attack_type, "203.0.113.7", "testuser")
    return acciones


def test_toda_accion_con_comando_tiene_resultado_simulado():
    """Sugerir un comando sin decir qué pasaría al correrlo es la mitad de útil."""
    for a in _todas_las_acciones():
        if a["comando_sugerido"]:
            assert a["resultado_simulado"], (
                f"'{a['accion']}' tiene comando pero no resultado_simulado")


def test_accion_sin_comando_no_tiene_resultado_simulado():
    """Una tarea manual ("alertar a los usuarios") no tiene nada que simular:
    inventar una salida de terminal para algo que no es un comando confundiría
    más de lo que aclara."""
    for a in _todas_las_acciones():
        if not a["comando_sugerido"]:
            assert a["resultado_simulado"] is None, (
                f"'{a['accion']}' no tiene comando pero sí resultado_simulado")


def test_el_resultado_simulado_usa_los_mismos_datos_validados_que_el_comando():
    """No es un texto genérico: menciona la IP/usuario real del incidente,
    igual que el comando que dice simular."""
    acciones = classifier._playbook("ssh_brute_force", "203.0.113.7", "testuser")
    bloqueo = next(a for a in acciones if "firewall" in a["accion"])
    assert "203.0.113.7" in bloqueo["resultado_simulado"]

    rotacion = next(a for a in acciones if "rotación" in a["accion"])
    assert "testuser" in rotacion["resultado_simulado"]


def test_ninguna_accion_pretende_haber_ejecutado_algo():
    """El texto es una hipótesis ("simulado", "el atacante vería", "quedaría
    inválida"), no una afirmación de que algo ya pasó en este sistema."""
    prohibidas = ("se ejecutó", "fue ejecutado", "acabo de", "acabamos de correr")
    for a in _todas_las_acciones():
        if not a["resultado_simulado"]:
            continue
        texto = a["resultado_simulado"].lower()
        for frase in prohibidas:
            assert frase not in texto, f"'{a['accion']}' insinúa ejecución real: {frase!r}"


# ─── El panel lo muestra con un rótulo inconfundible, solo tras aprobar ──────

def test_la_simulacion_solo_se_pinta_si_la_accion_esta_aprobada():
    cuerpo = APP_JS[APP_JS.index("function renderAction("):
                    APP_JS.index("function renderResultadoSimulado(")]
    assert 'a.status === "approved" ? renderResultadoSimulado(a)' in cuerpo


def test_el_rotulo_simulado_esta_en_mayusculas_y_es_explicito():
    cuerpo = APP_JS[APP_JS.index("function renderResultadoSimulado("):
                    APP_JS.index("function renderResultadoSimulado(") + 800]
    assert "SIMULADO" in cuerpo
    assert "nada de esto se ejecutó" in cuerpo


def test_renderresultadosimulado_no_pinta_nada_sin_texto():
    """Un incidente sin `resultado_simulado` (acción manual) no deja un cartel
    vacío colgando en el panel."""
    cuerpo = APP_JS[APP_JS.index("function renderResultadoSimulado("):]
    cuerpo = cuerpo[:cuerpo.index("\n}") + 2]
    assert 'if (!a.resultado_simulado) return "";' in cuerpo


def test_el_campo_no_se_escribe_en_el_registro_de_decisiones():
    """`resultado_simulado` es contenido del playbook (Agente 1), no una
    decisión del analista — decisions.jsonl no tiene por qué guardarlo."""
    import inspect

    import dashboard

    fuente = inspect.getsource(dashboard)
    assert "resultado_simulado" not in fuente, (
        "dashboard.py no debería tocar este campo al escribir una decisión")
