"""El modo de solución: pasos (procedimiento en orden) vs soluciones distintas.

El Agente 1 marca cada playbook con cómo se relacionan sus acciones principales
entre sí, y el panel lo anuncia. Las alternativas de una acción son siempre
distintas, sin importar el modo del playbook.
"""

from __future__ import annotations

from pathlib import Path

import classifier

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_JS = PROJECT_ROOT / "services" / "gateway" / "static" / "app.js"


def _acciones(attack_type, ip="203.0.113.7", user="bob"):
    return classifier._finalize(
        "INC-X", classifier._playbook(attack_type, ip, user),
        modo=classifier._modo_solucion(attack_type))


# ─── El clasificador marca el modo ───────────────────────────────────────────

def test_fuerza_bruta_y_escaneo_son_pasos():
    """Son procedimientos: contener → investigar → remediar → endurecer."""
    for tipo in ("ssh_brute_force", "port_scan"):
        principales = [a for a in _acciones(tipo) if not a["alternativa_de"]]
        assert principales, tipo
        assert all(a["modo"] == "pasos" for a in principales), tipo


def test_phishing_son_soluciones_distintas():
    """Bloquear el servidor, resetear credenciales, avisar y blocklist son
    acciones paralelas e independientes, no un orden obligatorio."""
    principales = [a for a in _acciones("credential_harvesting") if not a["alternativa_de"]]
    assert principales
    assert all(a["modo"] == "distintas" for a in principales)


def test_toda_accion_principal_declara_su_modo():
    """El panel lee `modo` de cada acción principal: ninguna puede faltar."""
    for tipo in ("ssh_brute_force", "port_scan", "credential_harvesting"):
        for a in _acciones(tipo):
            if not a["alternativa_de"]:
                assert a["modo"] in ("pasos", "distintas"), (tipo, a["accion"])


def test_las_alternativas_siempre_son_distintas():
    """Una alternativa es una opción distinta de su acción y de las demás
    alternativas, aunque el playbook sea de modo 'pasos'."""
    for tipo in ("ssh_brute_force", "port_scan", "credential_harvesting"):
        alternativas = [a for a in _acciones(tipo) if a["alternativa_de"]]
        assert alternativas, tipo
        assert all(a["modo"] == "distintas" for a in alternativas), tipo


def test_el_modo_no_cambia_el_orden_ni_los_comandos():
    """Marcar el modo es solo describir la relación entre acciones: no reordena
    ni toca los comandos del playbook."""
    acciones = [a for a in _acciones("ssh_brute_force") if not a["alternativa_de"]]
    assert [a["orden"] for a in acciones] == list(range(1, len(acciones) + 1))
    assert any("ufw deny from" in (a.get("comando_sugerido") or "") for a in acciones)


def test_el_mapa_de_modos_cubre_los_tipos_con_playbook():
    """Todo tipo con comandos en el playbook tiene su modo declarado
    explícitamente (no depende del valor por defecto)."""
    assert set(classifier.MODO_SOLUCION_POR_ATAQUE) == {
        "ssh_brute_force", "port_scan", "credential_harvesting"}


# ─── El panel anuncia el modo ────────────────────────────────────────────────

def test_el_panel_tiene_el_aviso_de_modo():
    """app.js distingue los dos modos y los rotula de forma inconfundible."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "renderModoSolucion" in js
    assert "Plan de respuesta" in js          # modo pasos
    assert "Son soluciones distintas" in js   # modo distintas
    assert 'a.modo === "pasos"' in js         # la etiqueta "Paso N" depende del modo
