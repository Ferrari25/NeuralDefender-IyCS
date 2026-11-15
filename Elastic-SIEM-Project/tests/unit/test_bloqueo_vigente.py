"""Bloqueo vigente: una IP que un analista ya bloqueó y vuelve a aparecer.

Si se aprobó "Bloquear la IP …" en un incidente, la misma IP en OTRO incidente
recibe su acción de bloqueo como `auto_applied`, sin pedir otra aprobación. Es
estado derivado del registro de decisiones (no ejecuta nada), se revoca
descartando la acción original, y una decisión explícita sobre la acción nueva
siempre gana.
"""

from __future__ import annotations

import importlib
import os

from tests.conftest import SECRET_KEY_DE_PRUEBA

os.environ.setdefault("SECRET_KEY", SECRET_KEY_DE_PRUEBA)
dashboard = importlib.import_module("dashboard")

IP = "198.51.100.77"
BLOQUEO = "Bloquear la IP que realiza el escaneo en el firewall"


def _decision(incident_id, action_id, decision="approved", accion=BLOQUEO, ip=IP,
              ts="2026-11-10T22:00:00+00:00"):
    return {"incident_id": incident_id, "action_id": action_id, "decision": decision,
            "analyst": "ana", "accion": accion, "source_ip": ip, "ts": ts}


def _incidente(incident_id, ip=IP, acciones=None):
    acciones = acciones or [
        ("a1", "Bloquear la IP atacante en el firewall perimetral"),
        ("a2", "Banear la IP en fail2ban (bloqueo temporal que expira solo)"),
        ("a3", "Verificar si hubo algún login EXITOSO desde la IP atacante"),
    ]
    return {"incident_id": incident_id, "source_ip": ip,
            "recommended_actions": [{"action_id": f"{incident_id}-{a}", "accion": t,
                                     "status": "pending"} for a, t in acciones]}


def _aplicar(state, inc):
    dashboard._aplicar_bloqueo_vigente(inc, dashboard._bloqueos_vigentes(state))
    return {a["accion"]: a["status"] for a in inc["recommended_actions"]}


def test_la_misma_ip_en_otro_incidente_queda_bloqueada_sola():
    state = {"SCAN-x": _decision("INC-SCAN", "SCAN-x")}
    inc = _incidente("INC-AUTH")
    estados = _aplicar(state, inc)
    assert estados["Bloquear la IP atacante en el firewall perimetral"] == "auto_applied"
    assert estados["Banear la IP en fail2ban (bloqueo temporal que expira solo)"] == "auto_applied"
    # Lo que no es un bloqueo sigue esperando a un humano.
    assert estados["Verificar si hubo algún login EXITOSO desde la IP atacante"] == "pending"
    b = inc["bloqueo_vigente"]
    assert (b["ip"], b["aprobado_por"], b["incidente_origen"]) == (IP, "ana", "INC-SCAN")
    assert b["acciones_aplicadas"] == 2


def test_el_incidente_de_origen_no_se_marca_como_reincidencia():
    inc = _incidente("INC-SCAN")
    _aplicar({"x": _decision("INC-SCAN", "x")}, inc)
    assert "bloqueo_vigente" not in inc


def test_otra_ip_no_se_ve_afectada():
    inc = _incidente("INC-AUTH", ip="203.0.113.9")
    assert set(_aplicar({"x": _decision("INC-SCAN", "x")}, inc).values()) == {"pending"}
    assert "bloqueo_vigente" not in inc


def test_descartar_el_bloqueo_original_lo_revoca():
    state = {"x": _decision("INC-SCAN", "x", decision="dismissed")}
    inc = _incidente("INC-AUTH")
    assert set(_aplicar(state, inc).values()) == {"pending"}


def test_una_accion_que_no_bloquea_no_crea_regla():
    state = {"x": _decision("INC-SCAN", "x", accion="Verificar si hubo algún login EXITOSO")}
    assert dashboard._bloqueos_vigentes(state) == {}


def test_bloqueos_salientes_de_phishing_no_cuentan():
    for texto in ("Bloquear el tráfico SALIENTE hacia el servidor de phishing (UFW)",
                  "Dar de baja / bloquear el servidor de phishing (página falsa)",
                  "Bloquear la cuenta (testuser) en vez de cambiarle la contraseña"):
        assert not dashboard._es_bloqueo_de_ip(texto)


def test_una_ip_invalida_no_se_bloquea():
    assert dashboard._bloqueos_vigentes({"x": _decision("I", "x", ip="desconocida")}) == {}


def test_la_decision_explicita_sobre_la_accion_nueva_gana():
    inc = _incidente("INC-AUTH")
    inc["recommended_actions"][0]["status"] = "dismissed"
    estados = _aplicar({"x": _decision("INC-SCAN", "x")}, inc)
    assert estados["Bloquear la IP atacante en el firewall perimetral"] == "dismissed"
    assert inc["bloqueo_vigente"]["acciones_aplicadas"] == 1


def test_el_panel_traduce_el_estado_nuevo():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "services/gateway/static/app.js").read_text()
    assert '["auto_applied",' in js
    assert "renderBloqueoVigente" in js
