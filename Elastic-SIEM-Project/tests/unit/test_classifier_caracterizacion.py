"""Caracterización del Agente 1 sobre la captura real del stack.

Estas pruebas NO dicen qué *debería* hacer el clasificador: congelan lo que hace
**hoy**, para que la refactorización de la Fase 1 no cambie nada sin que se note.
Al cerrar la Fase 2 ya no queda ningún bug del clasificador congelado: cada uno
tiene su archivo de regresión (`test_s01_*`, `test_l01_l02_*`, `test_b0x_*`).
"""

from __future__ import annotations

import classifier

# ─── Forma general de la salida ──────────────────────────────────────────────

def test_cantidad_de_incidentes(incidents):
    """La captura real produce 3 incidentes.

    Eran 4 hasta la Fase 1: los dos incidentes AUTH eran el mismo ataque partido
    por la ambigüedad atacante/víctima (L-02).
    """
    assert len(incidents) == 3


def test_ids_de_incidente_estables(incidents):
    """Los incident_id son deterministas: mismo input ⇒ mismos IDs.

    Importa porque `decisions.jsonl` referencia estos IDs: si cambian sin aviso,
    la auditoría histórica queda huérfana (A-03).

    El sufijo cambió en la Fase 2 al pasar de SHA-1 a SHA-256 (hallazgo B324 de
    bandit). Fue un corte consciente y por única vez, documentado en
    `docs/12-registro-de-pruebas.md` §6.
    """
    assert [i["incident_id"] for i in incidents] == [
        "INC-SCAN-172.18.0.7-8e58721f",
        "INC-AUTH-172.18.0.3-1d106398",
        "INC-PHISH-172.18.0.9-ed0c800f",
    ]


def test_orden_por_cantidad_de_eventos(incidents):
    """Los incidentes salen ordenados por event_count descendente."""
    counts = [i["event_count"] for i in incidents]
    assert counts == sorted(counts, reverse=True)
    assert counts == [26, 12, 1]


def test_tipos_y_severidades(incidents):
    por_id = {i["incident_id"]: i["classification"] for i in incidents}
    assert por_id["INC-SCAN-172.18.0.7-8e58721f"]["attack_type"] == "port_scan"
    assert por_id["INC-SCAN-172.18.0.7-8e58721f"]["severity"] == "alta"
    assert por_id["INC-AUTH-172.18.0.3-1d106398"]["attack_type"] == "ssh_brute_force"
    assert por_id["INC-PHISH-172.18.0.9-ed0c800f"]["attack_type"] == "credential_harvesting"


def test_todo_incidente_tiene_el_contrato_minimo(incidents):
    """El dashboard y el Agente 2 asumen estas claves; que ninguna falte."""
    requeridas = {
        "incident_id", "source_ip", "attacker_ips", "target_users",
        "first_seen", "last_seen", "event_count", "mitre",
        "classification", "analysis", "recommended_actions",
        "campaign_id", "related_incidents", "campaign_shared_ips",
    }
    for inc in incidents:
        assert requeridas <= set(inc), f"{inc['incident_id']} incompleto"


def test_analysis_arranca_vacio(incidents):
    """El Agente 1 nunca escribe `analysis`: eso es trabajo del Agente 2."""
    assert all(i["analysis"] is None for i in incidents)


# ─── Clasificación y explicabilidad ──────────────────────────────────────────

def test_toda_clasificacion_trae_factores(incidents):
    """Los `factores` son la explicabilidad que consume el dashboard."""
    for inc in incidents:
        factores = inc["classification"]["factores"]
        assert factores and all(isinstance(f, str) for f in factores)


def test_mitre_por_tipo_de_ataque(incidents):
    esperado = {
        "port_scan": "T1046",
        "ssh_brute_force": "T1110",
        "credential_harvesting": "T1566",
        "suspicious_auth": None,
    }
    for inc in incidents:
        atype = inc["classification"]["attack_type"]
        assert inc["classification"]["mitre_technique"] == esperado[atype]


def test_severidad_critica_por_volumen_extremo(siem_clean):
    """Por encima de CRITICAL_FAILURE_COUNT la severidad sube a 'critica'."""
    c = classifier._classification("ssh_brute_force", classifier.CRITICAL_FAILURE_COUNT,
                                   "detalle", [])
    assert c["severity"] == "critica"
    c_menor = classifier._classification("ssh_brute_force",
                                         classifier.CRITICAL_FAILURE_COUNT - 1, "detalle", [])
    assert c_menor["severity"] == "alta"


# ─── Umbrales ────────────────────────────────────────────────────────────────

def test_umbrales_declarados():
    """Congela los valores: la Fase 4 tiene que justificarlos en docs/13."""
    assert classifier.BRUTE_FORCE_THRESHOLD == 20
    assert classifier.CRITICAL_FAILURE_COUNT == 5000
    assert classifier.PORT_SCAN_DISTINCT_PORTS == 10


def test_port_scan_respeta_su_umbral():
    """9 puertos no son un escaneo; 10 sí."""
    def evento(puerto):
        return {"event_type": "network_flow", "source_ip": "10.1.1.1",
                "dest_ip": "10.1.1.2", "dest_port": puerto,
                "@timestamp": "2026-09-16T10:00:00.000Z"}

    assert classifier.detect_port_scans([evento(p) for p in range(1, 10)]) == []
    detectado = classifier.detect_port_scans([evento(p) for p in range(1, 11)])
    assert len(detectado) == 1
    assert detectado[0]["classification"]["attack_type"] == "port_scan"


def test_port_scan_agrega_puertos_y_destinos(incidents):
    scan = next(i for i in incidents if i["incident_id"].startswith("INC-SCAN"))
    assert len(scan["scanned_ports"]) == 26
    assert scan["target_hosts"] == ["172.18.0.5"]


# ─── Filtro MITRE de las alertas de autenticación ────────────────────────────

def test_alertas_de_otras_tecnicas_no_entran_como_auth(siem_clean):
    """Una alerta T1046/T1566 no debe procesarse como incidente de auth."""
    incs = classifier.detect_auth_incidents(siem_clean)
    ips = {i["source_ip"] for i in incs}
    assert "172.18.0.9" not in ips, "la alerta de phishing (T1566) se coló en auth"


# ─── Phishing ────────────────────────────────────────────────────────────────

def test_phishing_ignora_el_get_sin_credenciales(network_logs_dir):
    """El fixture tiene un GET y un POST; solo el POST con credenciales cuenta."""
    from tests.conftest import eventos_de_red
    incs = classifier.detect_phishing(eventos_de_red(network_logs_dir))
    assert len(incs) == 1
    assert incs[0]["event_count"] == 1


# ─── Playbooks ───────────────────────────────────────────────────────────────

def test_toda_accion_tiene_id_y_estado_inicial(incidents):
    """El `action_id` deriva del contenido de la acción, no de su posición (A-03)."""
    for inc in incidents:
        vistos = set()
        for act in inc["recommended_actions"]:
            assert act["action_id"].startswith(f"{inc['incident_id']}-")
            assert act["action_id"] not in vistos, "action_id duplicado"
            vistos.add(act["action_id"])
            assert act["status"] == "pending"


def test_playbook_por_tipo_de_ataque():
    """Cada tipo tiene su playbook; los desconocidos escalan a L2."""
    assert len(classifier._playbook("ssh_brute_force", "1.2.3.4", "bob")) == 4
    assert len(classifier._playbook("port_scan", "1.2.3.4", None)) == 4
    assert len(classifier._playbook("credential_harvesting", "1.2.3.4", "bob")) == 4
    generico = classifier._playbook("cualquier_otra_cosa", None, None)
    assert len(generico) == 1
    assert "L2" in generico[0]["accion"]


def test_los_comandos_salen_del_playbook_no_del_llm(incidents):
    """Ningún comando puede provenir del Agente 2: el Agente 1 los fija acá."""
    catalogo = ("sudo ufw deny from", "grep 'Accepted password'", "sudo passwd",
                "sudo apt-get install -y fail2ban", "sudo ss -tulnp")
    for inc in incidents:
        for act in inc["recommended_actions"]:
            cmd = act["comando_sugerido"]
            if cmd is not None:
                assert cmd.startswith(catalogo), f"comando fuera del catálogo: {cmd}"


# ─── Saneamiento heredado ────────────────────────────────────────────────────

def test_los_mensajes_de_muestra_estan_saneados(incidents):
    """`sanitize_for_prompt` aplana saltos de línea antes de llegar al LLM."""
    for inc in incidents:
        for msg in inc["sample_messages"]:
            assert "\n" not in msg and "\r" not in msg


# ─── R-02 · forma canónica del incidente ─────────────────────────────────────

def test_todos_los_incidentes_comparten_la_misma_forma(incidents):
    """Un incidente es un incidente, venga de la detección que venga.

    Antes de R-02, cada `detect_*` armaba el diccionario a mano y las formas no
    coincidían: los de port scan y phishing no traían `victim_hosts`,
    `log_event_count` ni `alert_event_count`, así que el dashboard recibía
    objetos distintos según el tipo de ataque y tenía que defenderse con `.get()`
    en todos lados.
    """
    base = {
        "incident_id", "source_ip", "attacker_ips", "victim_hosts", "target_users",
        "first_seen", "last_seen", "event_count", "log_event_count",
        "alert_event_count", "rule_name", "severity_siem", "risk_score", "mitre",
        "sample_messages", "evidence", "classification", "analysis",
        "recommended_actions",
    }
    for inc in incidents:
        faltantes = base - set(inc)
        assert not faltantes, f"{inc['incident_id']} no trae {faltantes}"


def test_los_campos_especificos_solo_aparecen_donde_corresponde(incidents):
    """`extras` evita que un incidente de phishing lleve puertos escaneados."""
    por_tipo = {i["classification"]["attack_type"]: i for i in incidents}

    scan = por_tipo["port_scan"]
    assert "scanned_ports" in scan and "target_hosts" in scan
    assert "phishing_urls" not in scan

    phish = por_tipo["credential_harvesting"]
    assert "phishing_urls" in phish
    assert "scanned_ports" not in phish

    auth = por_tipo["ssh_brute_force"]
    assert "scanned_ports" not in auth and "phishing_urls" not in auth


def test_la_dataclass_no_deja_campos_sin_inicializar():
    """Construir un `Incident` con lo mínimo produce un dict completo y usable."""
    from classifier import Incident

    incidente = Incident(
        incident_id="INC-X", source_ip="203.0.113.7",
        classification={"attack_type": "generic"}, recommended_actions=[],
        first_seen="2026-09-16T10:00:00+00:00", last_seen="2026-09-16T10:00:00+00:00",
        event_count=1,
    ).to_dict()

    assert incidente["attacker_ips"] == []
    assert incidente["victim_hosts"] == []
    assert incidente["mitre"] == {}
    assert incidente["analysis"] is None
    assert "extras" not in incidente, "`extras` se aplana, no se serializa como tal"
