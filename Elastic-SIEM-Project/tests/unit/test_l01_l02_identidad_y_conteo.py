"""Regresión de **L-01, L-02 y L-04** — identidad del incidente y conteo de eventos.

Los tres eran el mismo problema visto desde tres ángulos, y por eso se
corrigieron juntos:

- **L-02 (identidad):** las alertas se agrupaban por `source_ip` (el atacante) y
  los logs por `host_ip` (la víctima). El mismo ataque producía dos incidentes
  con identidades incompatibles.
- **L-01 (conteo):** `if not inc["event_count"]: inc["event_count"] += 1`
  incrementaba una sola vez. El contador quedaba clavado en 1 y, con el umbral en
  20, **ningún incidente construido solo desde logs podía alcanzarlo jamás**.
- **L-04 (campañas):** al correlacionar por `source_ip`, un atacante quedaba
  vinculado con el host que estaba atacando, como si fueran dos frentes de una
  misma campaña.

Por separado cada corrección aporta poco: arreglar el contador sin la identidad
da dos incidentes bien contados en vez de uno; arreglar la identidad sin el
contador deja un incidente unificado que sigue sin alcanzar el umbral.

Reemplazan a los congelados `test_L01_*`, `test_L02_*` y `test_L04_*`.
"""

from __future__ import annotations

import classifier

# ─── L-02 · un ataque, un incidente ──────────────────────────────────────────

def test_un_ataque_produce_un_solo_incidente(siem_clean):
    """El ataque 172.18.0.3 → 172.18.0.7 ya no se parte en dos."""
    incs = classifier.detect_auth_incidents(siem_clean)
    assert len(incs) == 1

    inc = incs[0]
    assert inc["source_ip"] == "172.18.0.3", "la identidad es el ATACANTE"
    assert inc["attacker_ips"] == ["172.18.0.3"]
    assert inc["victim_hosts"] == ["172.18.0.7"], "el host atacado tiene su propio campo"


def test_atacante_y_victima_no_se_confunden(siem_clean):
    """Los dos roles viven en campos distintos y no se pisan.

    Es la invariante que hace que el resto del sistema pueda razonar: el
    playbook sabe a quién bloquear, y la correlación sabe a quién seguir.
    """
    inc = classifier.detect_auth_incidents(siem_clean)[0]
    atacantes = set(inc["attacker_ips"]) | {inc["source_ip"]}
    assert not (atacantes & set(inc["victim_hosts"]))


def test_el_incidente_unificado_conserva_toda_la_evidencia(siem_clean):
    """Unificar no puede perder datos: se juntan los de las dos fuentes."""
    inc = classifier.detect_auth_incidents(siem_clean)[0]
    assert inc["target_users"] == ["testuser"], "los usuarios venían por el lado de los logs"
    assert inc["rule_name"], "la regla del SIEM venía por el lado de las alertas"
    assert inc["risk_score"], "el risk_score venía por el lado de las alertas"
    assert len(inc["evidence"]) > 0
    assert len(inc["sample_messages"]) > 0


def test_un_log_sin_ip_de_atacante_no_se_atribuye_a_la_victima():
    """Si no se puede extraer el atacante, el incidente va al sentinela.

    Antes caía en el bucket de la víctima, que es peor que no saber: producía un
    incidente que señalaba al host atacado como origen del ataque.
    """
    datos = {"alerts": [], "auth_failure_logs": [{
        "timestamp": "2026-09-16T10:00:00.000Z",
        "message": "authentication failure; logname= uid=0 euid=0 tty=ssh",
        "host_ip": "172.18.0.7"}]}
    inc = classifier.detect_auth_incidents(datos)[0]
    assert inc["source_ip"] == "desconocida"
    assert inc["victim_hosts"] == ["172.18.0.7"]
    assert inc["attacker_ips"] == []


def test_dos_atacantes_distintos_siguen_siendo_dos_incidentes():
    """Unificar por atacante no puede colapsar ataques que sí son distintos."""
    logs = []
    for ip in ("203.0.113.10", "203.0.113.20"):
        logs += [{"timestamp": f"2026-09-16T10:{m:02d}:00.000Z",
                  "message": f"Failed password for testuser from {ip} port {40000+m} ssh2",
                  "host_ip": "172.18.0.7"} for m in range(5)]

    incs = classifier.detect_auth_incidents({"alerts": [], "auth_failure_logs": logs})
    assert len(incs) == 2
    assert sorted(i["source_ip"] for i in incs) == ["203.0.113.10", "203.0.113.20"]
    assert all(i["event_count"] == 5 for i in incs)


# ─── L-01 · el contador cuenta ───────────────────────────────────────────────

def test_cada_linea_de_log_es_un_evento(siem_clean):
    """12 logs reales ⇒ `log_event_count == 12` (antes valía 1)."""
    inc = classifier.detect_auth_incidents(siem_clean)[0]
    assert len(siem_clean["auth_failure_logs"]) == 12
    assert inc["log_event_count"] == 12


def test_sin_alerta_del_siem_el_volumen_alcanza_para_detectar(auth_25_sin_alerta):
    """25 fallos y ninguna alerta de Kibana ⇒ fuerza bruta.

    Es el agujero de detección que cerraba L-01: antes, un ataque de cualquier
    volumen se reportaba como 'suspicious_auth / media / requiere revisión
    manual' si Elastic no había disparado una regla.
    """
    incs = classifier.detect_auth_incidents(auth_25_sin_alerta)
    assert len(incs) == 1

    inc = incs[0]
    assert inc["event_count"] == 25
    assert inc["classification"]["attack_type"] == "ssh_brute_force"
    assert inc["classification"]["severity"] == "alta"
    assert inc["source_ip"] == "203.0.113.50"


def test_el_umbral_se_respeta_en_los_dos_bordes():
    """19 fallos ⇒ sospechoso; 20 ⇒ fuerza bruta. Ahora el umbral es alcanzable."""
    def datos(n):
        return {"alerts": [], "auth_failure_logs": [{
            "timestamp": f"2026-09-16T10:00:{s:02d}.000Z",
            "message": f"Failed password for testuser from 203.0.113.7 port {40000+s} ssh2",
            "host_ip": "172.18.0.7"} for s in range(n)]}

    bajo = classifier.detect_auth_incidents(datos(BORDE := classifier.BRUTE_FORCE_THRESHOLD - 1))[0]
    assert bajo["event_count"] == BORDE
    assert bajo["classification"]["attack_type"] == "suspicious_auth"

    justo = classifier.detect_auth_incidents(datos(classifier.BRUTE_FORCE_THRESHOLD))[0]
    assert justo["classification"]["attack_type"] == "ssh_brute_force"


def test_volumen_extremo_eleva_la_severidad_a_critica():
    logs = [{"timestamp": "2026-09-16T10:00:00.000Z",
             "message": "Failed password for testuser from 203.0.113.7 port 40000 ssh2",
             "host_ip": "172.18.0.7"}] * classifier.CRITICAL_FAILURE_COUNT
    inc = classifier.detect_auth_incidents({"alerts": [], "auth_failure_logs": logs})[0]
    assert inc["event_count"] == classifier.CRITICAL_FAILURE_COUNT
    assert inc["classification"]["severity"] == "critica"


def test_logs_y_alertas_no_se_suman_dos_veces(siem_clean):
    """Los dos conteos describen el mismo ataque: se toma el máximo, no la suma.

    `prepare-for-ia.py` trae una muestra acotada de logs (size=20) mientras la
    regla threshold cuenta todo lo que vio Elasticsearch. Sumarlos inflaría la
    severidad contando dos veces los mismos intentos.
    """
    inc = classifier.detect_auth_incidents(siem_clean)[0]
    assert inc["log_event_count"] == 12
    assert inc["alert_event_count"] == 3
    assert inc["event_count"] == 12, "máximo, no 15"


def test_el_conteo_del_siem_gana_cuando_es_mayor():
    """Si la alerta vio más eventos que los logs muestreados, manda la alerta."""
    datos = {
        "alerts": [{"timestamp": "2026-09-16T10:00:00.000Z", "source_ip": "203.0.113.7",
                    "rule_name": "SSH Brute Force", "severity": "high", "risk_score": 73,
                    "event_count": 5000,
                    "mitre": {"technique_id": "T1110", "tactic": "Credential Access",
                              "technique": "Brute Force"}}],
        "auth_failure_logs": [{
            "timestamp": "2026-09-16T10:00:00.000Z",
            "message": "Failed password for testuser from 203.0.113.7 port 40000 ssh2",
            "host_ip": "172.18.0.7"}],
    }
    inc = classifier.detect_auth_incidents(datos)[0]
    assert inc["event_count"] == 5000
    assert inc["classification"]["severity"] == "critica"


# ─── L-04 · campañas solo por IP de atacante ─────────────────────────────────

def test_una_victima_compartida_no_crea_una_campana(incidents):
    """El port scan de 172.18.0.7 ya no 'comparte campaña' con su víctima.

    172.18.0.7 es el atacante del escaneo y el host atacado por SSH. Antes,
    correlacionar por `source_ip` los unía en una campaña inexistente.
    """
    assert all(i["campaign_id"] is None for i in incidents)
    assert all(i["related_incidents"] == [] for i in incidents)


def test_un_atacante_en_dos_frentes_si_forma_campana():
    """La correlación que sí importa sigue funcionando: misma IP, dos ataques."""
    scan = [{"event_type": "network_flow", "source_ip": "203.0.113.9",
             "dest_ip": "10.0.0.5", "dest_port": p,
             "@timestamp": "2026-09-16T09:00:00.000Z"} for p in range(1, 15)]
    auth = {"alerts": [], "auth_failure_logs": [{
        "timestamp": f"2026-09-16T10:{m:02d}:00.000Z",
        "message": f"Failed password for testuser from 203.0.113.9 port {40000+m} ssh2",
        "host_ip": "10.0.0.5"} for m in range(25)]}

    incs = classifier.classify(auth, scan)
    assert len(incs) == 2
    campanas = {i["campaign_id"] for i in incs}
    assert len(campanas) == 1 and None not in campanas
    for inc in incs:
        assert inc["campaign_shared_ips"] == ["203.0.113.9"]
        assert len(inc["related_incidents"]) == 1


def test_la_campana_nunca_se_arma_con_el_sentinela():
    """Dos incidentes sin IP identificable no son la misma campaña."""
    eventos = [{"event_type": "http_request", "source_ip": "no-es-ip",
                "dest_ip": None, "url": "/login", "username": "bob",
                "credential_submission": True,
                "@timestamp": "2026-09-16T10:00:00.000Z"}]
    incs = classifier.classify({}, eventos)
    assert all(i["campaign_id"] is None for i in incs)


# ─── Efecto sobre el playbook ────────────────────────────────────────────────

def test_el_playbook_bloquea_al_atacante_no_a_la_victima(siem_clean):
    """La consecuencia práctica de L-02: a quién apunta el `ufw deny`."""
    inc = classifier.detect_auth_incidents(siem_clean)[0]
    comandos = [a["comando_sugerido"] for a in inc["recommended_actions"]
                if a.get("comando_sugerido")]

    assert "sudo ufw deny from 172.18.0.3" in comandos
    assert not any("172.18.0.7" in c for c in comandos), \
        "bloquear al host atacado cortaría un servicio legítimo"
    assert any("sudo passwd testuser" in c for c in comandos)
