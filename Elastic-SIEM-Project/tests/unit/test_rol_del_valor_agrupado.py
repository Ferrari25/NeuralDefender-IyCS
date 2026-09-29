"""Atacante y víctima en el camino de las ALERTAS (defecto **D-02**).

Encontrado el 25-09-2026 verificando el script de demostración.

Una alerta de tipo *threshold* trae en `threshold_result.terms[0]` el **campo** y
el **valor** por los que agrupó. `prepare-for-ia.py` tomaba el valor y tiraba el
campo:

```python
"source_ip": terms[0].get("value") if terms else s.get("source_ip"),
```

Así, la regla A1 —que agrupa por `host.ip`, o sea por la máquina **atacada**—
producía un incidente que declaraba a la víctima como atacante: *"fuerza bruta,
severidad alta, 31 eventos"* desde una IP que nunca atacó nada, sin víctimas y
sin usuarios.

Es el mismo error que el hallazgo **L-02**, que confundía atacante con víctima en
el camino de los **logs**. Lo arreglamos ahí y quedó abierto acá.

La corrección no elige entre las dos lentes de detección —"esta IP ataca" y "este
host está siendo atacado" son preguntas distintas y las dos valen—: deja de
descartar el dato que ya dice cuál es cuál.
"""

from __future__ import annotations

import pytest

import classifier
import siem_lib

# ─── El mapeo de campo a rol ─────────────────────────────────────────────────

@pytest.mark.parametrize("campo,esperado", [
    ("source_ip.keyword", "atacante"),
    ("source_ip", "atacante"),
    ("host.ip.keyword", "victima"),
    ("host.ip", "victima"),
    ("host.name.keyword", "victima"),
    ("user.keyword", "usuario"),
])
def test_reconoce_el_rol_del_campo(campo, esperado):
    assert siem_lib.rol_del_campo_agrupado(campo) == esperado


@pytest.mark.parametrize("campo", [
    "dest_ip.keyword", "dest_port", "url.keyword", "campo.inventado",
    None, "", 42, [],
])
def test_un_campo_desconocido_no_se_interpreta(campo):
    """Ante la duda, no se asume: mejor sin atribución que con una falsa."""
    assert siem_lib.rol_del_campo_agrupado(campo) is None


def test_el_sufijo_keyword_es_indiferente():
    """Es el mismo campo lógico; las reglas usan `.keyword` por el mapeo."""
    assert (siem_lib.rol_del_campo_agrupado("source_ip")
            == siem_lib.rol_del_campo_agrupado("source_ip.keyword"))


# ─── El parseo de la alerta ──────────────────────────────────────────────────

def _alerta(regla: str, campo: str | None, valor: str | None,
            tecnica: str = "T1110", conteo: int = 5) -> dict:
    """Arma un documento de alerta como lo devuelve Elastic Security."""
    fuente = {
        "@timestamp": "2026-09-25T12:00:00.000Z",
        "kibana.alert.uuid": "abc123",
        "kibana.alert.rule.name": regla,
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 73,
        "kibana.alert.rule.threat": [{
            "tactic": {"name": "Credential Access"},
            "technique": [{"id": tecnica, "name": "Brute Force"}],
        }],
    }
    if campo is not None:
        fuente["kibana.alert.threshold_result"] = {
            "count": conteo, "from": "2026-09-25T11:55:00.000Z",
            "terms": [{"field": campo, "value": valor}],
        }
    return {"_source": fuente}


def _parse(hits):
    import importlib.util
    import pathlib
    ruta = pathlib.Path(__file__).resolve().parent.parent.parent / "src" / "prepare-for-ia.py"
    spec = importlib.util.spec_from_file_location("prepare_for_ia", ruta)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo.parse_alerts(hits)


def test_una_regla_agrupada_por_ip_de_origen_da_un_atacante():
    alerta = _parse([_alerta("SSH Brute Force – Aggressive per Source IP",
                             "source_ip.keyword", "203.0.113.7")])[0]

    assert alerta["source_ip"] == "203.0.113.7"
    assert alerta["victim_host"] is None
    assert alerta["grouped_by"] == "source_ip.keyword"


def test_una_regla_agrupada_por_host_da_una_VICTIMA_no_un_atacante():
    """**El defecto D-02, en una prueba.**

    A1 agrupa por `host.ip`: el valor es la máquina atacada. Antes terminaba en
    `source_ip` y el sistema la acusaba de ser el origen del ataque.
    """
    alerta = _parse([_alerta("SSH Brute Force – Basic Threshold",
                             "host.ip.keyword", "172.18.0.3")])[0]

    assert alerta["victim_host"] == "172.18.0.3"
    assert alerta["source_ip"] is None, (
        "el host atacado quedó declarado como atacante")


def test_una_regla_agrupada_por_usuario_da_un_usuario():
    alerta = _parse([_alerta("SSH Brute Force – Multiple Users Targeted",
                             "user.keyword", "testuser")])[0]

    assert alerta["target_user"] == "testuser"
    assert alerta["source_ip"] is None
    assert alerta["victim_host"] is None


def test_una_regla_eql_sigue_usando_el_source_ip_del_evento():
    """Las reglas EQL y de consulta no tienen `threshold_result`, pero copian el
    campo del evento al nivel superior del documento."""
    hit = _alerta("SSH Successful Login After Brute Force", None, None)
    hit["_source"]["source_ip"] = "203.0.113.9"

    alerta = _parse([hit])[0]
    assert alerta["source_ip"] == "203.0.113.9"
    assert alerta["grouped_by"] is None


def test_un_campo_de_agrupacion_desconocido_no_inventa_atribucion():
    alerta = _parse([_alerta("Regla rara", "dest_ip.keyword", "10.0.0.5")])[0]

    assert alerta["source_ip"] is None
    assert alerta["victim_host"] is None
    assert alerta["target_user"] is None
    assert alerta["grouped_by"] == "dest_ip.keyword", "se conserva para auditar"


def test_el_conteo_de_la_alerta_se_conserva_siempre():
    """Aunque no se pueda atribuir un atacante, el volumen sigue siendo señal."""
    alerta = _parse([_alerta("SSH Brute Force – Basic Threshold",
                             "host.ip.keyword", "172.18.0.3", conteo=31)])[0]
    assert alerta["event_count"] == 31


# ─── El clasificador ─────────────────────────────────────────────────────────

def test_una_alerta_centrada_en_la_victima_no_crea_un_atacante_falso():
    """El incidente queda sin atacante identificado, que es la verdad."""
    datos = {"alerts": [{
        "timestamp": "2026-09-25T12:00:00.000Z",
        "rule_name": "SSH Brute Force – Basic Threshold",
        "severity": "medium", "risk_score": 47, "event_count": 31,
        "source_ip": None, "victim_host": "172.18.0.3", "target_user": None,
        "grouped_by": "host.ip.keyword",
        "mitre": {"technique_id": "T1110", "tactic": "Credential Access",
                  "technique": "Brute Force"},
    }], "auth_failure_logs": []}

    incs = classifier.detect_auth_incidents(datos)
    assert len(incs) == 1

    inc = incs[0]
    assert inc["source_ip"] == "desconocida", "se atribuyó un atacante inexistente"
    assert inc["attacker_ips"] == []
    assert inc["victim_hosts"] == ["172.18.0.3"], "la víctima sí se registra"
    assert inc["event_count"] == 31, "el volumen se conserva"


def test_no_se_sugiere_bloquear_al_host_atacado():
    """La consecuencia práctica: `ufw deny` contra la víctima cortaría un
    servicio legítimo. Es el falso positivo con consecuencias reales que el
    proyecto entero busca evitar."""
    datos = {"alerts": [{
        "timestamp": "2026-09-25T12:00:00.000Z",
        "rule_name": "SSH Brute Force – Basic Threshold",
        "severity": "medium", "risk_score": 47, "event_count": 31,
        "source_ip": None, "victim_host": "172.18.0.3", "grouped_by": "host.ip.keyword",
        "mitre": {"technique_id": "T1110"},
    }], "auth_failure_logs": []}

    inc = classifier.detect_auth_incidents(datos)[0]
    for accion in inc["recommended_actions"]:
        cmd = accion.get("comando_sugerido") or ""
        assert "172.18.0.3" not in cmd


def test_una_alerta_centrada_en_el_atacante_sigue_funcionando():
    datos = {"alerts": [{
        "timestamp": "2026-09-25T12:00:00.000Z",
        "rule_name": "SSH Brute Force – Aggressive per Source IP",
        "severity": "high", "risk_score": 73, "event_count": 24,
        "source_ip": "203.0.113.7", "victim_host": None,
        "grouped_by": "source_ip.keyword",
        "mitre": {"technique_id": "T1110"},
    }], "auth_failure_logs": []}

    inc = classifier.detect_auth_incidents(datos)[0]
    assert inc["source_ip"] == "203.0.113.7"
    assert inc["attacker_ips"] == ["203.0.113.7"]
    assert any("ufw deny from 203.0.113.7" in (a.get("comando_sugerido") or "")
               for a in inc["recommended_actions"])


def test_las_dos_lentes_conviven_en_el_mismo_analisis():
    """A1 (víctima) y A2 (atacante) sobre el MISMO ataque: dos incidentes, cada
    uno diciendo lo que sabe, sin contaminarse."""
    datos = {"alerts": [
        {"timestamp": "2026-09-25T12:00:00.000Z",
         "rule_name": "SSH Brute Force – Aggressive per Source IP",
         "severity": "high", "risk_score": 73, "event_count": 24,
         "source_ip": "203.0.113.7", "victim_host": None,
         "grouped_by": "source_ip.keyword", "mitre": {"technique_id": "T1110"}},
        {"timestamp": "2026-09-25T12:01:00.000Z",
         "rule_name": "SSH Brute Force – Basic Threshold",
         "severity": "medium", "risk_score": 47, "event_count": 31,
         "source_ip": None, "victim_host": "10.0.0.5",
         "grouped_by": "host.ip.keyword", "mitre": {"technique_id": "T1110"}},
    ], "auth_failure_logs": []}

    incs = {i["source_ip"]: i for i in classifier.detect_auth_incidents(datos)}

    assert set(incs) == {"203.0.113.7", "desconocida"}
    assert incs["203.0.113.7"]["attacker_ips"] == ["203.0.113.7"]
    assert incs["desconocida"]["victim_hosts"] == ["10.0.0.5"]
    assert incs["desconocida"]["attacker_ips"] == []


def test_una_alerta_aporta_el_usuario_objetivo():
    """A6 agrupa por `user`: el valor es a quién atacaron."""
    datos = {"alerts": [{
        "timestamp": "2026-09-25T12:00:00.000Z",
        "rule_name": "SSH Brute Force – Multiple Users Targeted",
        "severity": "high", "risk_score": 70, "event_count": 5,
        "source_ip": None, "victim_host": None, "target_user": "testuser",
        "grouped_by": "user.keyword", "mitre": {"technique_id": "T1110"},
    }], "auth_failure_logs": []}

    inc = classifier.detect_auth_incidents(datos)[0]
    assert inc["target_users"] == ["testuser"]


def test_un_valor_hostil_en_la_alerta_se_valida_igual():
    """Viene de Elasticsearch, que ingiere logs: sigue siendo dato no confiable."""
    datos = {"alerts": [{
        "timestamp": "2026-09-25T12:00:00.000Z",
        "rule_name": "Regla", "severity": "high", "risk_score": 73, "event_count": 1,
        "source_ip": "x; rm -rf /", "victim_host": "'; DROP TABLE --",
        "target_user": "bob && curl evil", "grouped_by": "source_ip.keyword",
        "mitre": {"technique_id": "T1110"},
    }], "auth_failure_logs": []}

    inc = classifier.detect_auth_incidents(datos)[0]
    assert inc["source_ip"] == "desconocida"
    assert inc["victim_hosts"] == []
    assert inc["target_users"] == []


# ─── Blindaje ────────────────────────────────────────────────────────────────

def test_prepare_for_ia_no_vuelve_a_tirar_el_campo_agrupado():
    """Si alguien restaura `terms[0].value` como `source_ip`, el defecto vuelve."""
    import pathlib

    fuente = (pathlib.Path(__file__).resolve().parent.parent.parent
              / "src" / "prepare-for-ia.py").read_text(encoding="utf-8")

    assert "rol_del_campo_agrupado" in fuente
    assert '"victim_host"' in fuente
    assert '"source_ip":   terms[0].get("value")' not in fuente, (
        "volvió a tomarse el valor agrupado como atacante sin mirar el campo")
