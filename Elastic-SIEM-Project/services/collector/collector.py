#!/usr/bin/env python3
"""
Extracción del SIEM (antes `prepare-for-ia.py`): alertas + logs de auth fallida
dentro de una ventana temporal, agregados por IP. El resultado es la "captura"
que el servicio collector guarda en `data/siem_clean.json` y le entrega al
clasificador (Agente 1).

Si Elasticsearch no está accesible, NO se sobreescribe la captura existente: así
no se pierde la última buena (útil para demos con el stack apagado).
"""

from __future__ import annotations

from es_client import (
    ALERTS_INDEX,
    ES_HOST,
    LOGS_INDEX,
    alerts_query_por_regla,
    auth_failure_query,
    es_aggregate,
    es_search,
    es_search_por_grupo,
    rol_del_campo_agrupado,
    source_ip_aggregation,
)
from siem_lib import now_iso, ventana_de_analisis

OUTPUT_FILE = "data/siem_clean.json"
WINDOW = ventana_de_analisis()   # ventana temporal de análisis (SIEM_VENTANA)


def parse_alerts(hits: list[dict]) -> list[dict]:
    alerts = []
    for h in hits:
        s = h["_source"]
        threshold = s.get("kibana.alert.threshold_result", {})
        terms = threshold.get("terms") or []

        # Qué representa el valor por el que agrupó la regla. Antes se tomaba
        # `terms[0].value` y se lo guardaba SIEMPRE como `source_ip`, tirando el
        # nombre del campo: una regla que agrupa por `host.ip` (la máquina
        # atacada) terminaba declarando a la víctima como atacante.
        campo = terms[0].get("field") if terms else None
        valor = terms[0].get("value") if terms else None
        rol = rol_del_campo_agrupado(campo)

        # Reglas EQL y de consulta no tienen threshold_result, pero copian el
        # campo original del evento al nivel superior del documento de alerta.
        ip_atacante = valor if rol == "atacante" else (None if terms else s.get("source_ip"))
        host_victima = valor if rol == "victima" else None
        usuario = valor if rol == "usuario" else None
        # threat/technique pueden venir vacíos si la regla no tiene mapeo MITRE.
        threat_list = s.get("kibana.alert.rule.threat") or []
        threat0 = threat_list[0] if threat_list else {}
        tech_list = threat0.get("technique") or []
        tech0 = tech_list[0] if tech_list else {}
        alerts.append({
            "type":        "security_alert",
            "timestamp":   s.get("@timestamp"),
            "alert_id":    (s.get("kibana.alert.uuid", "") or "")[:16] + "...",
            "rule_name":   s.get("kibana.alert.rule.name"),
            "severity":    s.get("kibana.alert.severity"),
            "risk_score":  s.get("kibana.alert.risk_score"),
            "status":      s.get("kibana.alert.status"),
            "reason":      s.get("kibana.alert.reason"),
            # `source_ip` solo se completa cuando el valor agrupado REPRESENTA al
            # atacante. Si la regla agrupó por host, va a `victim_host` y el
            # atacante queda sin identificar — que es la verdad, no un valor
            # inventado.
            "source_ip":     ip_atacante,
            "victim_host":   host_victima,
            "target_user":   usuario,
            # Se conserva por qué campo agrupó, para poder auditar la decisión.
            "grouped_by":    campo,
            "event_count": threshold.get("count"),
            "time_window": {"from": threshold.get("from"), "to": s.get("@timestamp")},
            "mitre": {
                "tactic":       threat0.get("tactic", {}).get("name"),
                "technique":    tech0.get("name"),
                "technique_id": tech0.get("id"),
            },
            "false_positives": s.get("kibana.alert.rule.false_positives", []),
            "rule_query":      s.get("kibana.alert.rule.parameters", {}).get("query"),
        })
    return alerts


def parse_logs(hits: list[dict]) -> list[dict]:
    logs = []
    for h in hits:
        s = h["_source"]
        logs.append({
            "type":        "auth_failure_log",
            "timestamp":   s.get("@timestamp"),
            "message":     s.get("message"),
            "host_ip":     (s.get("host", {}).get("ip") or [None])[0]
                            if isinstance(s.get("host", {}).get("ip"), list)
                            else s.get("host", {}).get("ip"),
            "host_name":   s.get("host", {}).get("name"),
            "log_file":    s.get("log", {}).get("file", {}).get("path"),
            "tags":        s.get("tags", []),
            "source_type": s.get("fields", {}).get("source_type"),
        })
    return logs


def build_summary(alerts: list[dict], logs: list[dict], ip_buckets: list[dict]) -> dict:
    return {
        "total_alerts":        len(alerts),
        "total_auth_failures": len(logs),
        "active_alerts":       sum(1 for a in alerts if a.get("status") == "active"),
        "high_severity":       sum(1 for a in alerts if a.get("severity") == "high"),
        "window":              WINDOW,
        # Historial por IP (agregación de ES) — base del contexto "IP en 24h".
        "top_source_ips":      {b["key"]: b["doc_count"] for b in ip_buckets},
        "mitre_techniques":    sorted({a["mitre"]["technique_id"] for a in alerts
                                       if a.get("mitre", {}).get("technique_id")}),
    }


def capturar(window: str = WINDOW) -> dict:
    """Consulta Elasticsearch y arma la captura. Lanza `ESUnavailable` si no puede.

    Agrupadas POR REGLA: una regla ruidosa no puede tapar a las demás. Con
    `size=10` a secas, 96 alertas de una sola regla dejaban afuera a las otras
    siete —incluida la crítica de login exitoso tras fuerza bruta—. Ver
    es_client.alerts_query_por_regla.
    """
    print(f"Extrayendo datos del SIEM (ventana: {window}) desde {ES_HOST} ...")
    alerts     = parse_alerts(es_search_por_grupo(
        ALERTS_INDEX, alerts_query_por_regla(por_regla=5, window=window)))
    logs       = parse_logs(es_search(LOGS_INDEX, auth_failure_query(size=20, window=window)))
    ip_buckets = es_aggregate(LOGS_INDEX, source_ip_aggregation(window), "by_source_ip")

    summary = build_summary(alerts, logs, ip_buckets)
    print(f"  Alertas: {summary['total_alerts']} ({summary['active_alerts']} activas, "
          f"{summary['high_severity']} altas) · logs de auth fallida: "
          f"{summary['total_auth_failures']} · técnicas: {summary['mitre_techniques']}")
    return {
        "generated_at": now_iso(),
        "context": "Elastic SIEM - Análisis de seguridad automatizado",
        "summary": summary,
        "alerts": alerts,
        "auth_failure_logs": logs,
    }
