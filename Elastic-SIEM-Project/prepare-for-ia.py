#!/usr/bin/env python3
"""
Extrae y limpia datos del SIEM (alertas + logs de auth fallida) dentro de una
ventana temporal, agrega por IP, y genera `siem_clean.json` para el Agente 1.

Si Elasticsearch no está accesible, NO sobreescribe el archivo existente: así no
se pierde la última captura buena (útil para demos con el stack apagado).
"""

from __future__ import annotations

import sys

from siem_lib import (
    ALERTS_INDEX,
    ES_HOST,
    LOGS_INDEX,
    ESUnavailable,
    alerts_query_por_regla,
    auth_failure_query,
    es_aggregate,
    es_search,
    es_search_por_grupo,
    now_iso,
    rol_del_campo_agrupado,
    source_ip_aggregation,
    write_json,
)

OUTPUT_FILE = "siem_clean.json"
WINDOW = "24h"   # ventana temporal de análisis


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


def main() -> None:
    print(f"Extrayendo datos del SIEM (ventana: {WINDOW}) desde {ES_HOST} ...")
    try:
        # Agrupadas POR REGLA: una regla ruidosa no puede tapar a las demás.
        # Con `size=10` a secas, 96 alertas de una sola regla dejaban afuera a
        # las otras siete —incluida la crítica de login exitoso tras fuerza
        # bruta—. Ver siem_lib.alerts_query_por_regla.
        alerts     = parse_alerts(es_search_por_grupo(
            ALERTS_INDEX, alerts_query_por_regla(por_regla=5, window=WINDOW)))
        logs       = parse_logs(es_search(LOGS_INDEX, auth_failure_query(size=20, window=WINDOW)))
        ip_buckets = es_aggregate(LOGS_INDEX, source_ip_aggregation(WINDOW), "by_source_ip")
    except ESUnavailable as e:
        print(f"[ERROR] {e}")
        print(f"[INFO] No se sobreescribe '{OUTPUT_FILE}' para preservar la última captura.")
        sys.exit(1)

    summary = build_summary(alerts, logs, ip_buckets)
    output = {
        "generated_at": now_iso(),
        "context": "Elastic SIEM - Análisis de seguridad automatizado",
        "summary": summary,
        "alerts": alerts,
        "auth_failure_logs": logs,
    }
    write_json(OUTPUT_FILE, output)

    print(f"\n{'='*50}\n  RESUMEN\n{'='*50}")
    print(f"  Alertas de seguridad : {summary['total_alerts']}")
    print(f"  Alertas activas      : {summary['active_alerts']}")
    print(f"  Severidad alta       : {summary['high_severity']}")
    print(f"  Logs auth fallida    : {summary['total_auth_failures']}")
    print(f"  IPs origen (top)     : {list(summary['top_source_ips'].keys())}")
    print(f"  Técnicas MITRE       : {summary['mitre_techniques']}")
    print(f"\n[OK] JSON limpio guardado en '{OUTPUT_FILE}'.")


if __name__ == "__main__":
    main()
