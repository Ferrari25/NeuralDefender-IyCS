# Fuentes de log del proyecto

Qué logs entran al SIEM y por dónde (lo configura `filebeat/filebeat.yml`).

| Fuente | Input Filebeat | Contenido | `source_type` |
|--------|----------------|-----------|---------------|
| Logs de contenedores Docker | `container` (`/var/lib/docker/containers/*/*.log`) | Incluye el `ssh-target` (auth SSH) | — |
| Logs de sistema del host | `filestream` (`/var/log/auth.log`, `syslog`, `messages`) | Autenticación, eventos de sistema | `system_logs` |
| Tráfico de red / web sintético | `filestream` ndjson (`network_logs/*.json`) | Port scan, phishing (generados por las simulaciones / un IDS) | `network_traffic` |

## Notas
- Los paths están **acotados**: no se ingiere todo `/var/log/*.log`. El ruido GPU/Xorg se descarta
  con `drop_event` en ingesta.
- `network_logs/` es a la vez la entrada live (Filebeat → ES) y la fuente offline que lee
  `classifier.py`. Es el punto donde un IDS real (ej. Suricata) escribiría eventos de red.
- Índice destino en ES: `filebeat-<versión>-YYYY.MM.dd`. Alertas: `.alerts-security.alerts-default`.

## Fuentes futuras (del diseño en el Second Brain, aún no implementadas)
Suricata (eventos de red reales), Auditd (syscalls), Winlogbeat (Windows), CloudTrail (AWS).
