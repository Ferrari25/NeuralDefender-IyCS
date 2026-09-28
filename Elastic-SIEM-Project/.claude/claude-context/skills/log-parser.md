# Parsing de logs (grok / regex)

Referencia de los patrones que normalizan los logs crudos en este proyecto.

## Logstash grok (`logstash/pipeline/beats.conf`)

```
# Línea de syslog/auth completa (con overwrite para no duplicar `message`)
%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}

# Extracción de auth SSH
Failed password for %{USERNAME:user} from %{IP:source_ip}
Accepted password for %{USERNAME:user} from %{IP:source_ip}
Invalid user %{USERNAME:user} from %{IP:source_ip}
```

Notas clave: `overwrite => ["message"]` evita que `message` se vuelva array; el filtro `date`
mueve el `timestamp` parseado a `@timestamp`; `geoip` solo corre en IPs públicas (las privadas se
descartan con `cidr`).

## Regex en Python (`classifier.py`)

```python
_FROM_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")  # IP real del atacante
_USER_RE    = re.compile(r"for (?:invalid user )?(\w+)")      # usuario objetivo
```

## Logs de red/web (NDJSON, sin grok)
Los eventos de `network_logs/*.json` ya vienen estructurados (un objeto por línea), así que Filebeat
los parsea con el parser `ndjson` y no requieren grok. Campos: `event_type`, `source_ip`,
`dest_ip`, `dest_port`, `url`, `credential_submission`.
