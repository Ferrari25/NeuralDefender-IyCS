# Generador de queries en Kibana Query Language (KQL)

KQL filtra documentos en Kibana/Elasticsearch. Se usa en las reglas de detección y en Discover.

## Patrones del proyecto

```kql
# Fuerza bruta SSH (lo que dispara la regla Threshold)
tags:authentication_failure OR message:*Failed password* OR message:*authentication failure*

# Logins exitosos (para ver si la fuerza bruta tuvo éxito)
tags:authentication_success

# Usuario inválido (sondeo de cuentas)
tags:invalid_user OR message:*Invalid user*

# Tráfico de red sintético (port scan / phishing)
source_type:network_traffic
event_type:network_flow AND tags:port_scan
event_type:http_request AND credential_submission:true

# Acotar por IP / ventana
source_ip:172.18.0.7 AND @timestamp >= "now-24h"
```

## Buenas prácticas (voz del rule-engineer)
- Filtrar por `@timestamp` para limitar la ventana y el costo.
- Preferir `tags:` (campos keyword) sobre `message:*...*` (wildcards costosos) cuando exista el tag.
- Evitar wildcards al inicio (`*foo`): no usan el índice invertido.
