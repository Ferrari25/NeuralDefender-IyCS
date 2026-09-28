# Conversor de reglas Sigma → formato Elastic

[Sigma](https://github.com/SigmaHQ/sigma) es un formato genérico de reglas de detección. Se
convierte a query de Elastic con `sigma convert -t lucene` (o el backend `elasticsearch`).

## Ejemplo: fuerza bruta SSH (la regla actual, como Sigma)

```yaml
title: SSH Brute Force
status: experimental
logsource:
  product: linux
  service: auth
detection:
  selection:
    message|contains: "Failed password"
  condition: selection | count() by host.ip > 3
  timeframe: 5m
fields:
  - source_ip
  - user
falsepositives:
  - Usuarios que olvidaron su contraseña y reintentaron
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## Detection-as-code (recomendación pendiente)
Hoy las reglas viven solo en la UI de Kibana. Conviene mantenerlas como Sigma/JSON versionado en el
repo y convertirlas/importarlas en el despliegue, para tener revisión y reproducibilidad. Ver un
ejemplo de regla exportada en `outputs/detection-rules/brute-force.example.json`.
