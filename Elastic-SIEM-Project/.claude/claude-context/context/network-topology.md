# Topología de red y activos

Todo corre en la red Docker bridge **`elastic-net`** (rango típico `172.18.0.0/16`).

## Servicios y puertos (publicados en `127.0.0.1`, no en la LAN)

| Servicio | Puerto host | Rol |
|----------|-------------|-----|
| elasticsearch | 9200 | Almacén + API REST (activo crítico: contiene todos los eventos) |
| kibana | 5601 | UI del SIEM |
| logstash | 5044 / 9600 | Ingesta beats / API de monitoreo |
| ssh-target *(simulación)* | 2222 | Servidor SSH víctima |
| dashboard.py | 5000 | GUI de supervisión humana |

## Direcciones que aparecen en los datos/simulaciones

| IP | Quién |
|----|-------|
| `172.18.0.5` | host objetivo (donde corre el `ssh-target`; IP de origen de las alertas Threshold) |
| `172.18.0.7` | atacante (Hydra brute force, nmap port scan) |
| `172.18.0.8` | servidor de phishing (página falsa) |
| `172.18.0.9` | víctima que envía credenciales |

## Activos críticos
- **Elasticsearch:** concentra toda la evidencia. Su compromiso = pérdida de visibilidad y de logs.
- **Credenciales del stack:** `elastic` / `kibana_system` (en `.env`, nunca en Git).

## Clasificación de IPs en el pipeline
Las IPs privadas (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`) se saltan el `geoip` en
Logstash. En un despliegue real, las IPs atacantes serían públicas y sí tendrían enriquecimiento geo.
