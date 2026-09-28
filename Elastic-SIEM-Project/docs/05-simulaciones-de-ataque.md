# 05 · Simulaciones de ataque

El proyecto contempla **tres tipos de ataque**, cada uno con su simulación, su
ruta de detección y su mapeo MITRE ATT&CK. Todas las simulaciones pueden correr
en **modo live** (con contenedores) o **`--offline`** (solo generan logs
detectables, sin Docker).

| Ataque | Script | Técnica MITRE | Ruta de detección |
|--------|--------|---------------|-------------------|
| SSH Brute Force | `simulation/run-brute-force.sh` | T1110 (Credential Access) | logs SSH → Logstash → regla *Threshold* en Kibana |
| Port Scan | `simulation/run-port-scan.sh` | T1046 (Discovery) | eventos de red en `network_logs/` → clasificador (umbral de puertos) |
| Phishing / captura de credenciales | `simulation/run-phishing.sh` | T1566 (Initial Access) | eventos web en `network_logs/` → clasificador (envío de credenciales) |

> **Por qué `network_logs/`:** este proyecto no despliega Suricata, así que los
> ataques de red/web se materializan como eventos NDJSON en `network_logs/`. Ese
> directorio es a la vez (a) la entrada `network-traffic` de Filebeat hacia
> Elasticsearch en modo live, y (b) lo que lee el clasificador en modo offline.
> Es el mismo punto de inyección que usaría un IDS real escribiendo eventos.

---

## 1. SSH Brute Force (T1110)

Un atacante prueba muchas contraseñas contra SSH hasta encontrar una válida. Cada
intento fallido deja un `Failed password ...` que el SIEM cuenta por IP.

**Live:**
```bash
docker compose --profile simulation up -d
bash simulation/run-brute-force.sh
```
El script crea un diccionario, descubre la IP del `ssh-target` y lanza Hydra
(`hydra -l testuser -P passwords.txt <ip> -s 2222 ssh`). Genera una ráfaga de
fallos de autenticación (y, con `testpassword` en el diccionario, termina en un
login exitoso). Dos reglas de Kibana pueden dispararse: *SSH Brute Force –
Aggressive per Source IP* (Threshold, agrupa por `source_ip.keyword`) y, si hubo
login exitoso después de los fallos, *SSH Successful Login After Brute Force*
(EQL, severidad Critical — compromiso confirmado). Ver
[07 · Reglas de detección](07-reglas-de-deteccion.md).

**Detección en la capa IA:** `classifier.py` agrupa los fallos por IP; si superan
el umbral (`BRUTE_FORCE_THRESHOLD = 20`) o hay técnica T1110 → `ssh_brute_force`.
Extrae además la IP real del atacante y el usuario objetivo del texto del log.

---

## 2. Port Scan (T1046)

Reconocimiento de red: el atacante sondea muchos puertos para mapear servicios
expuestos antes de atacar.

```bash
bash simulation/run-port-scan.sh            # genera logs + nmap real si hay contenedor
bash simulation/run-port-scan.sh --offline  # solo logs
```

Genera un evento por puerto en `network_logs/port-scan-<timestamp-unix>.json` — el nombre
lleva un timestamp único por corrida a propósito: Filebeat (input `filestream`) identifica
archivos por inodo, y truncar+reescribir siempre el mismo nombre puede dejar el offset
desincronizado y que una corrida no se ingiera. Con nombre nuevo cada vez no hay ambigüedad, y
de paso queda el historial de corridas anteriores.
```json
{"@timestamp":"...","event_type":"network_flow","source_ip":"172.18.0.7",
 "dest_ip":"172.18.0.5","dest_port":22,"protocol":"tcp","action":"probe",
 "tags":["network_traffic","port_scan"],"source_type":"network_traffic"}
```

**Detección:** `detect_port_scans()` agrupa por IP origen y cuenta puertos
**distintos**; si ≥ `PORT_SCAN_DISTINCT_PORTS = 10` → `port_scan`.

---

## 3. Phishing / captura de credenciales (T1566)

Una víctima envía sus credenciales a una página de login falsa.

```bash
bash simulation/run-phishing.sh             # genera logs + POST real si hay contenedor
bash simulation/run-phishing.sh --offline   # solo logs
```

Genera eventos en `network_logs/phishing-<timestamp-unix>.json` (mismo motivo del nombre
único que en port scan — ver arriba) con una visita GET y un POST con credenciales:
```json
{"@timestamp":"...","event_type":"http_request","source_ip":"172.18.0.9",
 "dest_ip":"172.18.0.8","http_method":"POST","url":"/login","username":"testuser",
 "credential_submission":true,"tags":["web","credential_submission"],
 "source_type":"network_traffic"}
```

**Detección:** `detect_phishing()` busca `http_request` con `credential_submission`
(o `password_submitted`) y agrupa por IP → `credential_harvesting`.

---

## Correr los tres y verlos en el dashboard

```bash
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
python3 siem_pipeline.py
python3 dashboard.py     # http://127.0.0.1:5000 → 3 incidentes (SSH, scan, phishing)
```

Evidencia real de una corrida completa (los 4 tipos de incidente activos a la vez, con
correlación de campaña): `screenshots/dashboard-overview.png` — ver
[09 · El dashboard, en detalle](09-dashboard.md).

## Extender con un ataque nuevo

1. Generar el log representativo (en `network_logs/` o como log que Filebeat ya
   recolecte).
2. Agregar una función `detect_<tipo>()` en `classifier.py` con su umbral, sus **factores de
   explicabilidad**, y un playbook en `_playbook()` (con `comando_explicacion` para cada
   comando sugerido).
3. Agregar la rama del fallback en `siem_agent.py` (`_fallback_analysis`).
4. Si el nuevo ataque también puede detectarse en Kibana (el evento llega a `filebeat-*`),
   sumar la regla correspondiente — ver [07](07-reglas-de-deteccion.md).
5. Documentar acá.

## Limpieza

```bash
rm -f network_logs/*.json                      # borra los logs sintéticos
docker compose --profile simulation down -v    # baja ssh-target / hydra-attacker
```
