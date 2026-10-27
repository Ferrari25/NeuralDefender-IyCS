# 01 · Instalación, uso y simulaciones

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).

## Instalación

La guía completa de instalación desde cero — en un equipo que nunca vio este
proyecto, con todos los comandos, cómo generar cada secreto y la API de
Gemini — está en **[`nicotito.md`](../nicotito.md)**, en la raíz del
repositorio. No se repite acá para no tener dos versiones que se desactualicen
en paralelo.

Resumen de un vistazo, una vez que `.env` está configurado:

```bash
./scripts/start.sh                                   # stack Elastic + 14 reglas + microservicios
./scripts/siem.sh usuarios crear ana --rol analyst   # primer usuario, una vez
./scripts/siem.sh pipeline                           # extrae → clasifica → analiza
# → http://127.0.0.1:5000/login
```

La capa IA son ocho microservicios en Docker (ver
[00 §Microservicios](00-arquitectura.md#microservicios-de-la-capa-ia)). No hace
falta instalar dependencias Python en el host para correr el sistema: cada
imagen trae las suyas. `.devtools/` solo se usa para las pruebas y los linters.

## Uso y ejecución

### Pipeline completo (un comando)

```bash
./scripts/siem.sh pipeline
```

El servicio **pipeline** ya corre un ciclo solo cada 2 minutos
(`SIEM_PIPELINE_INTERVALO`, ver `.env.example`); este comando fuerza uno en el
momento. Le pide un ciclo al servicio **pipeline**, que encadena por HTTP:
**collector** (extrae de Elasticsearch → `data/collector/siem_clean.json`; si ES
no responde, **no pisa** la captura y el ciclo sigue con la última),
**classifier** (Agente 1), **analyst** (Agente 2) y **audit** (registra la
corrida en `data/audit/analysis_history.jsonl`). El reporte queda en
`data/pipeline/siem_incidents.json`. El CLI muestra el estado de cada etapa.

### Herramientas de cada servicio

Corren dentro del contenedor del servicio dueño de los datos:

```bash
./scripts/siem.sh usuarios listar     # servicio auth
./scripts/siem.sh auditoria           # servicio audit: verifica la cadena de hashes
./scripts/siem.sh cobertura           # servicio collector: SIEM ↔ panel
./scripts/siem.sh logs-es             # servicio collector: inspección ad-hoc de ES
./scripts/siem.sh estado              # estado de los contenedores de la capa IA
docker compose logs -f pipeline       # salida de cada etapa del ciclo
```

### El dashboard

Lo sirve el servicio **gateway**, que `start.sh` ya levanta:

```bash
docker compose up -d gateway   # (si hiciera falta levantarlo solo; trae sus dependencias)
# abrir http://127.0.0.1:5000/login
```

Guía completa panel por panel en [02 · Reglas y dashboard](02-reglas-y-dashboard.md#el-dashboard-de-supervisión).

**Qué pasa cuando decidís.** Cada click hace que el gateway le pida al
servicio **audit** que agregue una línea a `data/audit/decisions.jsonl`
(append-only e inmutable, firmada con el usuario de la sesión) con timestamp,
incidente, acción, decisión y nota opcional. El estado se reconstruye haciendo
*replay* de ese log, así que reiniciar cualquier servicio no pierde las
decisiones. El dashboard se refresca solo cada 15 s.

Cada decisión también se guarda como **caso** en la memoria del Agente 2
(servicio **knowledge**, `data/knowledge/casos.json`). Cuando un patrón se
repite, el agente propone una lección que hay que aprobar a mano. Cómo
funciona y dónde verlo: [05 · El "Gem"](05-gem-memoria-del-agente.md).

**Endpoints principales:**

| Método | Ruta | Qué hace |
|--------|------|----------|
| GET | `/api/v1/incidents` | Incidentes con el estado actual de cada acción. |
| POST | `/api/v1/decision` | Registra una decisión `{incident_id, action_id, decision, note}`. |
| GET | `/api/v1/decisions` | Historial completo de decisiones (auditoría). |
| GET | `/api/v1/audit/verify` | Verifica la cadena de hash del registro. |

### El LLM (Agente 2)

- Modelo por defecto: `gemini-flash-lite-latest` (alias — Google lo reapunta
  al flash-lite vigente, así no queda fijo a una versión que discontinúe).
  Salida estructurada (JSON) directa.
- **Interruptor de costo:** además de `GEMINI_API_KEY`, hace falta
  `SIEM_USE_LLM=true` en `.env` — apagado por defecto, para poder dejar la key
  guardada sin gastar tokens hasta activarla a propósito.
- Si no hay key, el interruptor está apagado, o la API falla (cuota/red), cada
  incidente cae al análisis determinístico. El campo `analyst_mode` y el
  banner en cada card indican qué se usó.
- Mitigación de inyección de prompt: los datos del log se marcan como **no
  confiables** por system instruction y se entregan delimitados; el LLM nunca
  genera comandos (esos vienen del playbook del Agente 1).

### Modo offline: solo la capa IA, sin el stack Elastic

```bash
docker compose up -d --build gateway     # los 8 microservicios, sin Elasticsearch
bash simulation/run-brute-force.sh --offline
bash simulation/run-port-scan.sh   --offline
bash simulation/run-phishing.sh    --offline
./scripts/siem.sh pipeline               # → http://127.0.0.1:5000
```

Sin Elasticsearch, el collector responde 503 y el ciclo lo informa
(`collector sin_captura`) y sigue clasificando desde `network_logs/`. El
Agente 2 usa el fallback determinístico. Las simulaciones `--offline` no
necesitan Docker; la capa IA sí corre en contenedores.

### Umbrales y ventana (RNF-MANT-04 / RNF-PORT-05)

Se ajustan en `.env`, sin reconstruir imágenes: `SIEM_UMBRAL_FUERZA_BRUTA` (20),
`SIEM_UMBRAL_CRITICO` (5000), `SIEM_UMBRAL_PUERTOS` (10), `SIEM_VENTANA` (`24h`; vale
`90m`, `7d`…) y `SIEM_ES_HOST` (otro cluster). Se aplican con
`docker compose up -d classifier collector`. Un valor inválido no se ignora: el
servicio no arranca y su log dice qué variable está mal.

### Respaldo y restauración (RQ-SEC-05)

El servicio `backup` respalda todos los días a las 03:00 (`SIEM_RESPALDO_HORA`, zona
`TZ`) los índices `filebeat-*` y las alertas (snapshot de Elasticsearch) más
`data/audit/`, en un único archivo cifrado con AES-256 (`SIEM_RESPALDO_CLAVE`) y su
`.sha256`. Conserva los últimos 7 (`SIEM_RESPALDO_RETENCION`) en
`data/backup/archivo/` o en `SIEM_RESPALDO_DIR` (mejor otro disco).

```bash
./scripts/siem.sh respaldo                                    # uno ya, a mano
docker logs siem-backup                                       # resultado de cada corrida
./scripts/siem.sh restaurar siem-respaldo-<UTC>.tar.gz.enc    # cluster vacío (desastre)
./scripts/siem.sh restaurar siem-respaldo-<UTC>.tar.gz.enc --renombrar   # al lado de los actuales
```

La restauración verifica el SHA-256 antes de descifrar y nunca pisa `data/audit/`:
deja la auditoría en `data/backup/archivo/restaurados/<respaldo>/` para que una
persona la compare y la reemplace. Cada respaldo es completo, así que restaurar es
un solo archivo: minutos, dentro del RTO de 30 min.

### Retención de datos personales (RQ-SEC-17)

`./scripts/deploy-ilm.sh` (lo corre `start.sh`) borra los índices `filebeat-*` y
los de alertas a los `SIEM_RETENCION_DIAS` días (30) **de la fecha de sus datos**.
`--dry-run` muestra qué índices caerían sin tocar nada.

### Salud y reinicio automático (RNF-CONF-05)

Elasticsearch, Kibana, Logstash y Filebeat se verifican cada 30 s; con 3 fallos
seguidos (≤ 90 s) quedan `unhealthy` y `siem-autoheal` los reinicia. Docker por sí
solo no lo hace: `restart: unless-stopped` solo actúa si el proceso termina.

---

## Simulaciones de ataque

El proyecto contempla **tres tipos de ataque**, cada uno con su simulación, su
ruta de detección y su mapeo MITRE ATT&CK. Todas corren en **modo live** (con
contenedores) o **`--offline`** (solo generan logs detectables, sin Docker).

| Ataque | Script | Técnica MITRE | Ruta de detección |
|--------|--------|---------------|-------------------|
| SSH Brute Force | `simulation/run-brute-force.sh` | T1110 (Credential Access) | logs SSH → Logstash → regla *Threshold*/EQL en Kibana |
| Port Scan | `simulation/run-port-scan.sh` | T1046 (Discovery) | eventos en `network_logs/` → clasificador (umbral de puertos) o regla Kibana |
| Phishing / captura de credenciales | `simulation/run-phishing.sh` | T1566 (Initial Access) | eventos en `network_logs/` → clasificador (envío de credenciales) o regla Kibana |

### 1. SSH Brute Force (T1110)

```bash
docker compose --profile simulation up -d
bash simulation/run-brute-force.sh                       # Hydra real contra ssh-target
bash simulation/run-brute-force.sh --offline             # solo logs, sin Docker
bash simulation/run-brute-force.sh --offline --ip 203.0.113.9   # IP propia, para demos
```

`--offline` (RF-SIM-05) escribe en `network_logs/brute-force-<timestamp-unix>.json`
las mismas líneas de sshd que deja `ssh-target` (24 `Failed password` y un
`Accepted password`). El clasificador las toma de ahí (`auth_logs_de_red()`), así
que el ataque se detecta sin Elasticsearch. Con el stack arriba no se cuentan dos
veces: Filebeat las indexa como `network_traffic`, y la consulta de auth fallida
del collector solo mira `ssh-target` y los logs del sistema.

Los contenedores de ataque (`ssh-target`, `hydra-attacker`) viven en su propia
red, `sim-net`, separada de la del SIEM y de la capa IA (RQ-SEC-24). Los
escaneos reales con nmap apuntan solo a la víctima del laboratorio.

El script crea un diccionario, descubre la IP del `ssh-target` y lanza Hydra
(`hydra -l testuser -P passwords.txt <ip> -s 2222 ssh`). Genera una ráfaga de
fallos de autenticación y, con la contraseña real en el diccionario, termina
en un login exitoso — lo que puede disparar *SSH Brute Force – Aggressive per
Source IP* (Threshold) y, si hubo éxito después de los fallos, *SSH
Successful Login After Brute Force* (EQL, severidad Critical: compromiso
confirmado).

**Detección en la capa IA:** `services/classifier/classifier.py` agrupa los fallos por IP; si
superan el umbral (`BRUTE_FORCE_THRESHOLD`, 20 por defecto, `SIEM_UMBRAL_FUERZA_BRUTA`
en `.env`) o hay técnica T1110 → `ssh_brute_force`.

### 2. Port Scan (T1046)

```bash
bash simulation/run-port-scan.sh            # genera logs + nmap real si hay contenedor
bash simulation/run-port-scan.sh --offline  # solo logs
bash simulation/run-port-scan.sh --offline --ip 172.19.0.9   # IP propia, para demos
```

Genera un evento por puerto en `network_logs/port-scan-<timestamp-unix>.json`
— nombre único por corrida a propósito: Filebeat (`filestream`) identifica
archivos por inodo, y reescribir siempre el mismo nombre puede desincronizar
el offset. **Detección:** `detect_port_scans()` agrupa por IP origen y cuenta
puertos **distintos**; si ≥ `PORT_SCAN_DISTINCT_PORTS` (10 por defecto,
`SIEM_UMBRAL_PUERTOS` en `.env`) → `port_scan`.

### 3. Phishing / captura de credenciales (T1566)

```bash
bash simulation/run-phishing.sh             # genera logs + POST real si hay contenedor
bash simulation/run-phishing.sh --offline   # solo logs
```

Genera eventos en `network_logs/phishing-<timestamp-unix>.json`: una visita
GET y un POST con credenciales. **Detección:** `detect_phishing()` busca
`http_request` con `credential_submission` y agrupa por IP →
`credential_harvesting`.

### Correr los tres y verlos en el dashboard

```bash
bash simulation/run-brute-force.sh --offline
bash simulation/run-port-scan.sh   --offline
bash simulation/run-phishing.sh    --offline
./scripts/siem.sh pipeline
docker compose up -d gateway     # http://127.0.0.1:5000
```

### Extender con un ataque nuevo

1. Generar el log representativo (en `network_logs/` o un log que Filebeat ya
   recolecte).
2. Agregar una función `detect_<tipo>()` en `services/classifier/classifier.py` con su
   umbral, sus factores de explicabilidad, y un playbook en `_playbook()`.
3. Agregar la rama del fallback en `services/analyst/siem_agent.py` (`_fallback_analysis`).
4. Si el ataque también puede detectarse en Kibana, sumar la regla
   correspondiente — ver [02 · Reglas de detección](02-reglas-y-dashboard.md).
5. Documentar acá.

### Limpieza

```bash
rm -f network_logs/*.json                      # borra los logs sintéticos
docker compose --profile simulation down -v    # baja ssh-target / hydra-attacker
```
