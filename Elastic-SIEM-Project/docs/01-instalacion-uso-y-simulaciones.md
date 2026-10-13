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

Le pide un ciclo al servicio **pipeline**, que encadena por HTTP:
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
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
./scripts/siem.sh pipeline               # → http://127.0.0.1:5000
```

Sin Elasticsearch, el collector responde 503 y el ciclo lo informa
(`collector sin_captura`) y sigue clasificando desde `network_logs/`. El
Agente 2 usa el fallback determinístico. Las simulaciones `--offline` no
necesitan Docker; la capa IA sí corre en contenedores.

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
bash simulation/run-brute-force.sh
```

El script crea un diccionario, descubre la IP del `ssh-target` y lanza Hydra
(`hydra -l testuser -P passwords.txt <ip> -s 2222 ssh`). Genera una ráfaga de
fallos de autenticación y, con la contraseña real en el diccionario, termina
en un login exitoso — lo que puede disparar *SSH Brute Force – Aggressive per
Source IP* (Threshold) y, si hubo éxito después de los fallos, *SSH
Successful Login After Brute Force* (EQL, severidad Critical: compromiso
confirmado).

**Detección en la capa IA:** `services/classifier/classifier.py` agrupa los fallos por IP; si
superan el umbral (`BRUTE_FORCE_THRESHOLD = 20`) o hay técnica T1110 →
`ssh_brute_force`.

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
puertos **distintos**; si ≥ `PORT_SCAN_DISTINCT_PORTS = 10` → `port_scan`.

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
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
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
