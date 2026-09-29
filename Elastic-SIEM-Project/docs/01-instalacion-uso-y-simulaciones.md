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
export PYTHONPATH="$PWD/.devtools"
./scripts/start.sh                    # stack + despliegue de las 14 reglas
python3 src/manage_users.py crear ana --rol analyst   # primer usuario, una vez
python3 src/siem_pipeline.py          # extrae → clasifica → analiza
python3 src/dashboard.py              # http://127.0.0.1:5000/login
```

## Uso y ejecución

### Pipeline completo (un comando)

```bash
python3 src/siem_pipeline.py
```

Encadena tres etapas: `src/prepare-for-ia.py` (extrae de Elasticsearch →
`data/siem_clean.json`; si ES no responde, **no pisa** el archivo y sigue con
la última captura), `src/classifier.py` (Agente 1 → `data/siem_incidents.json`)
y `src/siem_agent.py` (Agente 2 → agrega el análisis).

### Etapa por etapa

```bash
python3 src/prepare-for-ia.py     # ES → data/siem_clean.json   (requiere stack arriba)
python3 src/classifier.py         # Agente 1 → data/siem_incidents.json
python3 src/siem_agent.py         # Agente 2 → análisis + data/analysis_history.jsonl
python3 src/get-logs.py           # (opcional) inspección ad-hoc de ES
```

### El dashboard

```bash
python3 src/dashboard.py
# abrir http://127.0.0.1:5000/login
```

Guía completa panel por panel en [02 · Reglas y dashboard](02-reglas-y-dashboard.md#el-dashboard-de-supervisión).

**Qué pasa cuando decidís.** Cada click registra una línea en
`data/decisions.jsonl` (append-only e inmutable, firmada con el usuario de la
sesión) con timestamp, incidente, acción, decisión y nota opcional. El estado
se reconstruye haciendo *replay* de ese log, así que reiniciar el servidor no
pierde las decisiones. El dashboard se refresca solo cada 15 s.

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

### Modo offline de punta a punta (sin Docker)

```bash
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
python3 src/classifier.py && python3 src/siem_agent.py
python3 src/dashboard.py          # http://127.0.0.1:5000 → 3 incidentes
```

En modo offline, `src/prepare-for-ia.py` no puede hablar con ES: el pipeline
lo informa y continúa con los datos existentes. El Agente 2 usa el fallback
determinístico.

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

**Detección en la capa IA:** `src/classifier.py` agrupa los fallos por IP; si
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
python3 src/siem_pipeline.py
python3 src/dashboard.py     # http://127.0.0.1:5000
```

### Extender con un ataque nuevo

1. Generar el log representativo (en `network_logs/` o un log que Filebeat ya
   recolecte).
2. Agregar una función `detect_<tipo>()` en `src/classifier.py` con su
   umbral, sus factores de explicabilidad, y un playbook en `_playbook()`.
3. Agregar la rama del fallback en `src/siem_agent.py` (`_fallback_analysis`).
4. Si el ataque también puede detectarse en Kibana, sumar la regla
   correspondiente — ver [02 · Reglas de detección](02-reglas-y-dashboard.md).
5. Documentar acá.

### Limpieza

```bash
rm -f network_logs/*.json                      # borra los logs sintéticos
docker compose --profile simulation down -v    # baja ssh-target / hydra-attacker
```
