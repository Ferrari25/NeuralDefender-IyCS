# 06 · Flujo de datos

Este documento sigue **un evento** desde que el ataque ocurre hasta que un humano
toma una decisión, nombrando en cada paso el archivo/servicio responsable y la
forma de los datos.

## Vista general

```
 [1] ATAQUE        [2] RECOLECCIÓN     [3] NORMALIZACIÓN   [4] ALMACÉN+DETECCIÓN
 Hydra / nmap  ─▶  Filebeat        ─▶  Logstash        ─▶  Elasticsearch ─▶ alerta
 curl phishing     (filebeat.yml)      (beats.conf)        (regla Kibana)
                                                                  │
                                                                  ▼
 [8] DECISIÓN      [7] SUPERVISIÓN    [6] ANÁLISIS        [5] EXTRACCIÓN
 decisions.jsonl ◀─ dashboard.py  ◀─  classifier.py   ◀─  prepare-for-ia.py
 (append-only)      (Flask GUI)        + siem_agent.py     (siem_clean.json)
```

---

## Paso 1 — El ataque genera logs

- **SSH brute force:** cada intento fallido escribe `Failed password for testuser
  from 172.18.0.7 ...` en el log del contenedor `ssh-target`.
- **Port scan / phishing:** el script de simulación escribe eventos NDJSON en
  `network_logs/*.json` (rol equivalente al de un IDS escribiendo eventos de red).

## Paso 2 — Filebeat recolecta (`filebeat/filebeat.yml`)

Tres inputs:
- `container` → logs de los contenedores Docker (incluye el SSH).
- `filestream` → `/var/log/auth.log`, `syslog`, `messages` (acotado, sin firehose).
- `filestream` (ndjson) → `network_logs/*.json`, marcados `source_type:
  network_traffic`.

Un `drop_event` descarta ruido (GPU/Xorg) **en ingesta**, no después. Filebeat
envía todo a Logstash por el puerto 5044.

## Paso 3 — Logstash normaliza (`logstash/pipeline/beats.conf`)

Para eventos de auth SSH:
1. **grok** despega la línea syslog (`timestamp`, `hostname`, `program`) del mensaje real,
   solo para los logs que vienen del módulo `system`/`auth` de Filebeat.
2. **Un único bloque de grok, sin importar la fuente** matchea directo sobre el contenido del
   `message` ("Failed password" / "Accepted password" / "Invalid user") y extrae `user` y
   `source_ip`, agregando el tag correspondiente (`authentication_failure` /
   `authentication_success` / `invalid_user`). A propósito **no depende** de que Filebeat haya
   taggeado el evento como "ssh" ni de que `add_docker_metadata` haya podido enriquecer el
   evento con `container.name` — ese enriquecimiento puede fallar en silencio según la versión
   del Docker Engine del host (ver nota en [`docs/alertas/README.md`](alertas/README.md)). Así
   cubre por igual el `auth.log` del host y el stdout crudo del contenedor `ssh-target`.
3. **`date`** asigna el timestamp del evento a `@timestamp` (no la hora de
   ingesta) → las ventanas de correlación quedan correctas.
4. **`cidr` + `geoip`**: GeoIP solo para IPs públicas; las privadas
   (Docker/LAN) se saltan para no generar `_geoip_lookup_failure`.

Salida: índice diario `filebeat-<versión>-YYYY.MM.dd` en Elasticsearch. Los eventos de
red/web sintéticos (`network_logs/*.json`) van al **mismo** índice, vía el input
`network-traffic` de Filebeat.

## Paso 4 — Elasticsearch almacena y las reglas detectan

Cuatro **reglas de detección** de Kibana corren periódicamente sobre `filebeat-*` — no solo
SSH: también port scan y phishing, ya que sus eventos sintéticos llegan al mismo índice. Cada
una escribe en `.alerts-security.alerts-default` con severidad, risk score y mapeo MITRE.
Ver el detalle de cada una (y cómo crearlas por API) en
[07 · Reglas de detección](07-reglas-de-deteccion.md):

| Regla | Tipo | Dispara cuando |
|---|---|---|
| SSH Brute Force – Aggressive per Source IP | Threshold | 3+ fallos de auth de una misma IP en 2m |
| SSH Successful Login After Brute Force | EQL (secuencia) | fallo → éxito, misma IP, en 10m — compromiso confirmado |
| Port Scan – Many Distinct Ports | Threshold + cardinalidad | 10+ puertos distintos sondeados por una IP |
| Credential Submission to Suspicious Login | Custom query | POST con credenciales a una URL con "login" |

## Paso 5 — Extracción (`prepare-for-ia.py`)

Consulta la API REST de ES (`:9200`) con **ventana temporal** (`now-24h`):
- alertas de seguridad (`.alerts-security.alerts-default`),
- logs de auth fallida (`filebeat-*`),
- una **agregación por IP** (el "historial de la IP en 24h").

Produce `siem_clean.json` (resumen + alertas + logs). **Si ES no responde, no
sobreescribe** el archivo, para preservar la última captura buena.

```json
{ "summary": { "total_alerts": 3, "top_source_ips": {"172.18.0.5": 722133} },
  "alerts": [ ... ], "auth_failure_logs": [ ... ] }
```

## Paso 6 — Análisis en dos agentes

**Agente 1 — `classifier.py` (determinístico):** arma incidentes desde
`siem_clean.json` (auth/alertas) y desde `network_logs/` (red/web). Aplica reglas
de umbral y asigna tipo (`ssh_brute_force` / `port_scan` /
`credential_harvesting` / `suspicious_auth`), severidad, probabilidad de falso
positivo, una lista de **factores** que justifican esa clasificación
(explicabilidad), y un **playbook de acciones con comandos fijos y su
explicación en lenguaje claro**. Al final, `_link_campaigns()` revisa todos los
incidentes de la corrida y vincula los que comparten IP entre sí
(`campaign_id`, `related_incidents`). Salida: `siem_incidents.json` (con
`analysis: null`).

**Agente 2 — `siem_agent.py` (LLM con fallback):** antes de analizar, busca en
`decisions.jsonl` si ya hubo alguna decisión previa sobre alguna de las IPs de
este incidente en **otro** incidente (`historical_context`), y arma la nota de
campaña si `classifier.py` lo vinculó a otros (`campaign_context`). Con eso como
insumo, genera el análisis en lenguaje claro (explicación, metodología, riesgo,
severidad ajustada, referencias). Usa Gemini con salida estructurada; si no hay
key o la API falla, usa el **fallback determinístico**. Los campos
`contexto_historico` y `contexto_campana` del resultado final **siempre** se
sobreescriben con el valor calculado en Python — igual que los comandos, no
dependen de que el LLM los haya reproducido bien. Rellena `analysis` en
`siem_incidents.json` y registra la corrida en `analysis_history.jsonl`
(append-only).

```json
{ "incidents": [ {
    "incident_id": "INC-AUTH-172.18.0.5-c42ca785",
    "classification": { "attack_type": "ssh_brute_force", "severity": "critica" },
    "analysis": { "explicacion": "...", "severidad_ajustada": "CRITICAL",
                  "_source": "fallback" },
    "recommended_actions": [
      { "action_id": "...-a1", "accion": "Bloquear la IP ...",
        "comando_sugerido": "sudo ufw deny from 172.18.0.7", "status": "pending" }
    ] } ] }
```

> **Frontera de confianza:** el campo `message` lo controla el atacante. Por eso
> se sanea antes de mandarlo al LLM, el LLM lo trata como dato (no instrucción), y
> **los comandos no los inventa el LLM** sino el playbook del Agente 1.

## Paso 7 — Supervisión humana (`dashboard.py`)

El dashboard lee `siem_incidents.json` y superpone el estado de cada acción
haciendo *replay* de `decisions.jsonl`. Renderiza una card por incidente con
botones **Aprobar / Descartar** por acción.

## Paso 8 — La decisión queda registrada (`decisions.jsonl`)

Cada decisión es una línea **append-only e inmutable**, con la IP del incidente
incluida (para que el Agente 2 pueda buscar antecedentes en el Paso 6 de una
corrida futura):

```json
{"ts":"2026-06-11T23:41:51Z","incident_id":"INC-AUTH-...","action_id":"...-a1",
 "decision":"approved","analyst":"analista-soc","note":"",
 "source_ip":"172.18.0.3","attacker_ips":[]}
```

Nunca se sobreescribe. El estado actual de **cada acción** = la última decisión
por `action_id` (replay). El panel "Historial de Decisiones" del dashboard hace
lo mismo — dedupe por acción para mostrar el estado actual sin que la lista
crezca sin límite si el analista revisó la misma acción varias veces; el
archivo en sí conserva cada revisión para auditoría. Esto
da trazabilidad completa (quién decidió qué y cuándo) — base para auditoría
ISO 27001 y para calibrar el sistema con el tiempo.

---

## Resumen de artefactos

| Archivo | Lo produce | Lo consume | Naturaleza |
|---------|------------|------------|------------|
| `network_logs/*.json` | simulaciones / IDS | Filebeat, classifier | runtime |
| índices `filebeat-*` | Logstash | prepare-for-ia.py | persistente (ES) |
| `.alerts-security.*` | regla Kibana | prepare-for-ia.py | persistente (ES) |
| `siem_clean.json` | prepare-for-ia.py | classifier.py | intercambio |
| `siem_incidents.json` | classifier + agent | dashboard.py | intercambio |
| `decisions.jsonl` | dashboard.py | dashboard.py | append-only (auditoría) |
| `analysis_history.jsonl` | siem_agent.py | — | append-only (auditoría) |
