# 01 · Arquitectura

El sistema tiene **dos capas** que se conectan por un archivo de intercambio:

1. **Capa SIEM (Elastic Stack)** — recolecta, normaliza, almacena y detecta.
2. **Capa IA (Python)** — clasifica, analiza y presenta para supervisión humana.

```
┌──────────────────────────── CAPA SIEM (Docker) ─────────────────────────────┐
│                                                                              │
│   Fuentes de logs          Filebeat ──▶ Logstash ──▶ Elasticsearch ──▶ Kibana│
│   • contenedores (SSH)     (shipper)    (parseo,      (almacén +      (SIEM, │
│   • /var/log host                        GeoIP,        reglas de       reglas,│
│   • network_logs/*.json                  tags, date)   detección)      alertas)│
│                                                            │                 │
└────────────────────────────────────────────────────────────┼────────────────┘
                                                              │ alertas + logs
                                  prepare-for-ia.py  ◀────────┘ (REST API :9200)
                                          │  siem_clean.json
┌──────────────────────────── CAPA IA (Python) ──────────────▼─────────────────┐
│                                                                              │
│   classifier.py  ──▶  siem_agent.py  ──▶  siem_incidents.json                │
│   (Agente 1:          (Agente 2:                                             │
│    reglas/umbral)      LLM + fallback)         dashboard.py (Flask)          │
│                                                  │   el analista aprueba/     │
│                                                  ▼   descarta cada acción     │
│                                            decisions.jsonl (append-only)      │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Componentes de la capa SIEM

| Servicio | Imagen | Rol |
|----------|--------|-----|
| **elasticsearch** | `elasticsearch:8.12.2` | Almacén de eventos + motor de detección. Seguridad y TLS de transporte activados. |
| **kibana** | `kibana:8.12.2` | UI del SIEM (Security Solution): reglas de detección, alertas, dashboards. |
| **logstash** | `logstash:8.12.2` | Pipeline de normalización: grok de auth SSH, filtro `date`, GeoIP (solo IPs públicas), tags. |
| **filebeat** | `filebeat:8.12.2` | Shipper: logs de contenedores, `/var/log` acotado y `network_logs/*.json`. |
| **setup** | `elasticsearch:8.12.2` | One-shot: fija el password del usuario `kibana_system` para que Kibana autentique. |

### Componentes de simulación (perfil `simulation`)

| Servicio | Imagen | Rol |
|----------|--------|-----|
| **ssh-target** | `linuxserver/openssh-server` | Servidor SSH víctima del brute force. |
| **hydra-attacker** | `ubuntu:22.04` | Contenedor con Hydra (y nmap) para los ataques. |

> No arrancan por defecto. Se levantan con `docker compose --profile simulation up -d`.

## Componentes de la capa IA

| Archivo | Rol |
|---------|-----|
| `siem_lib.py` | Módulo común: config, acceso a ES (queries con ventana temporal + agregación por IP), saneamiento anti-inyección, utilidades JSON/JSONL. |
| `prepare-for-ia.py` | Extrae y limpia alertas + logs de auth desde Elasticsearch → `siem_clean.json`. |
| `classifier.py` | **Agente 1 determinístico.** Reglas/umbral; detecta `ssh_brute_force`, `port_scan`, `credential_harvesting`. Asigna playbook de acciones con comandos fijos, factores de explicabilidad, y correlación entre incidentes (campañas). |
| `siem_agent.py` | **Agente 2.** Análisis en lenguaje claro vía LLM (Gemini) con **fallback** determinístico si no hay API/red. Enriquece con contexto histórico de decisiones previas. |
| `siem_pipeline.py` | Orquestador: encadena prepare → classifier → agent. |
| `dashboard.py` + `templates/index.html` | GUI de supervisión humana (Flask). Ver el detalle completo en [09 · Dashboard](09-dashboard.md). |

## Qué hace cada agente, en detalle

### Agente 1 — `classifier.py` (determinístico)

1. **Detección** — agrupa eventos crudos (alertas de Kibana + logs de auth + eventos de red/web) por IP/host y aplica umbrales fijos (`BRUTE_FORCE_THRESHOLD = 20`, `PORT_SCAN_DISTINCT_PORTS = 10`, etc.).
2. **Clasificación** — asigna `attack_type`, `severity`, `confidence`, `false_positive_likelihood` y una lista de **factores concretos** (`classification.factores`) que explican por qué: "742 fallos ≥ umbral de 20", "confirmado por la regla del SIEM 'X'", etc. Esto es explicabilidad real, no una caja negra — cada severidad se puede justificar señalando el umbral o la regla que la disparó.
3. **Correlación (`_link_campaigns`)** — al final de `classify()`, revisa todos los incidentes de la corrida y vincula los que comparten al menos una IP (`source_ip` o `attacker_ips`), aunque vengan de detecciones distintas (ej. la misma IP hace port scan y después fuerza bruta SSH). Les asigna un `campaign_id` común y `related_incidents`, para que el dashboard los muestre como una sola campaña en vez de incidentes sueltos.
4. **Playbook** — arma la lista de acciones recomendadas con comandos fijos **y su explicación en lenguaje claro** (`comando_explicacion`: qué hace el comando exactamente, no solo cuál es).

### Agente 2 — `siem_agent.py` (LLM + fallback + contexto)

1. **Contexto histórico (`historical_context`)** — antes de analizar, busca en `decisions.jsonl` si el analista ya tomó alguna decisión sobre alguna de las IPs de este incidente, en **otro** incidente. Si encontró algo, arma un resumen ("ya se aprobó una acción sobre esta IP el...", "todas las decisiones previas fueron descartes").
2. **Contexto de campaña (`campaign_context`)** — si `classifier.py` vinculó este incidente a otros, arma la explicación de esa campaña.
3. **Análisis** — LLM (Gemini) si hay `GEMINI_API_KEY`, con el contexto histórico y de campaña como insumo del prompt; si no hay key o falla, cae al análisis determinístico de respaldo.
4. Los campos `contexto_historico` y `contexto_campana` del resultado final **siempre** se sobreescriben con el valor calculado en Python (paso 1-2), nunca se dejan a que el LLM los haya parafraseado — mismo principio que los comandos del playbook.

## Decisiones de diseño clave

- **Agente 1 determinístico antes del LLM:** una etapa rápida, barata y auditable
  filtra y clasifica antes de gastar el LLM. "O cumple el patrón o no."
- **Comandos del playbook, no del LLM:** los comandos que ve el operador salen de
  un playbook fijo en `classifier.py`, nunca del LLM. Así un log envenenado por un
  atacante no puede sugerirle al operador un comando malicioso.
- **Hechos auditables calculados en Python, siempre — no delegados al LLM:** los
  comandos, el contexto histórico y la correlación de campañas se calculan
  siempre de forma determinística. El LLM puede *usarlos* para redactar mejor su
  explicación, pero el campo final que ve el analista nunca depende de que el
  modelo los haya reproducido bien.
- **Fallback sin nube:** si no hay `GEMINI_API_KEY` o falla la red, el análisis se
  genera de forma determinística. El sistema **siempre** produce salida.
- **Supervisión humana con registro inmutable:** las decisiones van a un log
  append-only (`decisions.jsonl`, con la IP del incidente incluida desde
  `dashboard.py`); el estado se reconstruye por *replay*. El panel de "Historial
  de Decisiones" del dashboard deduplica por acción para mostrar el estado
  actual — el archivo en sí nunca se edita ni se borra.

## Red y exposición

Todos los servicios viven en la red Docker `elastic-net`. Los puertos publicados
al host están **bindeados a `127.0.0.1`** (no a toda la LAN): `9200` (ES),
`5601` (Kibana), `5044`/`9600` (Logstash), `2222` (ssh-target en simulación).
El dashboard Flask corre en `127.0.0.1:5000`.

Ver el recorrido detallado de un evento en [06 · Flujo de datos](06-flujo-de-datos.md).
