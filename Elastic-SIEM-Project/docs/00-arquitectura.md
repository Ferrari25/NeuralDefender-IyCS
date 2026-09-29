# 00 · Contexto, arquitectura y requerimientos

> **Índice de `docs/`** (5 documentos):
> **00 · Contexto, arquitectura y requerimientos** (este archivo) ·
> [01 · Instalación, uso y simulaciones](01-instalacion-uso-y-simulaciones.md) ·
> [02 · Reglas de detección y dashboard](02-reglas-y-dashboard.md) ·
> [03 · Autenticación y control de acceso](03-autenticacion-y-control-de-acceso.md) ·
> [04 · Auditoría, pruebas y demostración](04-auditoria-pruebas-y-demostracion.md).
>
> Para levantar el proyecto desde cero en un equipo nuevo, ver
> [`nicotito.md`](../nicotito.md) en la raíz.

## Por qué existe este proyecto

**Misión.** Reducir el tiempo que le toma a un analista de seguridad — o a una
sola persona encargada de seguridad en una organización sin SOC dedicado —
pasar de "hay una alerta" a "sé qué pasó y qué tengo que hacer", sin quitarle
la decisión final. El sistema clasifica, correlaciona y explica; el humano
aprueba o descarta.

**El problema real.** Un analista de un SOC mediano empieza el turno con
cientos o miles de alertas acumuladas — el volumen real que generan los
sistemas de seguridad modernos. Las herramientas actuales generan
**información** pero no **comprensión**: dicen que hubo 47 logins fallidos
desde una IP, pero no qué significa eso en el contexto de la red, ni si esa
misma IP estuvo activa antes haciendo otra cosa. Eso produce **alert fatigue**
(el cerebro normaliza el volumen y empieza a descartar por hábito, justo donde
se esconden los ataques lentos y graduales), tiempo de respuesta alto, y
decisiones tomadas bajo presión sin contexto suficiente.

**Qué agrega este sistema sobre un SIEM tradicional.** Un SIEM (Elastic,
Splunk, QRadar) es una base de datos rápida con reglas de correlación: cuando
dispara, entrega datos crudos y el analista construye el análisis desde cero.
Este proyecto agrega una capa de razonamiento automático que **no reemplaza**
al analista — le entrega un primer análisis ya hecho, en lenguaje que se lee
rápido, con una recomendación concreta. La diferencia entre leer *"47 failed
SSH logins from 185.220.101.43 in 10 minutes"* y leer *"esta IP está
ejecutando fuerza bruta automatizada contra SSH, el patrón sugiere Hydra o
Medusa; se recomienda bloquear en el firewall perimetral; probabilidad de
falso positivo: baja."*

**El principio rector: la IA sugiere, el humano decide.** El sistema **nunca**
bloquea nada sin que un humano apruebe la acción — los falsos positivos en
seguridad tienen consecuencias reales (cortar un proveedor legítimo,
interrumpir un servicio crítico). Es una decisión deliberada, no una
limitación, y es lo que hace al sistema confiable en un entorno real.

**Alcance incluido:** ingesta y normalización de logs (Filebeat → Logstash →
Elasticsearch), reglas de detección de Elastic Security con un catálogo
curado (ver [02](02-reglas-y-dashboard.md)), clasificación determinística con
explicabilidad y correlación de campañas, análisis en lenguaje claro (LLM o
fallback), dashboard de supervisión con registro append-only, y simulación de
3 tipos de ataque.

**Explícitamente fuera de alcance:** contención automática (el sistema nunca
ejecuta un bloqueo por sí solo), IDS de red real (los eventos de port
scan/phishing son sintéticos), multi-tenant, alta disponibilidad/clustering.

## Arquitectura — las dos capas

```
┌────────────────────────── CAPA SIEM (Docker) ───────────────────────────┐
│                                                                         │
│  Fuentes de logs                                                       │
│   • contenedores (SSH)      Filebeat → Logstash → Elasticsearch        │
│   • /var/log del host         (shipper)   (parseo, GeoIP,   → Kibana   │
│   • network_logs/*.json                    tags, date)      (reglas,  │
│                                                               alertas) │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                              │ alertas + logs (REST API :9200)
                              ▼
                    src/prepare-for-ia.py
                              │
                              ▼  data/siem_clean.json
┌─────────────────────────── CAPA IA (Python) ────────────────────────────┐
│                                                                         │
│  src/classifier.py → src/siem_agent.py → data/siem_incidents.json     │
│  (Agente 1:            (Agente 2:                                      │
│   reglas/umbral)         LLM + fallback)                               │
│                                  │                                      │
│                                  ▼                                      │
│                     src/dashboard.py (Flask)                           │
│                                  │  el analista aprueba/descarta       │
│                                  ▼                                      │
│                data/decisions.jsonl (append-only)                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Componentes de la capa SIEM

| Servicio | Imagen | Rol |
|----------|--------|-----|
| **elasticsearch** | `elasticsearch:8.12.2` | Almacén de eventos + motor de detección. Seguridad y TLS de transporte activados. |
| **kibana** | `kibana:8.12.2` | UI del SIEM (Security Solution): reglas de detección, alertas, dashboards. |
| **logstash** | `logstash:8.12.2` | Pipeline de normalización: grok de auth SSH, filtro `date`, GeoIP (solo IPs públicas), tags. |
| **filebeat** | `filebeat:8.12.2` | Shipper: logs de contenedores, `/var/log` acotado y `network_logs/*.json`. |
| **setup** | `elasticsearch:8.12.2` | One-shot: fija el password del usuario `kibana_system`. |

**Simulación** (perfil `simulation`, no arranca por defecto): `ssh-target`
(`linuxserver/openssh-server`, víctima) y `hydra-attacker` (`ubuntu:22.04` con
Hydra + nmap).

### Componentes de la capa IA

| Archivo | Rol |
|---------|-----|
| `src/siem_lib.py` | Módulo común: config, acceso a ES, saneamiento anti-inyección, utilidades JSON/JSONL. |
| `src/prepare-for-ia.py` | Extrae y limpia alertas + logs desde Elasticsearch → `data/siem_clean.json`. |
| `src/classifier.py` | **Agente 1 determinístico.** Detecta `ssh_brute_force`, `port_scan`, `credential_harvesting`; asigna playbook, factores de explicabilidad y correlación de campañas. |
| `src/siem_agent.py` | **Agente 2.** Análisis en lenguaje claro vía LLM (Gemini) con fallback determinístico. Enriquece con contexto histórico. |
| `src/siem_pipeline.py` | Orquestador: encadena prepare → classifier → agent. |
| `src/dashboard.py` + `templates/` + `static/` | GUI de supervisión humana (Flask). Ver [02 · Dashboard](02-reglas-y-dashboard.md). |

### Qué hace cada agente, en detalle

**Agente 1 — `src/classifier.py` (determinístico):**
1. **Detección** — agrupa eventos crudos (alertas de Kibana + logs de auth +
   eventos de red/web) por IP/host y aplica umbrales fijos
   (`BRUTE_FORCE_THRESHOLD = 20`, `PORT_SCAN_DISTINCT_PORTS = 10`).
2. **Clasificación** — asigna `attack_type`, `severity`, `confidence` y una
   lista de **factores concretos** que explican por qué ("742 fallos ≥ umbral
   de 20", "confirmado por la regla del SIEM 'X'"). Explicabilidad real, no
   caja negra.
3. **Correlación (`_link_campaigns`)** — vincula incidentes que comparten al
   menos una IP atacante, aunque vengan de detecciones distintas (ej. la
   misma IP hace port scan y después fuerza bruta SSH), incluso si comparten
   IP con un incidente que Kibana ya confirmó por su cuenta.
4. **Playbook** — arma la lista de acciones recomendadas con comandos fijos
   **y su explicación en lenguaje claro** de qué hace cada uno.

**Agente 2 — `src/siem_agent.py` (LLM + fallback + contexto):**
1. **Contexto histórico** — busca en `data/decisions.jsonl` si el analista ya
   decidió algo sobre alguna IP de este incidente, en **otro** incidente.
2. **Contexto de campaña** — si el Agente 1 vinculó este incidente a otros,
   arma la explicación de esa campaña.
3. **Análisis** — LLM (Gemini) si hay `GEMINI_API_KEY` **y** `SIEM_USE_LLM=true`
   (apagado por defecto para no gastar tokens sin querer); si falta cualquiera
   de los dos o falla, cae al análisis determinístico de respaldo.
4. Los campos de contexto histórico y de campaña **siempre** se sobreescriben
   con el valor calculado en Python — nunca se dejan a que el LLM los haya
   parafraseado, mismo criterio que los comandos del playbook.

### Decisiones de diseño clave

- **Agente 1 antes del LLM:** una etapa rápida, barata y auditable filtra y
  clasifica antes de gastar el LLM. "O cumple el patrón o no."
- **Comandos del playbook, nunca del LLM:** así un log envenenado por un
  atacante no puede sugerirle al operador un comando malicioso.
- **Hechos auditables calculados en Python, siempre:** comandos, contexto
  histórico y correlación de campañas nunca dependen de que el modelo los
  haya reproducido bien.
- **Fallback sin nube:** si falta la key, el interruptor está apagado, o
  falla la red, el sistema **siempre** produce salida.
- **Supervisión humana con registro inmutable:** las decisiones van a un log
  append-only; el estado se reconstruye por *replay*. El archivo nunca se
  edita ni se borra.

## Requerimientos

### Hardware mínimo

| Recurso | Mínimo | Recomendado | Por qué |
|---------|--------|-------------|---------|
| RAM | 4 GB libres | 8 GB | Elasticsearch + Kibana consumen más. Heap de ES fijado en 512 MB. |
| CPU | 2 cores | 4 cores | Logstash usa 2 workers. |
| Disco | 5 GB | 20 GB+ | Imágenes Docker (~3 GB) + índices que crecen con los logs. |

### Software

| Software | Versión | Para qué |
|----------|---------|----------|
| Docker Engine | 20.10+ | Correr el stack. |
| Docker Compose | **v2** (`docker compose`) | Orquestación. |
| Python | 3.10+ (probado en 3.13) | Capa IA, scripts y dashboard. |
| `openssl` | cualquiera | Generar certificados/claves. |
| Node.js 18+ | opcional | Solo para ESLint sobre `static/app.js`. |

### Conectividad

- **Modo offline (sin nube):** el sistema funciona completo sin internet
  usando el fallback determinístico. Útil para demos y entornos con
  requisitos de privacidad.
- **Modo con LLM:** requiere salida HTTPS hacia la API de Gemini — eso envía
  datos de los logs a un tercero (evaluar según la normativa aplicable, ej.
  Ley 25.326 de Protección de Datos Personales en Argentina).

Configuración completa de `.env` (secretos, cómo generarlos): ver
[`nicotito.md`](../nicotito.md) §3.

## Flujo de datos, paso a paso

```
[1] ATAQUE    [2] RECOLECCIÓN [3] NORMALIZACIÓN [4] ALMACÉN+DETECCIÓN
Hydra / nmap  ─▶ Filebeat     ─▶ Logstash       ─▶ Elasticsearch
curl phishing (filebeat.yml)  (beats.conf)      (regla Kibana) → alerta

                                                                        │
                                                                        ▼

[8] DECISIÓN         [7] SUPERVISIÓN     [6] ANÁLISIS           [5] EXTRACCIÓN
data/decisions.jsonl ◀─ src/dashboard.py ◀─ src/classifier.py   ◀─ src/prepare-for-ia.py
(append-only)        (Flask GUI)         ◀─ + src/siem_agent.py (data/siem_clean.json)
```

**Red y exposición.** Todos los servicios viven en la red Docker
`elastic-net`. Los puertos publicados al host están **bindeados a
`127.0.0.1`** (no a toda la LAN): `9200` (ES), `5601` (Kibana), `5044`/`9600`
(Logstash), `2222` (ssh-target en simulación). El dashboard Flask corre en
`127.0.0.1:5000`.

**Por qué `network_logs/`.** Este proyecto no despliega Suricata, así que los
ataques de red/web (port scan, phishing) se materializan como eventos NDJSON
en `network_logs/`. Ese directorio es a la vez (a) la entrada
`network-traffic` de Filebeat hacia Elasticsearch en modo live, y (b) lo que
lee el clasificador directamente en modo offline — es el mismo punto de
inyección que usaría un IDS real escribiendo eventos.
