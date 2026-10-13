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
                              │ alertas + logs (REST API :9200, red elastic-net)
                              ▼
┌──────────────────── CAPA IA (microservicios, Docker) ───────────────────┐
│                                                                         │
│   collector ──┐            (red interna ia-net, token interno)          │
│   (único con  │                                                         │
│   creds de ES)▼                                                         │
│            pipeline ──▶ classifier ──▶ analyst ──▶ audit                │
│          (orquesta,    (Agente 1,     (Agente 2,   (único escritor      │
│           guarda el     reglas/        LLM +        de la auditoría     │
│           reporte)      umbral)        fallback)    encadenada)         │
│                                          │ memoria                      │
│                                          ▼                              │
│                                      knowledge ◀── casos, lecciones,    │
│                                      (documentos,   documentos (gateway)│
│                                       casos, lecciones)                 │
│               ▲                                       ▲                 │
│               │ incidentes            decisiones      │                 │
│               └───────────── gateway ─────────────────┘                 │
│                        (panel Flask, sesión, CSRF, RBAC) ──▶ auth       │
│                                  ▲                     (usuarios)       │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │ 127.0.0.1:5000 (único puerto publicado)
                              el analista aprueba/descarta
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

Ocho microservicios, uno por responsabilidad, cada uno dueño de sus datos.
Detalle de por qué se partió así, cómo se hablan y qué garantiza cada frontera:
§[Microservicios](#microservicios-de-la-capa-ia).

| Servicio | Código | Datos propios | Rol |
|----------|--------|---------------|-----|
| **gateway** | `services/gateway/` (`dashboard.py`, `sesion_web.py`, `templates/`, `static/`) | — | Panel de supervisión humana (Flask). Ver [02 · Dashboard](02-reglas-y-dashboard.md). |
| **auth** | `services/auth/` (`siem_auth.py`, `manage_users.py`) | `data/auth/users.json` | Usuarios, Argon2id, permisos por rol, anti-fuerza bruta. |
| **audit** | `services/audit/` (`cadena.py`, `audit_verify.py`) | `data/audit/*.jsonl` | Registros append-only encadenados por hash: decisiones e historial de corridas. |
| **collector** | `services/collector/` (`collector.py`, `es_client.py`) | `data/collector/siem_clean.json` | Extrae y limpia alertas + logs desde Elasticsearch. |
| **classifier** | `services/classifier/classifier.py` | — (lee `network_logs/`, ro) | **Agente 1 determinístico.** Detecta `ssh_brute_force`, `port_scan`, `credential_harvesting`; asigna playbook, factores de explicabilidad y correlación de campañas. |
| **analyst** | `services/analyst/siem_agent.py`, `perfil_agente.md` | — | **Agente 2.** Análisis en lenguaje claro vía LLM (Gemini) con fallback determinístico. Enriquece con contexto histórico y con su memoria. |
| **knowledge** | `services/knowledge/` (`memoria.py`) | `data/knowledge/*.json` | **Memoria del Agente 2.** Documentos de la organización, casos resueltos y lecciones (propuestas por el sistema o por un analista, **aprobadas a mano**). Ver §[Memoria del Agente 2](#memoria-del-agente-2). |
| **pipeline** | `services/pipeline/` (`orquestador.py`, `siem_pipeline.py`) | `data/pipeline/siem_incidents.json` | Orquesta collector → classifier → analyst → audit y guarda el reporte. |

Librería compartida (`libs/`, se copia en cada imagen): `siem_lib.py` (tiempo,
saneamiento anti-inyección, JSON con permisos 0600, lectura de `network_logs/`),
`siem_validators.py` (lista blanca de IP/usuario) y `siem_servicios.py` (cliente
y base de servidor entre servicios).

### Qué hace cada agente, en detalle

**Agente 1 — `services/classifier/classifier.py` (determinístico):**
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

**Agente 2 — `services/analyst/siem_agent.py` (LLM + fallback + contexto):**
1. **Contexto histórico** — busca en `data/audit/decisions.jsonl` si el analista ya
   decidió algo sobre alguna IP de este incidente, en **otro** incidente.
2. **Contexto de campaña** — si el Agente 1 vinculó este incidente a otros,
   arma la explicación de esa campaña.
3. **Análisis** — LLM (Gemini) si hay `GEMINI_API_KEY` **y** `SIEM_USE_LLM=true`
   (apagado por defecto para no gastar tokens sin querer); si falta cualquiera
   de los dos o falla, cae al análisis determinístico de respaldo.
4. **Memoria** — le pide al servicio knowledge las lecciones aprobadas que
   aplican, los casos parecidos ya resueltos y los párrafos de documentos que
   mencionan el incidente. Van al LLM en un bloque `MEMORIA_DEL_AGENTE`
   (referencia, nunca órdenes) y al panel en `analysis.aprendizaje`.
5. Los campos de contexto histórico, de campaña y de memoria **siempre** se
   sobreescriben con el valor calculado en Python — nunca se dejan a que el LLM
   los haya parafraseado, mismo criterio que los comandos del playbook.

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
- **Un dueño por dato:** cada servicio es el único que escribe su directorio
  de `data/`. En particular, solo el servicio audit escribe la auditoría, y
  su API no tiene ninguna operación de modificación ni borrado.
- **Secretos por servicio:** las credenciales de Elasticsearch solo existen en
  el collector, la key de Gemini solo en el analyst, `SECRET_KEY` solo en el
  gateway y los hashes de contraseña nunca salen de auth.

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
| Python | 3.10+ (probado en 3.13) | Pruebas, linters y scripts auxiliares. La capa IA corre en contenedores (`python:3.13-slim`). |
| `openssl` | cualquiera | Generar certificados/claves. |
| Node.js 18+ | opcional | Solo para ESLint sobre `services/gateway/static/app.js`. |

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

[8] DECISIÓN      [7] SUPERVISIÓN   [6] ANÁLISIS                [5] EXTRACCIÓN
audit         ◀─ gateway        ◀─ pipeline ─▶ classifier   ◀─ collector
(append-only,    (Flask GUI)        (orquesta)  ─▶ analyst     (captura de ES)
 encadenado)                                                         
```

**Red y exposición.** El stack Elastic vive en la red Docker `elastic-net` y
la capa IA en `ia-net`; el collector es el único servicio en las dos. Los
puertos publicados al host están **bindeados a `127.0.0.1`** (no a toda la
LAN): `9200` (ES), `5601` (Kibana), `5044`/`9600` (Logstash), `2222`
(ssh-target en simulación) y `5000` (gateway). Los puertos internos de los
microservicios (`8000`) no se publican.

**Por qué `network_logs/`.** Este proyecto no despliega Suricata, así que los
ataques de red/web (port scan, phishing) se materializan como eventos NDJSON
en `network_logs/`. Ese directorio es a la vez (a) la entrada
`network-traffic` de Filebeat hacia Elasticsearch en modo live, y (b) lo que
lee el clasificador directamente en modo offline — es el mismo punto de
inyección que usaría un IDS real escribiendo eventos.

## Microservicios de la capa IA

Hasta la migración, la capa IA era un único proceso Python por etapa
(`src/*.py`) que se pasaban datos escribiendo y leyendo archivos de un mismo
`data/`, y el orquestador las lanzaba con `subprocess`. Ahora cada etapa es un
servicio HTTP en su propio contenedor.

### Cómo se partió

Por **dueño de datos y de secretos**, no por tamaño de código. Cada frontera
corresponde a algo que antes se podía violar por convención y ahora no:

| Frontera | Qué garantiza |
|----------|---------------|
| `audit` aparte | Un solo proceso escribe la auditoría. Antes la escribían el panel (decisiones) y el Agente 2 (corridas), cada uno con su `flock`. El sello de tiempo lo pone el servicio, no quien llama, y valida cada registro con lista blanca de campos. |
| `auth` aparte | Los hashes de contraseña no salen del servicio: el gateway recibe solo usuario, rol y permisos. |
| `collector` aparte | Es el único contenedor con `ELASTIC_PASSWORD` y el único conectado a `elastic-net`. |
| `analyst` aparte | Es el único contenedor con `GEMINI_API_KEY`, el único que necesita salir a internet. |
| `classifier` sin estado | No guarda nada; ve `network_logs/` en solo lectura. |
| `knowledge` aparte | El analyst sigue sin estado: lo que el agente aprende vive en un servicio propio, sin secretos ni salida a internet, cuya API solo guarda y devuelve texto. |
| `gateway` como única puerta | El navegador no puede hablar con ningún servicio interno. |

### Cómo se hablan

- **Siempre por `libs/siem_servicios.py`**: `llamar(servicio, método, ruta, cuerpo)`.
  Solo acepta servicios del registro cerrado (`SERVICIOS`), y la URL se resuelve
  desde la configuración (`http://<servicio>:8000`, o `SIEM_<SERVICIO>_URL`),
  nunca desde un dato. `tests/test_no_autonomy.py` verifica por AST que toda
  llamada del producto tenga servicio y ruta literales.
- **Token interno** (`X-Internal-Token` = `SIEM_INTERNAL_TOKEN`), comparado en
  tiempo constante. Todo servicio lo exige salvo su sonda `/v1/healthz`, y
  ninguno arranca sin él (mínimo 32 caracteres). `start.sh` lo genera si falta.
- **Errores honestos**: si un servicio no responde, quien llama falla con 503
  en vez de inventar un resultado. El panel no muestra incidentes sin el estado
  de las decisiones; el Agente 2 no dice "sin antecedentes" si no pudo consultar
  la auditoría; el gateway no trata a un usuario como anónimo si `auth` no responde.

### API interna

| Servicio | Rutas |
|----------|-------|
| auth | `POST /v1/authenticate` · `GET /v1/users/<username>` · `GET /v1/users-summary` |
| audit | `POST /v1/decisions` · `GET /v1/decisions` · `GET /v1/decisions/verify` · `POST /v1/analysis-history` · `GET /v1/analysis-history/verify` |
| collector | `POST /v1/snapshots` · `GET /v1/snapshots/latest` |
| classifier | `POST /v1/classify` |
| analyst | `POST /v1/analyze` |
| pipeline | `POST /v1/cycles` · `GET /v1/incidents` · `GET /v1/incidents/<incident_id>` |
| knowledge | `GET/POST /v1/documents` · `POST /v1/cases` · `GET/POST /v1/lessons` · `POST /v1/lessons/<leccion_id>/review` · `POST /v1/context` |

La API del gateway hacia el navegador (`/api/v1/...`) no cambió con la
migración. La memoria del agente agregó cuatro rutas: `GET /api/v1/memoria`,
`POST /api/v1/memoria/documentos`, `POST /api/v1/memoria/lecciones` y
`POST /api/v1/memoria/lecciones/<leccion_id>/revision` (las tres de escritura
exigen el permiso `decidir`).

### El ciclo del pipeline

`POST /v1/cycles` (o `./scripts/siem.sh pipeline`) corre, en orden:

1. **collector** — captura nueva de Elasticsearch. **Tolerable:** si ES no
   responde, se usa la última captura guardada; si no hay ninguna, se clasifica
   solo desde `network_logs/`.
2. **classifier** — **crítica**: si falla, el ciclo se aborta (502) y el
   reporte anterior queda intacto.
3. **analyst** — **crítica**, mismo criterio. Le pide al audit las decisiones
   previas para el contexto histórico, y al knowledge su memoria. Esta última
   es **tolerable**: si knowledge no responde, analiza sin memoria y cada
   incidente queda con `aprendizaje.disponible = false`.
4. **audit** — registra la corrida en `analysis_history.jsonl`.

Un candado impide dos ciclos simultáneos (el segundo recibe 409).

### Operación

| Antes | Ahora |
|-------|-------|
| `python3 src/siem_pipeline.py` | `./scripts/siem.sh pipeline` |
| `python3 src/manage_users.py ...` | `./scripts/siem.sh usuarios ...` |
| `python3 src/audit_verify.py` | `./scripts/siem.sh auditoria` (o, desde el host, `python3 services/audit/audit_verify.py data/audit/decisions.jsonl`) |
| `python3 src/verify-cobertura.py` | `./scripts/siem.sh cobertura` |
| `python3 src/dashboard.py` | `docker compose up -d gateway` (levanta las dependencias) |
| `data/decisions.jsonl` | `data/audit/decisions.jsonl` |
| `data/siem_incidents.json` | `data/pipeline/siem_incidents.json` |
| `users.json` | `data/auth/users.json` |

Los contenedores corren sin privilegios con el UID/GID de quien despliega
(`SIEM_UID`/`SIEM_GID`, que fijan `start.sh` y `deploy.sh`), así los archivos de
`data/<servicio>/` siguen siendo del usuario y conservan los permisos `0600`.

### Pruebas

La suite no necesita Docker: `tests/conftest.py::malla_en_proceso` reemplaza el
transporte HTTP de `siem_servicios` por uno que entrega cada petición al cliente
de prueba Flask del servicio destino. Rutas, códigos, token y cuerpos son los
mismos. `servicio_caido("audit", ...)` simula contenedores caídos.
`tests/integration/test_microservicios.py` cubre los contratos propios de la
malla.

### Memoria del Agente 2

Un "Gem" de Gemini es un prompt fijo más archivos de conocimiento: no aprende
con el uso, y no se puede invocar por API. El Agente 2 replica lo útil de esa
idea y le suma aprendizaje supervisado:

| Pieza | Dónde | Cómo crece |
|-------|-------|------------|
| **Perfil** (la parte "Gem") | `services/analyst/perfil_agente.md` | Se edita a mano y se versiona. Define personalidad y forma de trabajar. Las reglas de seguridad (no seguir instrucciones de los logs, no generar comandos) quedan en el código, fuera del perfil editable. |
| **Documentos** | `data/knowledge/documentos.json` | Un analista los carga desde el panel (`.txt`/`.md`, hasta 32 KB). Ante cada incidente se buscan los **párrafos** que mencionan sus IPs, usuarios, hosts o el tipo de ataque. |
| **Casos** | `data/knowledge/casos.json` | Cada aprobación/descarte del panel se guarda como caso resuelto. Ante un incidente nuevo se citan hasta 3 parecidos (mismo tipo de ataque, misma IP, mismo usuario). |
| **Lecciones** | `data/knowledge/lecciones.json` | El sistema propone una cuando el mismo patrón (tipo de ataque + IP) se decide igual en 2 incidentes distintos — `falso_positivo` si siempre se descartó, `reincidente` si siempre se aprobó. Un analista también puede escribir una. **Toda lección nace "propuesta" y solo se usa una vez aprobada por alguien con permiso `decidir`.** |

**Por qué la aprobación es manual.** Parte de los datos de un incidente los
controla el atacante. Si el sistema aprendiera solo, alguien podría
"entrenarlo" generando incidentes que se descartan hasta que su IP quedara
marcada como ruido. Con aprobación manual, la IA sugiere qué aprender y el
humano decide, igual que con las acciones de contención.

**Qué cambia una lección aprobada.** La lección se le muestra al LLM y al
analista, y además ajusta **solo** la probabilidad de falso positivo (`HIGH`
si es `falso_positivo` y `LOW` si es `reincidente`). Queda registrado qué
lección lo hizo (`falso_positivo_ajustado_por`) y qué valor había antes. Nunca
toca la severidad ni las acciones del playbook. Se aplica igual con o sin LLM,
así que el agente aprende aunque `SIEM_USE_LLM=false`.

**Límites, declarados.** La búsqueda es por coincidencia de términos y no por
embeddings: alcanza para la demo y no depende de ninguna API, pero no
encuentra sinónimos. Una lección revisada no se reabre, y una rechazada no se
vuelve a proponer. `reset.sh` no borra la memoria. Los cambios de estado de una
lección guardan quién y cuándo, pero no van a la cadena de hash de `audit`.

### Limitaciones conocidas

- **IP del cliente en el control de intentos.** Con el puerto publicado por
  Docker (vía `docker-proxy` en loopback), el gateway puede ver como origen la
  IP del puente de Docker en vez de la del navegador. El límite de intentos sigue funcionando por usuario, pero ya no
  distingue entre clientes. Como el puerto solo se publica en loopback, todos
  los clientes son locales igual.
- **Sin TLS entre servicios.** El tráfico interno viaja en claro dentro de
  `ia-net`, que no se publica. El token es defensa en profundidad, no cifrado.
- **Un solo worker en auth y pipeline.** El control de intentos y el candado
  de ciclos viven en memoria. Escalar esos dos servicios horizontalmente
  exigiría llevar ese estado a un almacén compartido.

