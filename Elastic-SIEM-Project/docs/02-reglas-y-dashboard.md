# 02 · Reglas de detección y dashboard

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).

## Reglas de detección en Kibana

**Las reglas no se crean a mano.** Las 14 del catálogo viven versionadas en
[`rules/ndjson/`](../rules/ndjson/) y se despliegan con
`./scripts/deploy-rules.sh` (lo hace `start.sh` automáticamente). Este
documento explica **cómo funciona** una regla, cómo se vería crearla desde la
consola, y cuáles conviene tener activas — el NDJSON es la fuente de verdad,
[`rules/rules.md`](../rules/rules.md) es el catálogo técnico completo.

> Sin regla no hay alerta: Logstash ingiere los logs a Elasticsearch, pero es
> la regla la que evalúa el umbral y escribe en
> `.alerts-security.alerts-default` — el índice que después lee
> `src/prepare-for-ia.py`.

### Cómo se cruza cada tipo de ataque con las reglas

| Ataque | Técnica | ¿Hay reglas de Kibana? | ¿El clasificador detecta sin ellas? |
|--------|---------|:-----------------------:|:-------------------------------------:|
| SSH Brute Force | T1110 | Sí — A1 a A7 | Sí, leyendo logs de auth directamente |
| Port Scan | T1046 | Sí — B1 a B4 | Sí, leyendo `network_logs/` |
| Phishing | T1566 | Sí — C1 a C3 | Sí, leyendo `network_logs/` |

Los tres tipos tienen **dos caminos de detección** a propósito: si la alerta
de Kibana ya existe para esa IP, el panel muestra su nombre real y su
severidad; si todavía no llegó (las reglas corren cada varios minutos, no al
instante) o el stack estuviera caído, el clasificador (Agente 1) igual
detecta el patrón leyendo los eventos crudos — el panel entonces dice "Sin
regla SIEM (detección propia)", nunca inventa un nombre que no exista en
Kibana. Si más tarde la alerta real llega, correr el pipeline de nuevo
actualiza el incidente con la regla real — `verify-cobertura.py` (ver
[04 · Auditoría, pruebas y demostración](04-auditoria-pruebas-y-demostracion.md))
demuestra justamente que nada queda sin esa actualización.

### Crear una regla paso a paso, en la UI (tutorial: fuerza bruta SSH)

**Requisitos previos:** el stack levantado, Kibana en `http://127.0.0.1:5601`,
datos ya en `filebeat-*` (corré al menos una vez `run-brute-force.sh`).

1. **Data view** (si no existe): ☰ → Stack Management → Data Views → Create.
   Name/Index pattern: `filebeat-*` · Timestamp: `@timestamp`.
2. **Habilitar el motor de detección**: ☰ → Security → Alerts, aceptar el
   prompt inicial (crea los índices de alertas).
3. **Security → Rules → Detection rules (SIEM) → Create new rule.**
   - Tipo: **Threshold**.
   - Index patterns: `filebeat-*`.
   - Custom query (KQL): `tags:authentication_failure OR message:*Failed password*`
   - Group by: `host.ip` · Threshold: `5`.
   - Severity: `High` · Risk score: `73`.
   - MITRE ATT&CK: Credential Access → Brute Force (T1110).
   - Schedule: cada `5m`, look-back `1m`.
   - Create & enable.

> ¿Por qué 5 y no un número más chico? Con un umbral muy bajo (2-3) cualquier
> usuario que se equivoca de contraseña dispara la regla — puro ruido. Este
> umbral (el de la **regla de Kibana**) es independiente del
> `BRUTE_FORCE_THRESHOLD = 20` de `src/classifier.py` (el umbral con el que
> el **Agente 1** corrobora el patrón por su cuenta): son dos capas de
> detección a propósito, no un valor inconsistente.

**Verificar:**

```bash
docker compose --profile simulation up -d ssh-target hydra-attacker
bash simulation/run-brute-force.sh
# esperar 5-10 min (la regla corre cada 5m), después:
curl -s -u elastic:$ELASTIC_PASSWORD \
  "http://127.0.0.1:9200/.alerts-security.alerts-default/_count"
```

### Detection-as-code: crear reglas por API (el método real de este proyecto)

Crear una regla a mano en la UI sirve para entender qué hace cada campo, pero
**no es reproducible** — si el stack se reinicia, hay que volver a clickear
todo. La forma reproducible, y la que efectivamente generó las 14 reglas de
este despliegue, es la API de Detection Engine de Kibana.

```bash
# Habilitar el motor de detección (una sola vez)
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/index" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json'
```

Ejemplo — fuerza bruta SSH (Threshold):

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "ssh-brute-force-aggressive-per-source-ip",
    "type": "threshold",
    "name": "SSH Brute Force – Aggressive per Source IP",
    "description": "Una misma IP acumula 10+ fallos de auth SSH en 1 minuto.",
    "severity": "high", "risk_score": 73,
    "index": ["filebeat-*"],
    "query": "tags:authentication_failure", "language": "kuery",
    "threshold": {"field": ["source_ip.keyword"], "value": 3},
    "from": "now-2m", "interval": "1m", "enabled": true,
    "threat": [{
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0006", "name": "Credential Access", "reference": "https://attack.mitre.org/tactics/TA0006/"},
      "technique": [{"id": "T1110", "name": "Brute Force", "reference": "https://attack.mitre.org/techniques/T1110/"}]
    }]
  }'
```

> **Gotcha real que costó dos intentos:** `source_ip`, `user` y `tags` los
> indexa Elasticsearch por defecto como `text` (analizado, no agregable). Un
> `threshold` que agrupe por `source_ip` falla con `Fielddata is disabled`.
> Hay que usar el subcampo automático `source_ip.keyword` (agregable) — ES lo
> crea solo para todo campo `text`, salvo que el mapping diga lo contrario.
> Mismo problema con EQL: `tags.keyword == "valor"`, no `tags == "valor"`.

Ejemplo — port scan (Threshold con cardinalidad, `dest_port` es numérico y no
necesita `.keyword`):

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "port-scan-many-distinct-ports",
    "type": "threshold",
    "name": "Port Scan – Many Distinct Ports",
    "description": "Una IP sondea 10+ puertos distintos del mismo objetivo.",
    "severity": "high", "risk_score": 73,
    "index": ["filebeat-*"],
    "query": "event_type:network_flow", "language": "kuery",
    "threshold": {"field": ["source_ip.keyword"], "value": 1,
                  "cardinality": [{"field": "dest_port", "value": 10}]},
    "from": "now-5m", "interval": "1m", "enabled": true
  }'
```

Ejemplo — phishing (Custom query, sin threshold):

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "credential-submission-suspicious-login",
    "type": "query",
    "name": "Credential Submission to Suspicious Login",
    "description": "Envio de credenciales a una pagina de login sospechosa.",
    "severity": "high", "risk_score": 68,
    "index": ["filebeat-*"],
    "query": "event_type:http_request and credential_submission:true and url:*login*",
    "language": "kuery", "from": "now-2m", "interval": "1m", "enabled": true
  }'
```

Ejemplo — login exitoso tras fuerza bruta (EQL, correlación entre eventos,
severidad Critical):

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "ssh-successful-login-after-brute-force",
    "type": "eql",
    "name": "SSH Successful Login After Brute Force",
    "description": "Login EXITOSO justo despues de una rafaga de fallos desde la misma IP.",
    "severity": "critical", "risk_score": 95,
    "index": ["filebeat-*"],
    "query": "sequence by source_ip.keyword with maxspan=10m\n  [any where tags.keyword == \"authentication_failure\"]\n  [any where tags.keyword == \"authentication_success\"]",
    "language": "eql", "from": "now-11m", "interval": "5m", "enabled": true
  }'
```

Verificar que corrieron y ver las alertas:

```bash
curl -s -u elastic:$ELASTIC_PASSWORD "http://127.0.0.1:5601/api/detection_engine/rules/_find" \
  -H 'kbn-xsrf: true' | python3 -c "
import json, sys
for r in json.load(sys.stdin)['data']:
    ex = r.get('execution_summary', {}).get('last_execution', {})
    print(r['name'], '|', ex.get('status'))
"
curl -s -u elastic:$ELASTIC_PASSWORD "http://127.0.0.1:9200/.alerts-security.alerts-default/_count"
```

**Por qué así:** reproducible (el mismo `curl` recrea la regla en cualquier
despliegue nuevo), versionable (el JSON del body se commitea tal cual, a
diferencia del export `.ndjson` de Kibana con metadata interna), y auditable
(queda un comando explícito de qué reglas existen y con qué configuración).

### Qué reglas activar (para no volver a sufrir alert fatigue)

Activar las 14 de una — con equipos chicos, el escenario real que este
proyecto apunta a resolver — es la forma más rápida de terminar con un
dashboard saturado y recrear el mismo problema que el sistema existe para
evitar.

**Nivel 1 — imprescindibles (correspondencia directa con lo que el clasificador ya sabe explicar):**

| Regla | Por qué vale la pena |
|-------|----------------------|
| **A2 · SSH Brute Force – Aggressive per Source IP** | Caso de uso principal: 10+ fallos desde una misma IP en 1 min. Umbral alto → casi nunca falso positivo. |
| **A4 · SSH Successful Login After Brute Force** | La más importante: login **exitoso** justo después de una ráfaga de fallos = compromiso probable, no "posible ataque". |
| **B1 · Port Scan – Many Distinct Ports** | Cubre el segundo tipo de ataque (reconocimiento de red). |
| **C1 · Credential Submission to Suspicious Login** | Cubre el tercer tipo (phishing), con la certeza más alta posible. |

**Nivel 2 — recomendadas (una vez que el Nivel 1 esté estable):** A6 (*SSH
Brute Force – Multiple Users Targeted*, detecta password spraying), B3
(*Sensitive Port Probe*, un solo intento contra 3389/445/3306 ya es
relevante), C2 (*Repeated Credential Harvesting*, escala severidad cuando C1
ya disparó).

**Nivel 3 — opcionales:** A3 (*SSH Invalid User Enumeration*, un typo también
la dispara), B2 (*Port Scan Horizontal*, necesita una red con más hosts para
que el patrón se note).

**No incluidas por redundantes:** A1 y A5 (cubiertas por A2), C3 (redundante
con C1+C2), A7 (umbral 1 a propósito — ver abajo).

**Qué NO hacer:**
- **No bajar el `Threshold` de fuerza bruta a 2-3** — cualquiera que se
  equivoca de contraseña dos veces dispara la regla. **A7 · SSH Isolated
  Authentication Failure** (umbral 1, severidad Low) es la excepción
  deliberada: pensada para demostrar el escalón más bajo de la escalera de
  severidad, no para dejarla encendida en un entorno real.
- **No marcar todo como `Critical`** — si todas las severidades son iguales,
  la severidad deja de ser información.
- **No activar reglas que se pisan** sobre el mismo patrón (ej. A1 y A2
  juntas generan 2 alertas por el mismo evento).
- **No usar `For each alert` en severidades bajas/medias** — reservarlo para
  High/Critical.
- **No dejar `False positives` vacío** — es lo que le permite al analista
  descartar rápido sin dudar.

---

## El dashboard de supervisión

`http://127.0.0.1:5000` (`src/dashboard.py` + `templates/index.html`) —
abrilo en vivo junto con esta guía para ver cada elemento descripto acá.

> **Los iconos son SVG monocromos, no emoji.** Un emoji se dibuja con la
> paleta del sistema operativo, cambia de forma entre plataformas y no
> hereda el color del texto — en un panel donde el color significa
> severidad, eso compite con la información. El sprite vive en
> `templates/_iconos.html` y usa `currentColor`.

### Vista general

1. **Cabecera** — título, el link *Cómo funciona este panel*, y un badge que
   indica si el último análisis lo hizo la IA o el fallback determinístico.
2. **Barra de resumen** — cuántas acciones esperan una decisión humana (lo
   que el panel existe para resolver), el total de incidentes/acciones, y el
   desglose por severidad como barra apilada con las 4 severidades — incluso
   las que están en cero (un cero informa: "se miró y no hay críticos").
3. **Eventos de Seguridad Activos** (tabla, filtrable).
4. **Ataques Recientes** y **Historial de Decisiones** (columna lateral).

### Eventos de Seguridad Activos

Una fila por incidente:

| Columna | Qué muestra |
|---|---|
| **ID** | El `incident_id`. Ícono de eslabón si está vinculado a otros incidentes de la misma campaña. Tag "✔ resuelto" si ya se aprobó al menos una acción. |
| **Estado** | Badge de severidad ajustada por el Agente 2. |
| **IP origen** | La IP asociada al incidente. |
| **Tipo de ataque** | Ícono estable por tipo: candado = SSH, radar = escaneo, anzuelo = phishing. |
| **Regla disparada** | El nombre real de la regla de Kibana que lo confirmó, o "Sin regla SIEM (detección propia)". Nunca se inventa un nombre que no exista en el catálogo. |
| **Análisis de IA** | Primera oración de la explicación del Agente 2. |

Arriba: filtro por severidad, por tipo de ataque, y buscador por IP. Un click
en una fila expande la **card de detalle** debajo de la tabla.

### La card de detalle

De arriba hacia abajo:

- **Banner de campaña** (morado, con eslabón) — si el incidente comparte IP
  con otro(s) activos. Los IDs relacionados son links directos.
- **Ficha técnica** — regla del SIEM (o "sin regla asociada"), cantidad de
  eventos, técnica MITRE ATT&CK (linkeada a attack.mitre.org), probabilidad
  de falso positivo, ventana temporal.
- **De dónde salió el análisis** — banner arriba del bloque de análisis:
  *"Análisis generado por IA (Gemini)"* (destello) o *"Análisis
  determinístico — reglas fijas, sin IA"* (archivo). Nunca ambiguo.
- **Análisis en lenguaje claro** — qué pasó, metodología, riesgo en este
  entorno, referencias, y antecedentes de esta IP (contexto histórico).
- **Puntos a investigar** (lupa) — solo con IA: 2-4 preguntas concretas
  específicas de este incidente, no una plantilla. Su ausencia en un
  incidente con fallback es a propósito: esa diferencia ES la distinción
  entre los dos modos.
- **Por qué esta severidad** (bombilla) — factores concretos que el Agente 1
  usó para clasificar.
- **Evidencia** (lupa) — cronología cruda de eventos, puertos sondeados,
  URLs, usuarios objetivo, colapsable.
- **Acciones sugeridas** — responsable, plazo, comando con su explicación en
  lenguaje claro, y botones **Aprobar**/**Descartar**. Al descartar, el panel
  pide el motivo antes de confirmar — queda en la auditoría y le da contexto
  al Agente 2 la próxima vez.

### Ataques Recientes

Barra lateral, ordenada por severidad y luego por `last_seen`: ícono de tipo,
severidad, IP y tiempo relativo. Vista de "qué pasó últimamente", sin filtro.

### Historial de Decisiones

Agrupado **por incidente**, no por acción individual (con muchas acciones por
incidente, un historial plano se vuelve ilegible). Cada fila resume un
incidente ("N ✔ · M ✘") y se expande con un click para ver el detalle de
cada decisión. El archivo `data/decisions.jsonl` es append-only — cada click
agrega una línea nueva y nunca se borra nada. El panel deduplica por acción y
muestra la decisión más reciente de cada una; el archivo completo, con cada
revisión, se sigue auditando leyendo `data/decisions.jsonl` o vía
`GET /api/v1/decisions`.

### Correlación entre incidentes

Implementada en `src/classifier.py::_link_campaigns()`. Al terminar de
clasificar todos los incidentes de una corrida, el Agente 1 revisa si alguno
comparte IP atacante con otro — aunque vengan de detecciones distintas.
Ejemplo real: una misma IP hizo un escaneo de puertos y, poco después,
apareció fuerza bruta SSH contra el mismo host — sin correlación son 2
incidentes "Alta" sueltos; con correlación, el dashboard los marca como una
sola campaña de 2+ frentes, que es lo que realmente está pasando.

### Contexto histórico

Implementado en `src/siem_agent.py::historical_context()`. Antes de generar
el análisis, el Agente 2 busca en `data/decisions.jsonl` si ya hubo alguna
decisión sobre alguna de las IPs de este incidente, tomada en **otro**
incidente. Si encuentra algo, arma un resumen: cuántas decisiones previas,
cuántas aprobadas/descartadas, cuál fue la más reciente y quién la tomó.

### Explicabilidad

Implementado en `src/classifier.py::_classification()`, parámetro
`factores`. Cada rama de detección arma una lista de señales concretas que
sustentan la severidad — se puede señalar exactamente qué umbral se superó,
si el SIEM confirmó el patrón, cuántos hosts/usuarios están afectados. Es la
respuesta a "¿por qué la IA dice que esto es Alto y no Medio?" con una lista
verificable, no una caja negra.

### Dónde vive el código del panel

| Archivo | Qué contiene |
|---------|--------------|
| `templates/index.html` | Solo marcado (98 líneas). Referencia los estáticos con `url_for` |
| `static/app.js` | Toda la lógica del cliente |
| `static/app.css` | La hoja de estilos |
| `templates/login.html` + `static/login.js` | Pantalla de inicio de sesión |

**Por qué se separó del HTML.** Mientras el `<script>` vivía dentro de la
plantilla, ESLint no lo analizaba — corría sobre cero archivos. **Cómo se
escapa el contenido.** Todo el HTML se arma con la plantilla etiquetada
`html`, que escapa cada valor interpolado salvo los fragmentos que ella misma
produce; olvidarse de escapar ya no es posible.

**Cómo se prueba.** El JavaScript pasa por linters + SAST y por pruebas
unitarias que analizan el código fuente (ver
[04 · Auditoría, pruebas y demostración](04-auditoria-pruebas-y-demostracion.md)).
No hay todavía una suite E2E automatizada contra un navegador real
(`pytest-playwright` está en `requirements-dev.txt` pero comentado, es
trabajo pendiente) — la verificación contra el servidor real y un navegador
se hizo manualmente durante el desarrollo.
