# 07 · Configurar las reglas de detección en Elastic

> **Desde el 17-09-2026 las reglas no se crean a mano.** Las 13 están versionadas
> en [`../rules/ndjson/`](../rules/ndjson/) y se despliegan con
> `./scripts/deploy-rules.sh` (lo hace `start.sh` automáticamente). Este
> documento explica **cómo funciona** una regla y cómo se crearía desde la
> consola; el archivo NDJSON es la fuente de verdad. Ver
> [`12-registro-de-pruebas.md`](12-registro-de-pruebas.md) §4.8.

Para que el SIEM **genere una alerta** a partir de los logs, hace falta una **regla de detección**
en Kibana (Elastic Security). Esta guía explica cómo crearla paso a paso para el ataque de fuerza
bruta SSH, y cómo se manejan los otros dos ataques.

> Sin regla no hay alerta: Logstash ingiere los logs a Elasticsearch, pero es la regla la que
> evalúa el umbral y escribe en `.alerts-security.alerts-default` (el índice que después lee
> `prepare-for-ia.py`).

> Esta guía cubre **una** regla en detalle, a modo de tutorial. Para el catálogo completo de
> **13 reglas listas para crear** (con severidad, riesgo y variantes por tipo de ataque) y para
> saber **cuáles vale la pena activar** sin generar ruido, ver
> [`rules/rules.md`](../rules/rules.md) y [`docs/alertas/`](alertas/README.md).

## Requisitos previos

1. El stack está levantado y Kibana abre en `http://127.0.0.1:5601` (ver [03 · Instalación](03-instalacion-y-montaje.md)).
2. **Ya hay datos en `filebeat-*`.** La regla solo dispara si existen logs. Corré al menos una vez
   la simulación de fuerza bruta para tener `authentication_failure` en el índice (ver
   [05 · Simulaciones](05-simulaciones-de-ataque.md)).
3. Kibana tiene la clave de cifrado de saved objects configurada (`KIBANA_SAVEDOBJECTS_KEY` →
   `xpack.encryptedSavedObjects.encryptionKey`). Ya está en `kibana.yml`; es lo que permite habilitar
   el motor de detección.

## Paso 1 — Crear el data view (si no existe)

1. Kibana → menú **☰ → Stack Management → Data Views → Create data view**.
2. Name: `filebeat-*` · Index pattern: `filebeat-*` · Timestamp field: `@timestamp`.
3. Guardar.

## Paso 2 — Habilitar el motor de detección

1. Kibana → **☰ → Security → Alerts**.
2. La primera vez, Kibana pide habilitar las detecciones (crea los índices de alertas).
   Aceptar. Si pide permisos, iniciá sesión como `elastic`.

## Paso 3 — Crear la regla *Threshold* (fuerza bruta SSH, T1110)

1. **Security → Rules → Detection rules (SIEM) → Create new rule**.
2. Tipo de regla: **Threshold**.
3. **Definir la fuente y la condición:**
   - **Source / Index patterns:** `filebeat-*`
   - **Custom query (KQL):**
     ```
     tags:authentication_failure OR message:*Failed password* OR message:*authentication failure*
     ```
   - **Group by field:** `host.ip`
   - **Threshold:** `5`

   > ¿Por qué 5 y no un número más chico? Con un umbral muy bajo (2-3) cualquier
   > usuario que se equivoca de contraseña dispara la regla — puro ruido. Este
   > umbral (el de la **regla de Kibana**, que decide cuándo el SIEM escribe una
   > alerta) es independiente del `BRUTE_FORCE_THRESHOLD = 20` de
   > `classifier.py` (el umbral con el que el **Agente 1** corrobora el patrón
   > por su cuenta, incluso sin alerta de Kibana, mirando directamente
   > `siem_clean.json`). Son dos capas de detección a propósito, no un valor
   > inconsistente: ver [`../docs/alertas/README.md`](alertas/README.md).
4. **About rule:**
   - **Name:** `Detección de ataques de fuerza bruta`
   - **Description:** `Detecta múltiples fallos de autenticación desde una misma IP (fuerza bruta SSH).`
   - **Severity:** `High` · **Risk score:** `73`
   - **Tags:** `brute-force`, `authentication`, `credential-access`
   - **MITRE ATT&CK:** táctica *Credential Access* → técnica *Brute Force (T1110)*
   - **False positives:** `Usuarios que olvidaron su contraseña y reintentaron`
5. **Schedule:**
   - **Runs every:** `5m`
   - **Additional look-back time:** `1m`
6. **Create & enable rule.**

> Capturas paso a paso de esta misma regla en [`../brute_force.md`](../brute_force.md).

## Paso 4 — Disparar y verificar

```bash
# generar la fuerza bruta (con el stack y la simulación arriba)
docker compose --profile simulation up -d ssh-target hydra-attacker
bash simulation/run-brute-force.sh
```

1. Esperá 5–10 minutos (la regla corre cada 5m).
2. Kibana → **Security → Alerts** → debería aparecer la alerta *Detección de ataques de fuerza bruta*.
3. Confirmá por API que el índice de alertas tiene documentos:
   ```bash
   curl -s -u elastic:$ELASTIC_PASSWORD \
     "http://127.0.0.1:9200/.alerts-security.alerts-default/_count"
   ```

A partir de acá, `python3 prepare-for-ia.py` ya puede extraer la alerta hacia la capa IA.

## Port scan y phishing SÍ tienen regla — vía la capa IA como fuente

A diferencia de lo que podría suponerse por no tener Suricata desplegado, **estas dos SÍ
tienen reglas reales creadas y activas** en este proyecto — porque las simulaciones escriben
los eventos de red/web como NDJSON en `network_logs/`, que Filebeat ingiere al **mismo**
índice `filebeat-*` (input `network-traffic`, ver [06 · Flujo de datos](06-flujo-de-datos.md)).
No hace falta Suricata: la fuente de eventos ya está en Elasticsearch, solo hace falta
escribir la condición correcta.

| Ataque | Tipo de regla | Condición | MITRE |
|--------|---------------|-----------|-------|
| Port scan | Threshold + cardinalidad | agrupar por `source_ip.keyword`, cardinalidad de `dest_port` ≥ 10 | T1046 |
| Phishing | Custom query | `event_type:http_request and credential_submission:true and url:*login*` | T1566 |

Las 4 reglas de Nivel 1 de [`docs/alertas/01-alertas-recomendadas.md`](alertas/01-alertas-recomendadas.md)
(SSH agresivo, login exitoso tras fuerza bruta, port scan, phishing) están **creadas y
corriendo** en este despliegue:

![Reglas activas en Kibana](../screenshots/kibana-reglas-de-deteccion.png)

## Detection-as-code: crear reglas por API (recomendado)

Crear una regla a mano en la UI, paso a paso, sirve para entender qué hace cada campo (por
eso el Paso 3 de arriba) — pero **no es reproducible**: si el stack se reinicia desde cero,
hay que volver a clickear todo. La forma reproducible es la **API de Detection Engine de
Kibana**, que además es justo lo que se usó para crear las 4 reglas activas de este
despliegue.

### Paso 0 — Habilitar el motor de detección (una sola vez)

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/index" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json'
```

### Ejemplo — la regla de fuerza bruta (Threshold)

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "ssh-brute-force-aggressive-per-source-ip",
    "type": "threshold",
    "name": "SSH Brute Force – Aggressive per Source IP",
    "description": "Una misma IP acumula 10+ fallos de auth SSH en 1 minuto.",
    "severity": "high",
    "risk_score": 73,
    "index": ["filebeat-*"],
    "query": "tags:authentication_failure",
    "language": "kuery",
    "threshold": {"field": ["source_ip.keyword"], "value": 3},
    "from": "now-2m",
    "interval": "1m",
    "enabled": true,
    "threat": [{
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0006", "name": "Credential Access", "reference": "https://attack.mitre.org/tactics/TA0006/"},
      "technique": [{"id": "T1110", "name": "Brute Force", "reference": "https://attack.mitre.org/techniques/T1110/"}]
    }]
  }'
```

> **Gotcha real que nos costó dos intentos:** `source_ip`, `user` y `tags` los indexa
> Elasticsearch por defecto como `text` (analizado, no agregable). Un `threshold` que agrupe
> por `source_ip` falla con `Fielddata is disabled`. Hay que usar el subcampo automático
> `source_ip.keyword` (agregable) — Elasticsearch lo crea solo para todo campo `text`, salvo
> que el mapping diga lo contrario. Mismo problema con reglas EQL: `tags.keyword == "valor"`,
> no `tags == "valor"`.

### Ejemplo — port scan (Threshold con cardinalidad)

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "port-scan-many-distinct-ports",
    "type": "threshold",
    "name": "Port Scan – Many Distinct Ports",
    "description": "Una IP sondea 10+ puertos distintos del mismo objetivo.",
    "severity": "high",
    "risk_score": 73,
    "index": ["filebeat-*"],
    "query": "event_type:network_flow",
    "language": "kuery",
    "threshold": {"field": ["source_ip.keyword"], "value": 1,
                  "cardinality": [{"field": "dest_port", "value": 10}]},
    "from": "now-5m",
    "interval": "1m",
    "enabled": true
  }'
```

`dest_port` es `long` (numérico), así que ese sí es agregable sin `.keyword`.

### Ejemplo — phishing (Custom query, sin threshold)

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "credential-submission-suspicious-login",
    "type": "query",
    "name": "Credential Submission to Suspicious Login",
    "description": "Envio de credenciales a una pagina de login sospechosa.",
    "severity": "high",
    "risk_score": 68,
    "index": ["filebeat-*"],
    "query": "event_type:http_request and credential_submission:true and url:*login*",
    "language": "kuery",
    "from": "now-2m",
    "interval": "1m",
    "enabled": true
  }'
```

### Ejemplo — login exitoso tras fuerza bruta (EQL, correlación entre eventos)

```bash
curl -s -u elastic:$ELASTIC_PASSWORD -X POST \
  "http://127.0.0.1:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
    "rule_id": "ssh-successful-login-after-brute-force",
    "type": "eql",
    "name": "SSH Successful Login After Brute Force",
    "description": "Login EXITOSO justo despues de una rafaga de fallos desde la misma IP.",
    "severity": "critical",
    "risk_score": 95,
    "index": ["filebeat-*"],
    "query": "sequence by source_ip.keyword with maxspan=10m\n  [any where tags.keyword == \"authentication_failure\"]\n  [any where tags.keyword == \"authentication_success\"]",
    "language": "eql",
    "from": "now-11m",
    "interval": "5m",
    "enabled": true
  }'
```

### Verificar que corrieron y ver las alertas

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

### Ventajas de crear las reglas así

- **Reproducible:** el mismo `curl` recrea la regla en cualquier despliegue nuevo, sin
  clickear la UI.
- **Versionable:** el JSON del body se puede commitear tal cual (a diferencia del export
  `.ndjson` de Kibana, que trae metadata interna innecesaria para versionar).
- **Auditable:** queda un comando explícito de qué reglas existen y con qué configuración,
  en vez de "lo que haya quedado clickeado en la UI".
