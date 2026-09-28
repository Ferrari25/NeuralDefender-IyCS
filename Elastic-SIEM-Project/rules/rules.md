# Catálogo de reglas de detección (Elastic Security)

13 configuraciones de reglas para los 3 tipos de ataque del proyecto. Cada una
trae las 4 secciones del asistente de Kibana (**Define / About / Schedule / Rule
actions**), con variaciones de severidad, riesgo, nombre y descripción para ver
**cómo salta cada alerta**.

> ## ⚡ No hace falta crearlas a mano
>
> Las 13 están **versionadas** en [`ndjson/`](ndjson/), una por archivo, y se
> despliegan con un comando:
>
> ```bash
> ./scripts/deploy-rules.sh      # importa las 13 y las habilita
> ./scripts/export-rules.sh      # el camino inverso: Kibana → repositorio
> ```
>
> `scripts/start.sh` ya lo hace al levantar el stack. Este documento pasa a ser
> la **explicación** de cada regla; el archivo NDJSON es la fuente de verdad.
> Antes había que recrearlas en la consola, y quien clonaba el repositorio no
> obtenía el mismo sistema (hallazgo F-02, requisito `RF-DIF-03`).

### ⚠️ Los campos de agrupación llevan `.keyword`

Este documento nombra los campos como los muestra el asistente de Kibana
(`source_ip`, `tags`, `user`, `dest_ip`, `host.ip`, `event_type`,
`http_method`). En el índice `filebeat-*` **todos esos están mapeados como
`text`**, y agrupar o correlacionar por un campo `text` falla:

```
Fielddata is disabled on [source_ip]. Text fields are not optimised for
operations that require per-document field data like aggregations.
```

Por eso los archivos de `ndjson/` usan el subcampo `.keyword`
(`source_ip.keyword`, `tags.keyword`…). Una regla threshold o EQL que agrupe por
el campo a secas **no corre**. Hay una prueba que lo vigila:
`tests/unit/test_reglas_como_codigo.py::test_los_campos_de_agrupacion_usan_keyword`.

Los campos que **no** necesitan sufijo son `dest_port` (`long`) y
`credential_submission` (`boolean`).

## Referencia de campos de los datos del proyecto

| Campo | Valores / ejemplo | Fuente |
|-------|-------------------|--------|
| `tags` | `authentication_failure`, `authentication_success`, `invalid_user`, `port_scan` | Logstash |
| `message` | `Failed password for testuser from 172.18.0.6 ...` | logs SSH |
| `source_ip` | IP del atacante (extraída por grok) | Logstash |
| `user` | usuario objetivo | Logstash |
| `host.ip` | IP(s) del host que reporta | Filebeat |
| `source_type` | `network_traffic`, `system_logs` | Filebeat |
| `event_type` | `network_flow`, `http_request` | network_logs |
| `dest_port`, `dest_ip` | puerto/host sondeado | network_logs |
| `credential_submission` | `true` cuando se envían credenciales | network_logs |
| `url`, `http_method`, `username` | `/login`, `POST`, `testuser` | network_logs |

Índice para todas las reglas: **`filebeat-*`**.

## Resumen (cómo salta cada una)

| # | Nombre | Tipo | Severidad | Riesgo | Dispara cuando… |
|---|--------|------|-----------|--------|-----------------|
| A1 | SSH Brute Force – Basic Threshold | Threshold | Medium | 47 | ≥5 fallos por host.ip en 5 min |
| A2 | SSH Brute Force – Aggressive per Source IP | Threshold | High | 73 | ≥10 fallos por source_ip en 1 min |
| A3 | SSH Invalid User Enumeration | Threshold | Medium | 50 | ≥3 "Invalid user" por source_ip |
| A4 | SSH Successful Login After Brute Force | EQL | Critical | 95 | fallo→éxito mismo host en 10 min |
| A5 | SSH High-Volume Credential Attack | Threshold | Critical | 88 | ≥50 fallos por source_ip en 5 min |
| A6 | SSH Brute Force – Multiple Users Targeted | Threshold | High | 70 | 1 IP ataca ≥5 usuarios distintos |
| B1 | Port Scan – Many Distinct Ports | Threshold (cardinality) | High | 73 | 1 IP toca ≥10 puertos distintos |
| B2 | Port Scan – Horizontal (Multiple Hosts) | Threshold (cardinality) | High | 75 | 1 IP toca ≥5 hosts distintos |
| B3 | Sensitive Port Probe | Custom query | Medium | 55 | sondeo a 22/3389/445/3306… |
| B4 | Port Scan – Rapid Sequential Probe | EQL | Medium | 50 | 3 probes encadenados misma IP |
| C1 | Credential Submission to Suspicious Login | Custom query | High | 68 | POST con credenciales a /login |
| C2 | Repeated Credential Harvesting | Threshold | High | 72 | ≥3 envíos de credenciales por IP |
| C3 | Phishing Page Visit + Submission | EQL | Medium | 60 | GET seguido de POST con creds |

Cada código corresponde a un archivo: `A1` → `ndjson/A1-ssh-brute-force-basic-threshold.ndjson`.

---

# A · SSH Brute Force / autenticación (MITRE T1110)

## A1 · SSH Brute Force – Basic Threshold

**Define rule**
- Rule type: **Threshold**
- Source / Index patterns: `filebeat-*`
- Custom query (KQL): `tags:authentication_failure OR message:*Failed password*`
- Group by: `host.ip`
- Threshold: `5`
- Cardinality: *(vacío)*
- Alert suppression: *(no)*

**About rule**
- Name: `SSH Brute Force – Basic Threshold`
- Description: `Detecta 5 o más fallos de autenticación SSH desde el mismo host en una ventana corta. Línea base de detección de fuerza bruta.`
- Default severity: **Medium**
- Default risk score: **47**
- Reference URLs: `https://attack.mitre.org/techniques/T1110/`
- False positives: `Usuarios que olvidaron su contraseña y reintentaron varias veces.`
- MITRE ATT&CK: Tactic **Credential Access (TA0006)** → Technique **Brute Force (T1110)**
- Tags: `brute-force`, `authentication`, `ssh`, `credential-access`
- Investigation guide (advanced): `Revisar source_ip y user. ¿La IP es interna/conocida? ¿Hubo un authentication_success posterior?`
- Author: `SIEM-IA`  ·  License: `DRL`

**Schedule rule**
- Runs every: `5m`
- Additional look-back time: `1m`

**Rule actions**
- Action frequency: `Per rule run` (resumen, no por alerta)
- Connector: *(ninguno en demo; en prod: Slack/Email/Webhook al dashboard)*

---

## A2 · SSH Brute Force – Aggressive per Source IP

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `tags:authentication_failure`
- Group by: `source_ip`
- Threshold: `10`

**About rule**
- Name: `SSH Brute Force – Aggressive per Source IP`
- Description: `Una misma IP de origen acumula 10+ fallos de autenticación en 1 minuto: patrón de herramienta automatizada (Hydra/Medusa).`
- Default severity: **High**
- Default risk score: **73**
- Severity override (advanced): `risk_score >= 85 → Critical`
- MITRE: Credential Access → Brute Force (T1110) → sub-técnica **Password Guessing (T1110.001)**
- Tags: `brute-force`, `ssh`, `automated`, `hydra`
- False positives: `Scanners de vulnerabilidades autorizados; equipos de pentesting.`

**Schedule rule**
- Runs every: `1m`
- Additional look-back time: `1m`

**Rule actions**
- Action frequency: `For each alert`
- Connector: *(webhook al pipeline de IA — opcional)*

---

## A3 · SSH Invalid User Enumeration

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `tags:invalid_user OR message:*Invalid user*`
- Group by: `source_ip`
- Threshold: `3`

**About rule**
- Name: `SSH Invalid User Enumeration`
- Description: `Una IP prueba múltiples nombres de usuario inexistentes: reconocimiento/enumeración de cuentas previo a la fuerza bruta.`
- Default severity: **Medium**
- Default risk score: **50**
- MITRE: Credential Access → Brute Force (T1110); también **Discovery / Account Discovery (T1087)**
- Tags: `enumeration`, `ssh`, `reconnaissance`
- References: `https://attack.mitre.org/techniques/T1087/`
- False positives: `Errores de tipeo del nombre de usuario por usuarios legítimos.`

**Schedule rule**
- Runs every: `5m` · Look-back: `2m`

**Rule actions**
- Action frequency: `Per rule run`

---

## A4 · SSH Successful Login After Brute Force

**Define rule**
- Rule type: **Event Correlation (EQL)**
- Index patterns: `filebeat-*`
- EQL query:
  ```eql
  sequence by host.ip with maxspan=10m
    [ any where "authentication_failure" in tags ]
    [ any where "authentication_success" in tags ]
  ```

**About rule**
- Name: `SSH Successful Login After Brute Force`
- Description: `CRÍTICO: un login EXITOSO tras una ráfaga de fallos desde el mismo host. Indica que la fuerza bruta funcionó y hay un acceso comprometido.`
- Default severity: **Critical**
- Default risk score: **95**
- MITRE: Credential Access → Brute Force (T1110); **Initial Access / Valid Accounts (T1078)**
- Tags: `brute-force`, `compromise`, `lateral-movement`, `critical`
- Investigation guide: `Aislar el host. Verificar la sesión del user. Rotar credenciales YA. Revisar comandos ejecutados post-login.`
- False positives: `Usuario legítimo que falló varias veces y luego acertó su contraseña.`

**Schedule rule**
- Runs every: `5m` · Look-back: `5m`

**Rule actions**
- Action frequency: `For each alert`  ·  Connector: *(PagerDuty/Email — escalamiento inmediato)*

---

## A5 · SSH High-Volume Credential Attack

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `tags:authentication_failure`
- Group by: `source_ip`
- Threshold: `50`

**About rule**
- Name: `SSH High-Volume Credential Attack`
- Description: `Ataque de fuerza bruta masivo: 50+ fallos desde una IP en 5 minutos. Diccionario grande / ataque sostenido.`
- Default severity: **Critical**
- Default risk score: **88**
- MITRE: Credential Access → Brute Force (T1110)
- Tags: `brute-force`, `high-volume`, `ssh`, `critical`
- False positives: `Muy improbable; un volumen así casi siempre es malicioso.`

**Schedule rule**
- Runs every: `5m` · Look-back: `1m`

**Rule actions**
- Action frequency: `For each alert`

---

## A6 · SSH Brute Force – Multiple Users Targeted

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `tags:authentication_failure`
- Group by: `source_ip`
- Threshold: `5`
- Cardinality (advanced): when field **`user`** cardinality is **>= 5**

**About rule**
- Name: `SSH Brute Force – Multiple Users Targeted`
- Description: `Una IP intenta autenticarse contra 5+ usuarios distintos: password spraying en vez de fuerza bruta sobre una sola cuenta.`
- Default severity: **High**
- Default risk score: **70**
- MITRE: Credential Access → Brute Force → **Password Spraying (T1110.003)**
- Tags: `password-spraying`, `ssh`, `credential-access`
- References: `https://attack.mitre.org/techniques/T1110/003/`

**Schedule rule**
- Runs every: `10m` · Look-back: `2m`

**Rule actions**
- Action frequency: `Per rule run`

---

# B · Port Scan / reconocimiento de red (MITRE T1046)

## B1 · Port Scan – Many Distinct Ports

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `source_type:network_traffic AND event_type:network_flow`
- Group by: `source_ip`
- Threshold: `1`
- Cardinality: when field **`dest_port`** cardinality is **>= 10**

**About rule**
- Name: `Port Scan – Many Distinct Ports`
- Description: `Una IP sondea 10 o más puertos distintos del mismo objetivo: escaneo de puertos (reconocimiento previo a un ataque).`
- Default severity: **High**
- Default risk score: **73**
- MITRE: Tactic **Discovery (TA0007)** → **Network Service Discovery (T1046)**
- Tags: `port-scan`, `reconnaissance`, `network`, `nmap`
- References: `https://attack.mitre.org/techniques/T1046/`
- False positives: `Herramientas de monitoreo/inventario autorizadas (ej. Nessus, escáneres internos).`

**Schedule rule**
- Runs every: `5m` · Look-back: `5m`

**Rule actions**
- Action frequency: `For each alert`

---

## B2 · Port Scan – Horizontal (Multiple Hosts)

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `source_type:network_traffic AND event_type:network_flow`
- Group by: `source_ip`
- Threshold: `1`
- Cardinality: when field **`dest_ip`** cardinality is **>= 5**

**About rule**
- Name: `Port Scan – Horizontal (Multiple Hosts)`
- Description: `Una IP sondea el mismo puerto en 5+ hosts distintos: barrido horizontal buscando un servicio específico en la red.`
- Default severity: **High**
- Default risk score: **75**
- MITRE: Discovery → **Network Service Discovery (T1046)**; **Remote System Discovery (T1018)**
- Tags: `port-scan`, `horizontal-scan`, `lateral-movement`, `network`

**Schedule rule**
- Runs every: `5m` · Look-back: `5m`

**Rule actions**
- Action frequency: `Per rule run`

---

## B3 · Sensitive Port Probe

**Define rule**
- Rule type: **Custom query**
- Index patterns: `filebeat-*`
- Custom query: `event_type:network_flow AND dest_port:(22 OR 23 OR 445 OR 3306 OR 3389 OR 5432 OR 9200)`

**About rule**
- Name: `Sensitive Port Probe`
- Description: `Sondeo a puertos sensibles (SSH, Telnet, SMB, bases de datos, RDP, Elasticsearch). Aún un solo intento es relevante en estos servicios.`
- Default severity: **Medium**
- Default risk score: **55**
- Risk score override (advanced): `dest_port:3389 → 70` (RDP expuesto = mayor riesgo)
- MITRE: Discovery → **Network Service Discovery (T1046)**
- Tags: `port-probe`, `sensitive-services`, `network`
- False positives: `Health-checks internos hacia esos puertos.`

**Schedule rule**
- Runs every: `5m` · Look-back: `2m`

**Rule actions**
- Action frequency: `Per rule run`

---

## B4 · Port Scan – Rapid Sequential Probe

**Define rule**
- Rule type: **Event Correlation (EQL)**
- Index patterns: `filebeat-*`
- EQL query:
  ```eql
  sequence by source_ip with maxspan=30s
    [ any where event_type == "network_flow" ]
    [ any where event_type == "network_flow" ]
    [ any where event_type == "network_flow" ]
  ```

**About rule**
- Name: `Port Scan – Rapid Sequential Probe`
- Description: `Tres o más conexiones de red en menos de 30s desde la misma IP: cadencia típica de un escaneo automatizado (nmap -T4/5).`
- Default severity: **Medium**
- Default risk score: **50**
- MITRE: Discovery → **Network Service Discovery (T1046)**
- Tags: `port-scan`, `timing`, `automated`

**Schedule rule**
- Runs every: `5m` · Look-back: `5m`

**Rule actions**
- Action frequency: `Per rule run`

---

# C · Phishing / captura de credenciales (MITRE T1566)

## C1 · Credential Submission to Suspicious Login

**Define rule**
- Rule type: **Custom query**
- Index patterns: `filebeat-*`
- Custom query: `event_type:http_request AND credential_submission:true AND url:*login*`

**About rule**
- Name: `Credential Submission to Suspicious Login`
- Description: `Se enviaron credenciales (usuario+contraseña) a una página de login sospechosa. Posible captura de credenciales (phishing).`
- Default severity: **High**
- Default risk score: **68**
- MITRE: Tactic **Initial Access (TA0001)** → **Phishing (T1566)**; **Credentials Input Capture (T1056)**
- Tags: `phishing`, `credential-harvesting`, `web`, `initial-access`
- References: `https://attack.mitre.org/techniques/T1566/`
- Investigation guide: `Identificar al usuario afectado, forzar reset de credenciales, dar de baja la página falsa.`
- False positives: `Logins legítimos a aplicaciones internas que casualmente matcheen el patrón.`

**Schedule rule**
- Runs every: `1m` · Look-back: `1m`

**Rule actions**
- Action frequency: `For each alert`

---

## C2 · Repeated Credential Harvesting

**Define rule**
- Rule type: **Threshold**
- Index patterns: `filebeat-*`
- Custom query: `event_type:http_request AND credential_submission:true`
- Group by: `source_ip`
- Threshold: `3`

**About rule**
- Name: `Repeated Credential Harvesting`
- Description: `Una misma IP recibe 3+ envíos de credenciales: campaña de phishing activa capturando a varias víctimas.`
- Default severity: **High**
- Default risk score: **72**
- MITRE: Initial Access → **Phishing (T1566)**
- Tags: `phishing`, `campaign`, `credential-harvesting`

**Schedule rule**
- Runs every: `5m` · Look-back: `2m`

**Rule actions**
- Action frequency: `Per rule run`

---

## C3 · Phishing Page Visit + Submission

**Define rule**
- Rule type: **Event Correlation (EQL)**
- Index patterns: `filebeat-*`
- EQL query:
  ```eql
  sequence by source_ip with maxspan=5m
    [ any where event_type == "http_request" and http_method == "GET" ]
    [ any where event_type == "http_request" and credential_submission == true ]
  ```

**About rule**
- Name: `Phishing Page Visit + Submission`
- Description: `Secuencia completa de phishing: la víctima visita la página falsa (GET) y luego envía sus credenciales (POST). Confirma el ciclo de captura.`
- Default severity: **Medium**
- Default risk score: **60**
- MITRE: Initial Access → **Phishing (T1566)** → **Spearphishing Link (T1566.002)**
- Tags: `phishing`, `kill-chain`, `web`

**Schedule rule**
- Runs every: `5m` · Look-back: `5m`

**Rule actions**
- Action frequency: `For each alert`

---

## Notas sobre los ajustes avanzados

- **Severity / Risk score override:** permite que la severidad o el riesgo de cada
  alerta varíe según un campo del evento (ej. `dest_port:3389 → riesgo 70`).
- **Cardinality (Threshold):** además de contar documentos, exige que un campo
  tenga N valores distintos (ej. 10 puertos distintos) — clave para port scan.
- **Alert suppression:** agrupa alertas repetidas por un campo durante un período
  para no inundar al analista (útil en A2/A5).
- **Investigation guide:** texto que aparece en la alerta para guiar al analista;
  alimenta el "criterio" que también muestra el dashboard de IA.
- **Rule actions → frequency:** `Per rule run` (un resumen por corrida) vs
  `For each alert` (notifica por cada alerta) — usar `For each alert` solo en
  severidades altas/críticas para no saturar.
- Tras crear/ajustar una regla, exportala (Rules → Export) y guardala como código
  en `.claude/claude-context/outputs/detection-rules/` para versionarla.
