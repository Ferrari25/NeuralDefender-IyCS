# 11 · Reporte de la Fase 0 — red de seguridad, certificación y linters

> **Fecha:** 16-09-2026 · **Alcance:** Fase 0 del [plan de acción](10-plan-de-accion.md) §8.
> **Estado:** completada. **No se modificó la lógica del sistema**: los siete módulos
> Python del proyecto están tal cual estaban al empezar. Lo único que cambió en el
> código existente es `.gitignore` (nuevas entradas al final).
>
> El objetivo de esta fase no era corregir nada, sino construir el instrumental que
> permite corregir sin romper: pruebas que congelan el comportamiento actual, una
> certificación automatizada de no-autonomía, y análisis estático configurado.

---

## 1. Resumen

| Objetivo | Resultado |
|----------|-----------|
| Red de seguridad (fixtures + caracterización) | **121 pruebas**, 119 pasan, 2 se omiten por diseño, en **1,3 s** |
| Cobertura sobre el alcance del plan §4.1 | **90 %** (objetivo de la Fase 2: ≥ 80 %) — ya superado |
| Certificación de no-autonomía por AST | **30 pruebas**, propiedad verificada y probada contra 4 mutantes |
| `pylint-secure-coding-standard` | Configurado y corriendo · score **9,19/10** |
| `eslint-plugin-security` | Configurado y validado · efectivo a partir del refactor R-05 |
| Puerta de calidad reproducible | `scripts/check.sh` — **17 s**, verde en la línea de base |

**Los 24 bugs del plan quedaron congelados como pruebas.** Cada uno tiene un test que
hoy pasa afirmando el comportamiento incorrecto y que **fallará cuando se corrija** —
que es exactamente lo que se busca: ninguna corrección de la Fase 1 puede pasar
inadvertida.

---

## 2. Lo que se creó

### 2.1 Archivos nuevos

```
tests/
  conftest.py                                 133 líneas   fixtures y aislamiento
  test_no_autonomy.py                         494 líneas   certificación por AST
  fixtures/
    siem_clean.min.json                                    captura real: 7 alertas + 12 logs
    auth_25_sin_alerta.json                                sintético: 25 fallos, 0 alertas
    network_logs/{port-scan,phishing}.json                 26 puertos · 2 eventos web
    malicious/{cmd-injection,xss-incident-id}.json          payloads de S-01 y S-02
  unit/
    test_classifier_caracterizacion.py         180 líneas   18 pruebas
    test_classifier_bugs_congelados.py         202 líneas   10 pruebas (bugs)
    test_siem_lib_caracterizacion.py           202 líneas   27 pruebas
  integration/
    test_api_caracterizacion.py                243 líneas   24 pruebas
    test_auditoria_append_only.py              252 líneas   12 pruebas

pytest.ini              configuración y marcas
requirements-dev.txt    dependencias de desarrollo
.pylintrc               pylint + pylint-secure-coding-standard
.bandit                 exclusiones de bandit
ruff.toml               estilo y reglas rápidas
eslint.config.js        eslint + security + no-unsanitized
package.json            dependencias JS de análisis
scripts/check.sh        puerta de calidad completa (102 líneas)
```

### 2.2 Instalación del entorno

Este equipo tiene el intérprete marcado como *externally managed* (PEP 668) y sin
`python3-venv`, así que las herramientas se instalan **en el proyecto**, sin tocar el
Python del sistema ni pedir `sudo`:

```bash
python3 -m pip install --target=.devtools -r requirements-dev.txt
export PYTHONPATH="$PWD/.devtools"
npm install

./scripts/check.sh          # puerta completa
.devtools/bin/pytest -q     # solo las pruebas
```

`.devtools/` y `node_modules/` quedaron agregados a `.gitignore`.

---

## 3. Red de seguridad: pruebas de caracterización

### 3.1 Principio

Una prueba de caracterización **no dice qué debería hacer el sistema**: documenta lo
que hace. Si `event_count` vale 1 cuando debería valer 12, la prueba afirma que vale 1.
Así, cuando la Fase 1 lo corrija, la prueba falla y la corrección queda registrada como
un cambio explícito y revisado, en vez de un efecto lateral silencioso.

Por eso hay dos grupos separados:

```bash
pytest -m "not bug"    # 97 pruebas · comportamiento correcto · deben estar SIEMPRE verdes
pytest -m bug          # 24 pruebas · bugs congelados · DEBEN fallar al corregirlos
```

### 3.2 Aislamiento

Los módulos del proyecto resuelven rutas contra el directorio actual
(`siem_incidents.json`, `decisions.jsonl`, `network_logs/`). La fixture `sandbox`
cambia el CWD a un `tmp_path` por prueba, de modo que **ninguna prueba toca los datos
reales**. Se verificó: tras correr la suite completa, `decisions.jsonl` y
`network_logs/` del proyecto quedan intactos.

### 3.3 Cobertura obtenida

| Módulo | Cobertura | Sin cubrir |
|--------|:---------:|------------|
| `classifier.py` | **90 %** | `main()` y la rama sub-umbral con alerta |
| `dashboard.py` | **95 %** | el bloque `__main__` |
| `siem_lib.py` | **88 %** | `es_aggregate()` (requiere ES real) |
| **Total (alcance §4.1)** | **90 %** | objetivo ≥ 80 % ✅ |

`siem_agent.py` queda en 29 % y **fuera del umbral a propósito**: su camino principal
depende de la API de Gemini. La Fase 2 agrega un cliente simulado.

### 3.4 Los 24 bugs congelados

| Prueba | Hallazgo | Afirma hoy que… |
|--------|:--------:|------------------|
| `test_L01_event_count_ignora_los_logs_siguientes` | L-01 | 12 logs reales ⇒ `event_count == 1` |
| `test_L01_ningun_incidente_solo_de_logs_alcanza_el_umbral` | L-01 | 25 fallos sin alerta ⇒ `suspicious_auth`, no fuerza bruta |
| `test_L02_un_ataque_produce_dos_incidentes` | L-02 | un ataque genera incidentes para `172.18.0.3` **y** `172.18.0.7` |
| `test_L03_playbook_emite_placeholder_teniendo_la_ip` | L-03 | el comando dice `ufw deny from <IP_ATACANTE>` |
| `test_L04_campana_vincula_victima_con_atacante` | L-04 | la campaña se arma con `172.18.0.7`, que es víctima en un caso |
| `test_S01_username_hostil_llega_al_comando_sugerido` | S-01 | se sugiere `sudo passwd victima; curl …\| bash` |
| `test_S01_ip_hostil_llega_al_incident_id` | S-01 | un `source_ip` con JS entra crudo al `incident_id` |
| `test_B01_es_search_no_captura_read_timeout` | B-01 | un ES lento produce traceback, no `ESUnavailable` |
| `test_B02_es_host_por_defecto_sin_tls` | B-02 | `ES_HOST` es `http://` con Basic Auth |
| `test_B03_comparacion_lexicografica_de_timestamps` | B-03 | `…Z` ordena después de `…+00:00` para el mismo instante |
| `test_B04_prepare_for_ia_no_genera_eventos_de_red` | B-04 | `network_events`/`web_events` no existen: rama muerta |
| `test_B05_corridas_repetidas_inflan_el_mismo_incidente` | B-05 | dos corridas ⇒ `event_count` 26 → 52 |
| `test_A01_reset_sh_borra_el_registro_de_auditoria` | A-01 | `reset.sh` borra la auditoría junto a los datos de demo |
| `test_A02_append_jsonl_sin_bloqueo_ni_fsync` | A-02 | `append_jsonl` no usa `flock` ni `fsync` |
| `test_A03_regenerar_incidentes_puede_huerfanar_decisiones` | A-03 | el `action_id` es posicional (`-a1`, `-a2`…) |
| `test_A04_el_log_no_esta_encadenado_por_hash` | A-04 | se edita una línea intermedia y **nada lo detecta** |
| `test_A_permisos_por_defecto_del_registro` | — | el registro se crea con el umask, no `0600` |
| `test_API01_ningun_endpoint_pide_autenticacion` | API-01 | los tres endpoints responden 200 sin sesión |
| `test_API01_el_analista_sale_del_entorno_no_de_la_sesion` | API-01 | el firmante de la auditoría es una variable de entorno |
| `test_API02_nota_sin_limite_de_tamano` | API-02 | 100 000 caracteres entran al registro inmutable |
| `test_API02_cuerpo_malformado_devuelve_html` | API-02 | un cliente JSON recibe HTML de Werkzeug |
| `test_API04_acepta_action_id_inexistente` | API-04 | se audita `INC-INVENTADO-000`, que nunca existió |
| `test_API05_sin_versionado_ni_cache_control` | API-05 | no hay `/api/v1/` ni `Cache-Control` |
| `test_API_no_existe_healthz` | API-05 | no hay endpoint de salud para el E2E |

### 3.5 Hallazgos nuevos de esta fase

Tres cosas que el análisis del plan no había registrado y que aparecieron al escribir
las pruebas:

1. **`read_jsonl` revienta con una línea corrupta.** `read_network_logs` sí tolera JSON
   malformado, pero `read_jsonl` no. Como el dashboard lo usa para reconstruir el
   estado, **un solo byte corrupto en `decisions.jsonl` deja el panel inutilizable**.
   Congelado en `test_read_jsonl_revienta_con_linea_corrupta`. Se suma a la Fase 2
   junto con A-02/A-04.
2. **`is_private_ip` trata los rangos de documentación como privados.** Python marca
   `192.0.2.0/24`, `198.51.100.0/24` y `203.0.113.0/24` (RFC 5737) como privados. No es
   un bug — Logstash usa esa distinción para decidir si aplica GeoIP — pero conviene
   que esté escrito: una IP de documentación en un fixture no se enriquece.
3. **`sanitize_for_prompt` no neutraliza instrucciones.** Aplana y recorta; no elimina
   texto que parezca una orden. La defensa contra inyección de prompt es la *system
   instruction* del Agente 2, no esta función. Queda documentado en
   `test_sanitize_no_neutraliza_instrucciones` para que nadie asuma de más.

---

## 4. Certificación de no-autonomía

### 4.1 Qué verifica

`tests/test_no_autonomy.py` (30 pruebas) recorre el **AST** de los 7 módulos Python del
sistema. Se analiza el árbol y no el texto porque un `grep` se engaña con un comentario
o un string, y se lo esquiva con `getattr(os, "sys" + "tem")`.

| # | Verificación |
|---|--------------|
| 1 | El descubrimiento de archivos funciona (si fallara, todo pasaría en vacío) |
| 2 | Ningún import de `subprocess`, `pty`, `paramiko`, `fabric`, `docker`, `kubernetes`, `ansible`, `telnetlib`… |
| 3 | Ninguna llamada a `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `eval`, `exec`, `compile`, ni el rodeo `getattr(os, "system")` |
| 4 | La allowlist (`siem_pipeline.py`) es mínima, no usa `shell=True`, sus comandos son **literales** (`[sys.executable, "<script>.py"]`) y el módulo no lee archivos, ni el entorno, ni importa `siem_lib` |
| 5 | `comando_sugerido` nunca llega a una llamada que no sea de formateo o impresión |
| 6 | El Agente 2 no tiene `tools=`, `function_declarations` ni `code_execution`, y su esquema de salida no declara ningún campo de comando |
| 7 | Un LLM comprometido que devuelva `"comando_sugerido": "rm -rf /"` **no altera el playbook** (probado con un cliente simulado hostil) |
| 8 | Sin scheduler, watcher, ni clientes de infraestructura (`boto3`, `pyufw`, `iptc`, `scapy`…) |
| 9 | El único `requests` del proyecto es `requests.post` hacia `ES_HOST`: sin `put`/`delete`/`patch`, sin webhooks |
| 10 | Las rutas de Flask son exactamente cuatro y ninguna contiene `execute`/`run`/`contain`/`block`/`remediate` |
| 11 | La plantilla no usa `eval`, `new Function` ni `execCommand`, y su único `POST` es el registro de una decisión |

### 4.2 La excepción, acotada

`siem_pipeline.py` usa `subprocess.run` para encadenar las tres etapas del propio
pipeline. Está en la allowlist y se le verifican condiciones adicionales (§4 del
archivo): comandos literales, sin shell, sin datos de log de por medio. El test
`test_allowlist_pipeline_no_recibe_datos_externos` comprueba por AST que el módulo
importa **solo** `subprocess`, `sys` y `__future__`, y que no llama a `open`,
`load_json`, `getenv` ni `load_dotenv`.

`tests/` se excluye del escaneo a propósito: la suite usa `subprocess` legítimamente
para lanzar el pipeline real y verificar que no pisa la auditoría. Eso es andamiaje de
prueba, no capacidad del producto, y
`test_el_andamiaje_de_pruebas_no_se_despliega` vigila esa frontera (ningún módulo del
sistema importa la suite, y `pytest` no está en `requirements.txt`).

### 4.3 Verificación por mutación

Una prueba que no puede fallar no certifica nada. Se introdujeron cuatro violaciones
reales, una por vez, y se restauró el código después de cada una:

| Mutante | Detectado por |
|---------|---------------|
| `os.system(data.get("cmd"))` dentro de `api_decision` | `test_sin_llamadas_de_ejecucion[dashboard.py]` → `dashboard.py:103: os.system(...)` |
| `getattr(os, 'system')` en `classifier.py` (disfrazado) | `test_sin_llamadas_de_ejecucion[classifier.py]` → `classifier.py:29: getattr(..., 'system')` |
| `import paramiko` en `siem_agent.py` | `test_sin_imports_de_ejecucion[siem_agent.py]` → `siem_agent.py:25: import paramiko` |
| Ruta `POST /api/execute` en el dashboard | `test_el_dashboard_no_define_rutas_de_ejecucion` **y** `test_la_api_no_expone_ninguna_ruta_de_ejecucion` |

Los cuatro fueron detectados, incluido el `getattr` disfrazado que un `grep` no ve.
Tras restaurar, la suite volvió a 119 verdes.

### 4.4 Resultado

```
── Certificación de no-autonomía ──────────────────────────
Archivos .py analizados por AST : 7
Con import de subprocess        : ['siem_pipeline.py']
Allowlist                       : ['siem_pipeline.py']
Rutas HTTP que ejecutan algo    : ninguna
Herramientas del LLM            : ninguna
───────────────────────────────────────────────────────────
```

> **Certificado:** ningún componente del sistema posee autonomía ni permisos para
> ejecutar acciones de contención sobre la infraestructura. La ejecución de comandos
> está bloqueada por construcción y, desde esta fase, **verificada automáticamente en
> cada corrida**.

**La salvedad sigue en pie, y es importante:** la no-autonomía técnica no protege del
todo mientras el hallazgo **S-01** siga abierto. El sistema no ejecuta el comando, pero
puede entregarle al analista un comando armado por un atacante, con una explicación
amable de qué hace, para que lo copie y lo pegue en su terminal. La cadena termina en
una persona con `sudo`, y esa persona es parte del sistema. Se corrige en la Fase 1.

---

## 5. Análisis estático (SAST)

### 5.1 Línea de base — Python

**bandit** (`bandit -r . -x './.devtools,./.venv,./node_modules,./tests,./elasticsearch'`)
sobre 1 117 líneas:

| Severidad | Regla | Ubicación | Estado |
|-----------|-------|-----------|--------|
| **HIGH** | B324 · SHA-1 débil | `classifier.py:52` (`_incident_id`) | Fase 2 → `usedforsecurity=False` |
| **HIGH** | B324 · SHA-1 débil | `classifier.py:476` (`_link_campaigns`) | Fase 2 → `usedforsecurity=False` |
| LOW | B404 · import de subprocess | `siem_pipeline.py:18` | **Justificado** (allowlist §4.2) |
| LOW | B603 · subprocess sin shell | `siem_pipeline.py:31` | **Justificado** (allowlist §4.2) |

Los dos B324 son exactamente los que el plan §3.4 anticipó. No son una vulnerabilidad
real — SHA-1 se usa acá para generar un identificador corto, no como control de
seguridad — pero hay que **declararlo explícitamente** en el código en vez de dejar que
la herramienta lo interprete.

**pylint + pylint-secure-coding-standard** → **9,19/10**. Los hallazgos del plugin de
seguridad son dos, y los dos apuntan a trabajo ya planificado:

| Regla | Ubicación | Coincide con |
|-------|-----------|--------------|
| `R8005` · evitar `open()` al escribir, preferir `os.open()` | `siem_lib.py:180` (`write_json`) y `:186` (`append_jsonl`) | **A-02** — es justamente el escritor del registro append-only, que la Fase 2 va a reescribir con `flock` + `fsync` + modo `0600` |
| `W1510` · `subprocess.run` sin `check=` explícito | `siem_pipeline.py:31` | Fase 2 — `check=False` explícito |

Que el linter de seguridad señale por su cuenta el escritor de la auditoría, sin que se
lo haya configurado para eso, es una confirmación independiente de que A-02 estaba bien
priorizado.

**ruff** → 12 hallazgos en el código del proyecto (6 de orden de imports, 3 de modos
redundantes en `open()`, 2 de SHA-1, 1 import sin usar). Todos cosméticos o duplicados
de lo anterior; se resuelven en la Fase 2 con los refactors R-01…R-05. El código nuevo
de esta fase (`tests/`) está en **cero hallazgos**.

### 5.2 Línea de base — JavaScript

`eslint.config.js` deja configurados los dos plugins pedidos:

- **`eslint-plugin-security`** — `detect-eval-with-expression`, `detect-child-process`,
  `detect-unsafe-regex`, `detect-object-injection`, `detect-non-literal-regexp`.
- **`eslint-plugin-no-unsanitized`** — `no-unsanitized/property` y `no-unsanitized/method`.
  **Este es el que detecta S-02**: asignaciones a `innerHTML` con contenido no literal.
  El plugin de seguridad, por sí solo, no lo ve.

**Alcance actual, dicho con franqueza:** hoy el JavaScript vive embebido en
`templates/index.html` (680 líneas de HTML + CSS + JS), que ESLint no analiza. La
configuración apunta a `static/**/*.js` y **entra en vigor con el refactor R-05**
(Fase 3), que extrae el script a su propio archivo. Hasta entonces está lista pero sin
archivos que analizar.

Para comprobar que no es una configuración decorativa, se validó con un archivo de
prueba que reproduce los tres patrones que importan:

```
static/__smoke.js
  2:3   error  Unsafe assignment to innerHTML                no-unsanitized/property
  3:3   error  eval with argument of type MemberExpression   security/detect-eval-with-expression
  3:3   error  eval can be harmful                           no-eval
  4:10  error  The Function constructor is eval              no-new-func
```

Las reglas disparan. El archivo de prueba se eliminó tras la verificación.

Mientras tanto, la plantilla queda cubierta por el lado Python:
`test_la_plantilla_no_ejecuta_nada_del_lado_del_cliente` verifica por texto que no
aparezcan `eval(`, `new Function(`, `execCommand` ni `child_process`, y que el único
`POST` del panel sea el registro de una decisión.

### 5.3 Puerta de calidad

`scripts/check.sh` corre todo en **17 segundos**:

```
══ Análisis estático (SAST) ══
  ruff · tests/                     OK
  ruff · proyecto                   BASE   12 hallazgo(s) conocido(s), sin regresiones
  pylint + secure-coding-standard   OK
  bandit · severidad alta           BASE   2 hallazgo(s) conocido(s), sin regresiones
  eslint + security                 OK

══ Pruebas ══
  no-autonomía (AST)                OK
  unitarias                         OK
  integración                       OK
  cobertura >= 80% (alcance §4.1)   OK

══ Resultado ══
  ✅ Todo en verde.
```

**Sobre el modo "línea de base":** una puerta que arranca en rojo no da ninguna señal —
se normaliza el rojo y deja de mirarse. Los 12 hallazgos de ruff y los 2 de bandit son
preexistentes y están agendados, así que la puerta los acepta como base y **falla ante
cualquier hallazgo nuevo**. Los números solo pueden bajar; cuando bajan, el script
avisa para que se actualice la base.

Verificado inyectando un `hashlib.md5()` nuevo en `siem_lib.py`:

```
  ruff · proyecto     FALLA  13 hallazgos (línea de base: 12) — hay 1 nuevo(s)
  bandit · sev. alta  FALLA   3 hallazgos (línea de base:  2) — hay 1 nuevo(s)
```

Detectado, y verde otra vez tras revertir.

---

## 6. Qué NO se hizo en esta fase

Por disciplina de alcance, y para que la Fase 1 arranque sobre una base limpia:

- **No se corrigió ningún bug.** Los 24 siguen ahí, ahora con una prueba que los fija.
- **No se refactorizó nada** (R-01…R-05 son de las Fases 2 y 3).
- **No se tocó la lógica de clasificación, la API ni la plantilla.**
- **No se agregó autenticación** (Fase 3).
- **No se instaló Playwright**: el E2E depende del refactor R-05 y corresponde a la
  Fase 3. Las líneas están en `requirements-dev.txt`, comentadas.
- **No se configuró CI**: el plan lo ubica en la Fase 2. `scripts/check.sh` ya es el
  contenido de esos jobs; convertirlo a YAML es mecánico.

---

## 7. Estado de los criterios de aceptación de la v1.0

| Criterio | Estado |
|----------|:------:|
| `pytest` verde, cobertura ≥ 80 % en `classifier`/`siem_lib`/`dashboard` | ✅ **90 %** |
| Suite completa en < 5 minutos | ✅ **17 s** |
| bandit y `pylint-secure-coding-standard` sin hallazgos HIGH/MEDIUM | ⏳ 2 HIGH (B324), Fase 2 |
| ESLint con `security` y `no-unsanitized` sin errores | ⏳ configurado; efectivo tras R-05 |
| `test_no_autonomy.py` pasa | ✅ 30 pruebas, 4 mutantes detectados |
| `docs/11` publicado | ✅ este documento |
| Ningún endpoint accesible sin sesión | ⏳ Fase 3 |
| Cadena de hash de `decisions.jsonl` verificable | ⏳ Fase 2 |
| Ningún `comando_sugerido` con metacaracteres ni placeholders | ⏳ Fase 1 (S-01, L-03) |
| Demo offline completa con login | ⏳ Fase 3 |
| Documentación en `/docs`, índice al día | ⏳ Fase 4 (reubicaciones §7.2 del plan) |

---

## 8. Recomendación para la Fase 1

El orden del plan §8 sigue siendo el correcto. Dos observaciones desde lo aprendido acá:

1. **Empezar por S-01**, no por L-01. Es el único hallazgo con consecuencias fuera del
   sistema (un comando hostil ejecutado a mano por el analista), y su corrección —
   el validador con lista blanca — es independiente del resto.
2. **L-01 y L-02 hay que corregirlos juntos.** Arreglar el contador sin arreglar la
   identidad produce dos incidentes con el conteo correcto en vez de uno; y arreglar la
   identidad sin el contador deja un incidente unificado que sigue sin alcanzar el
   umbral. Por separado, cada uno mejora poco; juntos cierran el agujero de detección.
   Sus pruebas congeladas están escritas para fallar en bloque.

Al corregir cada bug, el flujo es: correr `pytest -m bug`, ver cuál falla, y **reescribir
esa prueba** para que afirme el comportamiento nuevo (el docstring de cada una ya dice
cuál debería ser), moviéndola fuera del grupo `bug`. Cuando `pytest -m bug` no colecte
nada, la deuda registrada está saldada.
