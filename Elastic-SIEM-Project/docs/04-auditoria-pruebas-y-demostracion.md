# 04 · Auditoría, pruebas y demostración

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).
>
> Este documento fusiona tres temas relacionados: qué se auditó y qué se
> encontró, qué se prueba y cómo reproducirlo, y el guion para demostrarlo
> todo en vivo desde cero. El detalle histórico palabra por palabra de cada
> hallazgo sigue en el historial de git — esto es la versión que alguien
> necesita leer hoy, no el proceso completo para llegar hasta acá.

## Auditoría y hallazgos

### Qué pide la materia y cómo se cumple (actualizado 26-10-2026)

| Objetivo | Estado | Cómo se demuestra |
|----------|:------:|--------------------|
| **Pruebas de código estático** | ✅ | `./scripts/pruebas_de_codigo_estatico.sh` — ruff, eslint (linters) + pylint+secure-coding-standard, bandit (SAST). Líneas de base en cero. `./scripts/pruebas_de_verificacion.sh` demuestra que detectan: 20 casos sanos pasan y 5 defectos inyectados fallan. |
| **Pruebas de servicio** | ✅ | `./scripts/pruebas_de_servicio.sh` — 323 pruebas de integración sobre la API HTTP real del panel y de cada microservicio (la malla corre en proceso), `deploy-rules.sh` contra un Kibana simulado, `reset.sh` contra un sandbox, autenticación completa. |
| **Desarrollo e implementación en entorno de simulación** | ✅ | Los tres ataques se simulan y detectan de punta a punta; el panel exige login; las 14 reglas se despliegan como código; `services/collector/verify-cobertura.py` demuestra que ninguna alerta real del SIEM se pierde en el camino al panel. Falta la suite E2E de navegador (ver Pendientes, más abajo). |

Comando único para reproducir todo: `./scripts/pruebas_completas.sh`. Para
demostrar que las pruebas detectan errores: `./scripts/pruebas_de_verificacion.sh`.

### Cómo se hizo la auditoría

El proyecto pasó por varias rondas de revisión estructurada (una auditoría
integral inicial, y correcciones puntuales identificadas después, cada una
con su propia prueba de regresión). El criterio fue siempre el mismo: no
negociar sobre la propiedad central del sistema — **la IA sugiere, el humano
decide, y nada ejecuta acciones de contención** (certificado por
`tests/test_no_autonomy.py`, que recorre el AST de todo el código) — y
verificar cada afirmación contra una corrida real, no contra lo que el código
"debería" hacer.

### Hallazgos — bloqueantes y de diseño

Todos con su prueba de regresión en `tests/`. "RESUELTO" significa que hay
una prueba que falla si el problema vuelve a aparecer.

| # | Qué se encontró | Estado |
|---|------------------|--------|
| F-01 | El dashboard no pedía autenticación; el campo `analyst` del registro salía de una variable de entorno, no de quién estaba logueado | ✅ RESUELTO — login Argon2id, sesiones, CSRF, 3 roles |
| F-02 | Solo 4 de las reglas documentadas estaban realmente desplegadas en Kibana | ✅ RESUELTO — 14 reglas versionadas, `deploy-rules.sh` idempotente |
| F-03 | El JavaScript del panel no pasaba por ningún linter | ✅ RESUELTO — ESLint + plugins de seguridad |
| F-04 | No hay pruebas de navegador (E2E) | ⚠️ ABIERTO — ver Pendientes |
| F-05 | El contrato de `/api/v1/incidents` es inconsistente entre endpoints | 🔸 MENOR |
| F-06 | La demo depende de haber atacado en las últimas 24h | ✅ MITIGADO — los scripts de demo preparan todo desde cero |
| F-07 | Cobertura desigual: `services/analyst/siem_agent.py` muy por debajo del resto (depende de la API de Gemini, la parte menos verificable sin red) | ✅ MITIGADO — hoy 85 %, con el respaldo determinístico, la memoria y un LLM hostil simulado; sigue fuera del umbral estricto |
| F-08 | La suite dependía de la fecha del sistema | ✅ RESUELTO — fixtures centralizados + guarda de regresión |
| D-01 | Una regla ruidosa de Kibana tapaba a las demás en la muestra que ve el LLM | ✅ RESUELTO — agrupa por regla, no por recencia global |
| D-02 | La víctima aparecía como atacante en las alertas agrupadas por host | ✅ RESUELTO — distingue atacante/víctima/usuario por el campo agrupado |
| D-11 | El panel atribuía a una regla de Elastic detecciones que en realidad hizo el clasificador propio, con nombres inventados | ✅ RESUELTO — `detection_source` declara la procedencia real; ningún `rule_name` se escribe a mano (certificado por AST) |
| D-12 | Una agregación sin `.keyword` sobre `filebeat-*` rompía toda la captura del SIEM | ✅ RESUELTO |
| T-01 | Dos archivos de pruebas (`test_estado_y_accion.py`, `test_resultado_simulado.py`) solo pasaban si otra prueba había importado el panel antes: corridos solos fallaban por falta de `SECRET_KEY` | ✅ RESUELTO — cada archivo provee lo que necesita; lo encontró la verificación 80/20 |
| D-14 | La regla C2 (*Repeated Credential Harvesting*) agrupa por `source_ip`, que en un envío de credenciales es la **víctima**: una campaña con muchas víctimas distintas contra el mismo servidor no la dispara (escenario PH-02 del pentest; C1 sí dispara) | ⚠️ ABIERTO — habría que agrupar por `dest_ip` |
| D-13 | Las alertas de escaneo de puertos y phishing nunca se cruzaban contra los incidentes — solo SSH lo hacía | ✅ RESUELTO — `services/classifier/classifier.py` cruza esas alertas por IP y técnica; sigue sin existir un detector genérico para una técnica MITRE completamente nueva (decisión de diseño) |

### Pendiente, por prioridad

| # | Pendiente | Esfuerzo | Por qué importa |
|---|-----------|:--------:|------------------|
| P4 | Suite E2E con Playwright | Medio | Es la única capa del sistema (la interfaz) sin pruebas automatizadas |
| P5 | Vista de triage y pantalla de decisión como rutas separadas | Medio | Presentación del MVP |
| P6 | CI corriendo `pruebas_completas.sh` | Bajo | Evidencia continua, no solo bajo demanda |
| P7 | Contrato estable de `/api/v1/` (F-05) | Bajo | Consistencia de la API |
| P8 | Umbrales de clasificación a configuración externa | Bajo | Ajustar sin tocar código |
| P9 | Corregir la agrupación de C2 (D-14) | Bajo | Hoy una campaña de phishing con varias víctimas no escala por C2 |
| P10 | Cerrar los 3 huecos del pentest (PS-03, PS-04, PS-05) | Medio | Escaneos horizontales y sondeos de puertos sensibles no llegan al panel — ver [`pruebas_de_penetracion.md`](../pruebas_de_penetracion.md) |
| P11 | Rotar los secretos versionados en `.env` y sacar del repo las claves privadas | Bajo | `.env`, `elasticsearch/certs/*.key` y `users.json` están en git por decisión del dueño del repo |

**Fuera de alcance, a propósito:** MFA/SSO/recuperación de contraseña,
Suricata/IDS de red real (las simulaciones NDJSON cumplen el rol), un LLM
local vía Ollama (el fallback determinístico ya cubre el caso sin nube),
respaldos cifrados y retención (brecha normativa identificada, no resuelta).

### Conclusión de la auditoría

El núcleo del sistema está construido, verificado y es defendible: la cadena
completa (ataque → detección → clasificación → análisis → supervisión →
auditoría) funciona de punta a punta, la no-autonomía está certificada por
análisis estático y no por convención, y el registro de decisiones es
inmutable de forma verificable, no solo por costumbre. Lo más valioso para
una defensa no es el porcentaje de cobertura — es poder mostrar que las
pruebas **encuentran cosas de verdad**: esta auditoría documenta más de una
decena de defectos reales que las herramientas encontraron.

---

## Registro de pruebas

### Cómo reproducirlo

```bash
export PYTHONPATH="$PWD/.devtools"

./scripts/pruebas_de_codigo_estatico.sh   # linters + SAST (~40 s)
./scripts/pruebas_de_servicio.sh          # AST + unitarias + servicio + pentest + cobertura (~2 min)
./scripts/pruebas_completas.sh            # los dos anteriores juntos
./scripts/pruebas_de_verificacion.sh      # 80/20: el código sano pasa y cada defecto inyectado falla
```

O por separado:

```bash
python3 -m pytest tests/unit -q                  # solo unitarias
python3 -m pytest tests/integration -q           # solo servicio
python3 -m pytest tests/test_no_autonomy.py -q   # solo la certificación por AST
python3 -m pytest tests/unit/test_validators.py -v   # un archivo, prueba por prueba
```

Cada archivo de pruebas pasa también corrido solo, sin depender de que otro
haya corrido antes (verificado el 26-10-2026).

### Dónde ver los resultados

| Qué | Dónde |
|-----|-------|
| El resultado de cada etapa (`✔ OK`, `BASE`, `✘ FALLA`) | La salida de los scripts de arriba, agrupada por categoría |
| El detalle de un linter | `.devtools/bin/ruff check .` · `node_modules/.bin/eslint 'services/gateway/static/**/*.js'` · ver [`pruebas_de_linters.md`](../pruebas_de_linters.md) §3 |
| Los hallazgos subrayados en el código, mientras se escribe | VS Code, panel **Problems** (`Ctrl+Shift+M`), abriendo la carpeta raíz del repo — ver [`pruebas_de_linters.md`](../pruebas_de_linters.md) §7 |
| Qué prueba hace cada archivo | La tabla de abajo, y el docstring al principio de cada archivo de `tests/` |
| La cobertura por módulo | `python3 -m pytest -q --cov=classifier --cov=dashboard … --cov-report=term` (la lista completa está en `scripts/pruebas_de_servicio.sh`, variable `COBERTURA`) |

### Los tipos de prueba, y por qué son distintos

| Tipo | Qué verifica | Ejemplo |
|------|--------------|---------|
| **Linter** (`ruff`, `eslint`) | Lee el código: estilo, imports, errores comunes y patrones peligrosos | `==` en vez de `===` en el JS del panel |
| **SAST** (`bandit`, `pylint` + `pylint-secure-coding-standard`) | Lee el código y busca vulnerabilidades conocidas | `subprocess.run(..., shell=True)` |
| **Estático por AST, propio** (`tests/test_no_autonomy.py`) | Recorre el AST del producto para certificar una propiedad: nada ejecuta comandos | Detecta `os.system()` disfrazado como `getattr(os, "sys"+"tem")` |
| **Unitaria** (`tests/unit/`) | Una función o módulo aislado, sin contactar nada externo | `classifier.detect_port_scans()` con eventos sintéticos |
| **Servicio** (`tests/integration/`) | El contrato real de un componente: API HTTP con el cliente Flask real (la malla de microservicios corre en proceso, ver `malla_en_proceso` en `tests/conftest.py`), y scripts como procesos reales contra un sandbox | Login completo con CSRF y cookies de sesión reales |
| **Pentest simulado** (`tests/integration/test_pentest.py`) | Ataques evasivos por el clasificador real; falla ante una regresión | Fuerza bruta "low-and-slow" |
| **Verificación 80/20** (`scripts/pruebas_de_verificacion.sh`) | Que las pruebas de arriba detectan errores de verdad | Borrar un permiso y ver que las pruebas de API-01 fallan |

### Inventario, última corrida (26-10-2026)

**Total: 1308 pruebas** (5 omitidas a propósito), todas en verde.

| Grupo | Pruebas | Tiempo |
|-------|--------:|-------:|
| Estático por AST (`tests/test_no_autonomy.py`) | 86 | ~2 s |
| Unitarias (`tests/unit/`, 26 archivos) | 888 + 5 omitidas | ~9 s |
| Servicio (`tests/integration/`, 13 archivos) | 334 | ~49 s |
| — de las cuales, pentest (`test_pentest.py`) | 10 | <1 s |

#### Qué prueba cada archivo

**Estático por AST**

| Archivo | Pruebas | Qué certifica |
|---------|-------:|---------------|
| `tests/test_no_autonomy.py` | 86 | Ningún módulo del producto ejecuta procesos, abre una shell ni se conecta a un host por su cuenta (incluye formas disfrazadas). La allowlist de `subprocess` está vacía. Toda llamada entre servicios tiene destino y ruta literales. Enumera la API completa de cada servicio. La auditoría no expone modificación ni borrado. Ningún rol tiene un permiso de ejecución. |

**Unitarias (`tests/unit/`)**

| Archivo | Pruebas | Qué certifica |
|---------|-------:|---------------|
| `test_validators.py` | 91 | Los validadores de IP y usuario (`siem_validators`) rechazan todo lo que podría inyectar algo en un comando sugerido |
| `test_s01_inyeccion_comandos.py` | 57 | S-01: un usuario o IP hostil del log nunca termina dentro del comando que el analista copia; si no valida, la acción no se ofrece |
| `test_s02_xss_dashboard.py` | 52 | S-02: el panel escapa todo lo que interpola (plantilla `html`), sin `onclick` en línea; accesibilidad: las filas se alcanzan con Tab y se abren con Enter/Espacio |
| `test_classifier_caracterizacion.py` | 21 | Congela qué produce hoy el Agente 1 sobre una captura real, incluido el catálogo de alternativas de remediación |
| `test_procedencia_de_la_deteccion.py` | 21 | D-11: `detection_source` dice la verdad; ningún `rule_name` se inventa |
| `test_l01_l02_identidad_y_conteo.py` | 15 | L-01/L-02/L-04: un mismo ataque produce un solo incidente, con el conteo de eventos correcto |
| `test_rol_del_valor_agrupado.py` | 28 | D-02: distingue atacante, víctima y usuario según el campo por el que agrupó la regla |
| `test_alertas_por_regla.py` | 18 | D-01: una regla ruidosa no tapa a las demás en la muestra de alertas |
| `test_modo_de_solucion.py` | 7 | El playbook declara si sus acciones son pasos en orden o soluciones alternativas |
| `test_resultado_simulado.py` | 8 | La vista "qué pasaría" es texto fijo del playbook, marcada como SIMULADO, y nunca va al registro de decisiones |
| `test_severidad_del_agente.py` | 43 | La severidad que devuelve el Agente 2 (incluso un LLM que responde "alta") siempre se normaliza a un valor que el panel puede pintar |
| `test_interruptor_del_llm.py` | 18 | Con la key puesta pero `SIEM_USE_LLM` apagado, no se llama a Gemini |
| `test_reglas_como_codigo.py` | 155 | Las 14 reglas de `rules/ndjson/`: estructura válida, nombres únicos, MITRE, campos `.keyword`, coherencia con el catálogo |
| `test_agregaciones_keyword.py` | 6 | D-12: el collector agrega sobre `.keyword`, nunca sobre un campo `text` |
| `test_b0x_robustez_y_formatos.py` | 39 | B-01…B-05: timeouts de Elasticsearch, HTTP inseguro bloqueado, formatos de fecha y archivos |
| `test_siem_lib_caracterizacion.py` | 26 | La librería común: errores de ES, saneamiento anti-inyección, escritura de archivos con permisos `0600` |
| `test_gestion_usuarios.py` | 66 | Almacén de usuarios, Argon2id, validación de nombres y contraseñas, y la CLI `manage_users.py` |
| `test_contraste_de_la_interfaz.py` | 53 | Todo par texto/fondo del panel cumple contraste WCAG AA |
| `test_tokens_de_diseno.py` | 19 | El CSS solo usa los tokens de `tokens.css` (nada de px sueltos ni `:root` propios) |
| `test_iconos.py` | 67 | El sprite SVG está bien formado, sin iconos huérfanos ni emoji |
| `test_estado_y_accion.py` | 18 | Un estado (aprobado/pendiente) no se dibuja como un botón, y se muestra en español |
| `test_resumen.py` | 19 | La barra de resumen destaca lo pendiente y muestra las 4 severidades, incluso en cero |
| `test_resuelto.py` | 4 | El tag "resuelto" aparece cuando se aprobó al menos una acción |
| `test_historial_agrupado.py` | 6 | El historial de decisiones se agrupa por incidente |
| `test_motivo_de_descarte.py` | 11 | Descartar pide el motivo dentro del panel, no con un `prompt()` |
| `test_despliegue_compose.py` | 25 | RQ-SEC-24: la simulación corre en su red `sim-net` y el nmap real no apunta a la red del SIEM; RNF-COMP-01: todo contenedor tiene `mem_limit` (256 MB la capa IA) |

**Servicio (`tests/integration/`)**

| Archivo | Pruebas | Qué certifica |
|---------|-------:|---------------|
| `test_api01_autenticacion.py` | 60 | API-01: todo exige sesión, permisos por rol (un viewer que decide recibe 403 y no se escribe nada), CSRF, expiración, bloqueo por intentos, `X-Forwarded-For` no esquiva el bloqueo, el panel no arranca sin `SECRET_KEY` |
| `test_api_v1.py` | 38 | API-02…API-05: validación de entrada, errores siempre en JSON, rechazo de acciones inexistentes |
| `test_api_caracterizacion.py` | 17 | Congela el contrato de cada endpoint del panel |
| `test_pipeline_programado.py` | 11 | El pipeline corre solo cada 2 min: un turno corre el ciclo real, se saltea si hay uno manual en curso, sobrevive a un ciclo fallido, y está apagado por defecto fuera del contenedor |
| `test_microservicios.py` | 40 | Token interno, qué etapa del ciclo puede fallar y cuál aborta, la segunda barrera del servicio audit, el panel ante un servicio caído |
| `test_a02_a04_integridad.py` | 35 | A-02…A-04: escritura con `flock`+`fsync`, concurrencia real, cadena de hash que detecta cualquier edición |
| `test_auditoria_append_only.py` | 7 | El registro de decisiones solo crece; el pipeline no lo pisa |
| `test_a01_reset_preserva_auditoria.py` | 12 | A-01: `reset.sh` real (en un sandbox) archiva la auditoría en vez de borrarla |
| `test_memoria_del_agente.py` | 22 | El Gem: casos, lecciones propuestas que no se usan sin aprobar, ajuste solo del falso positivo — ver [05](05-gem-memoria-del-agente.md) |
| `test_reportes.py` | 17 | Cada decisión guarda su contexto (nunca el comando), `actividad.jsonl` encadenado, reportes CSV/JSON con filtro de fechas y escape de fórmulas |
| `test_despliegue_de_reglas.py` | 23 | `deploy-rules.sh` y `export-rules.sh` contra un Kibana simulado: desplegar dos veces no duplica |
| `test_scripts_de_demostracion.py` | 42 | Los scripts de demo no ejecutan nada al imprimirse, nombran scripts reales y respetan `--ip` |
| `test_pentest.py` | 10 | El simulador de Kibana cubre las 14 reglas, los ataques de manual siempre se detectan, y no hay regresiones |

### Verificación 80/20: las pruebas detectan errores

Un "todo en verde" no prueba nada por sí solo: también saldría verde si las
herramientas no miraran ningún archivo. `./scripts/pruebas_de_verificacion.sh`
corre **25 casos** sobre una **copia temporal** del proyecto. El repositorio
real nunca se modifica, y la copia se borra al terminar.

- **20 casos sanos (80 %)**: el código tal como está, en 20 grupos que cubren
  los 4 analizadores estáticos y los 40 archivos de pruebas. **Tienen que pasar.**
- **5 casos mutantes (20 %)**: se inyecta un defecto real y se corre la
  herramienta que lo cuida. **Tienen que fallar.**

| Caso | Defecto inyectado (solo en la copia) | Quién lo tiene que detectar |
|------|--------------------------------------|-----------------------------|
| M1 | Un módulo del collector con `subprocess.run(cmd, shell=True)` | bandit (SAST) |
| M2 | `innerHTML = evento.mensaje` en un JS del panel (XSS) | eslint + `no-unsanitized` (linter) |
| M3 | `os.system("iptables -F")` en el servicio classifier | `test_no_autonomy.py` (AST) |
| M4 | `/api/v1/decision` pierde `@requiere_permiso("decidir")` | `test_api01_autenticacion.py` (servicio) |
| M5 | El Gem usa lecciones que nadie aprobó | `test_memoria_del_agente.py` (servicio) |

La verificación es correcta solo si salen **exactamente 20 ✔ y 5 ✘**, cada uno
donde se esperaba. Un caso sano que falla es un error del código; un mutante
que pasa es una prueba que no está mirando. Si alguien cambia el código que un
mutante modifica, el script lo avisa en vez de dar un resultado falso. Salida
de la corrida del 26-10-2026:

```
  Casos corridos     : 25
  Pasaron            : 20  (80 %)  — esperado: 20 sanos (80 %)
  Fallaron           : 5  (20 %)  — esperado: 5 mutantes (20 %)
  Resultados inesperados: 0

  ✅ Verificación correcta: el código sano pasa y cada defecto inyectado es detectado.
```

La primera corrida de este script encontró un defecto real: dos archivos
(`test_estado_y_accion.py` y `test_resultado_simulado.py`) solo pasaban si otra
prueba había importado el panel antes. Ya está corregido (ver T-01 en la tabla
de hallazgos).

### Cobertura

```bash
./scripts/pruebas_de_servicio.sh   # incluye el paso de cobertura al final
```

Umbral: **≥ 80 %** sobre los 20 módulos de la variable `COBERTURA` de
`scripts/pruebas_de_servicio.sh`. Última corrida: **94 %** en total.

| Módulo | Cobertura | Módulo | Cobertura |
|--------|---------:|--------|---------:|
| `classifier.py` | 99 % | `siem_auth.py` | 99 % |
| `siem_validators.py` | 100 % | `siem_lib.py` | 97 % |
| `sesion_web.py` | 97 % | `memoria.py` | 95 % |
| `knowledge_service.py` | 94 % | `manage_users.py` | 94 % |
| `cadena.py` | 93 % | `dashboard.py` | 91 % |
| `audit_service.py` | 91 % | `auth_service.py` | 89 % |
| `analyst_service.py` | 88 % | `classifier_service.py` | 88 % |
| `orquestador.py` | 87 % | `collector_service.py` | 86 % |
| `siem_servicios.py` | 84 % | `pipeline_service.py` | 81 % |
| `reportes.py` | 97 % ¹ | `programador.py` | 98 % |

¹ Medido con `--cov=services/audit`. Con `--cov=reportes`, como figura en el
script, la herramienta no lo registra porque el módulo se importa antes de que
empiece a medir: el 94 % total corresponde a los otros 19.

`services/analyst/siem_agent.py` no está en la lista estricta porque su camino
principal depende de la API de Gemini, pero hoy llega al **85 %** con el
respaldo determinístico y un cliente LLM hostil simulado. `collector.py` y
`es_client.py` tampoco están: dependen de un Elasticsearch real.

### Selección por marca

```bash
pytest -m "not bug"   # todas las pruebas activas
pytest -m bug         # 0 pruebas — no queda ningún bug congelado
```

---

## Demostración desde cero

**Para qué sirve.** Es el guion completo de una demo/defensa: qué correr, en
qué orden, qué decir mientras corre y qué contestar si preguntan. La pregunta
que un evaluador va a hacer, explícita o no, es *"¿cómo sé que ese panel no
está mostrando un archivo JSON que ustedes prepararon?"* — este guion la
responde de la única forma que no admite réplica: poniendo todo en cero
delante del público y construyendo el resultado paso a paso.

Cuatro números arrancan en cero: reglas de detección en Kibana (0 → 14),
alertas en Elasticsearch (0 → 4+), documentos de Filebeat (0 → 100+),
incidentes en el panel (0 → 3+).

**No digas "todo lo que ves sale de las reglas que acabo de subir".** No es
cierto y es fácil de refutar: el escaneo de puertos y el phishing los puede
detectar el Agente 1 leyendo `network_logs/` directamente, sin pasar por
Elasticsearch — aparecerían aunque no hubiera una sola regla desplegada (ver
más abajo, "Los dos caminos de detección").

### Antes de empezar

```bash
./scripts/demo-desde-cero.sh --estado   # comprobación; si Kibana no contesta:
./scripts/start.sh
```

Qué tener abierto: terminal con el guion, Kibana en dos pestañas (Security →
Rules y Security → Alerts), el panel (`http://127.0.0.1:5000/login`), y una
terminal libre para `services/audit/audit_verify.py` al final. Los usuarios de
laboratorio los crea `./scripts/demo.sh` (`analista`/`observador`/`auditor`,
credenciales conocidas a propósito). Ojo: en este repositorio `.env` **sí**
está versionado, por decisión del dueño (ver `.gitignore`).

**Cuánto tarda:** 6 a 9 minutos, de los cuales ~4 son espera a que las reglas
disparen (corren cada 1 a 10 minutos) — esa espera **es** parte de la
demostración, es el SIEM trabajando, no el script. `--sin-docker` baja a ~3
minutos omitiendo la fuerza bruta con Hydra, pero pierde la única fila
"Elastic SIEM" del cuadro final — no usar en una defensa real.

### El guion

```bash
./scripts/demo-desde-cero.sh
```

Va narrado y con pausas, pide confirmación antes de borrar.

1. **Todo a cero** — borra reglas, alertas, índices de Filebeat y artefactos
   del pipeline. No baja Docker. El registro de auditoría **no** se borra: se
   archiva en `data/audit/archivo/` (hallazgo A-01) — decirlo antes de que lo
   pregunten.
2. **Mostrar que no hay nada** — recargar Kibana (0 reglas, 0 alertas) y el
   panel (vacío) a la vista de todos.
3. **Desplegar las reglas** (`./scripts/deploy-rules.sh`) — recargar Rules:
   pasa de 0 a 14. Aclarar: desplegar acá es subir reglas de *detección*, no
   ejecuta nada sobre ninguna máquina.
4. **Generar los ataques** — escaneo de 26 puertos y captura de credenciales
   (NDJSON sintético) + fuerza bruta SSH real con Hydra contra el contenedor
   `ssh-target` (no es sintético: los intentos quedan en su
   `/var/log/auth.log`, Filebeat los recoge, Logstash los normaliza,
   Elasticsearch los indexa — la misma ruta que un ataque real).
5. **La ingesta** — el conteo de documentos de Filebeat sube de 0.
6. **Las reglas disparan** — la espera larga. Recargar Alerts y mostrar el
   nombre de la regla. Mientras se espera: cada regla tiene su intervalo (la
   de fuerza bruta agresiva corre cada minuto, otras cada diez) — es Elastic
   evaluando las reglas contra los datos que acaban de entrar, no el
   proyecto.
7. **Clasificación y panel** — el pipeline corre las tres etapas; abrir el
   panel y recargar. Los incidentes están ahí.

### Los dos caminos de detección

```
                    ┌─ reglas de Kibana ──→ alertas ─┐
  ataque → logs ────┤                                ├──→ Agente 1 → Agente 2 → panel
                    └─ network_logs/ ────────────────┘
```

| Camino | Qué detecta | Qué aporta |
|--------|-------------|------------|
| **Elastic SIEM** | Fuerza bruta SSH, escaneo de puertos, phishing | La alerta trae el nombre de la regla, la severidad del SIEM, el riesgo y la técnica MITRE. |
| **Agente 1** | Los tres tipos, sin depender de que la regla ya haya disparado | Cuenta fallos de auth, puertos distintos y envíos de credenciales leyendo los logs directamente. No espera a Elasticsearch, pero si la alerta ya existe, la usa. |

**Si preguntan por qué un escaneo o un phishing aparecen "sin regla SIEM":**
puede pasar, pero ya no es la regla general (hallazgo D-13, resuelto). Si en
el momento de correr `services/pipeline/siem_pipeline.py` la alerta de Kibana todavía no
disparó, el incidente queda como "Sin regla SIEM (detección propia)"
temporalmente — volver a correr el pipeline un rato después, ya con la
alerta indexada, lo actualiza a la regla real. `services/collector/verify-cobertura.py` es
la herramienta para demostrar esto: compara las alertas reales de
Elasticsearch contra lo que muestra el panel y avisa si algo quedó sin
actualizar.

### Después del guion: cerrar el círculo

**La decisión humana.** Entrar como `analista`, abrir un incidente y aprobar
una acción — el sistema sugirió un comando, no lo ejecutó, y no puede: no
existe ninguna ruta que ejecute nada. Cerrar sesión y entrar como
`observador`: los botones no están; por API, el servidor responde 403.

**La auditoría es verificable.**

```bash
./scripts/demo-auditoria.sh
```

Copia el registro, altera una decisión aprobada para que diga "descartada", y
el verificador la detecta señalando la línea y terminando con código 1.
Trabaja sobre una copia y prueba con SHA-256 que el archivo real no cambió —
el registro no es imposible de editar, es **detectable**, y por eso sirve
como evidencia. **No editar `data/audit/decisions.jsonl` a mano para esto:** es el
registro de auditoría real y no hay forma prolija de deshacer el cambio.

### Si algo falla

| Síntoma | Qué pasó | Qué hacer |
|---------|----------|-----------|
| `Kibana no responde` | El stack está abajo | `./scripts/start.sh` y esperar a que libere la consola |
| **La captura de Elasticsearch no se renovó** | El pipeline siguió con datos viejos | No presentar así. Revisar el log del pipeline — suele ser un 400 en una consulta |
| `todavía no hay alertas` | Las reglas no llegaron a correr | No es un error: el Agente 1 detecta igual. Esperar y correr `./scripts/siem.sh pipeline` de nuevo |
| La fuerza bruta no completa | Faltan los contenedores de simulación | `docker compose --profile simulation up -d ssh-target hydra-attacker` |
| El panel muestra el diseño viejo | La imagen del gateway es anterior al cambio | Reconstruirla: `docker compose up -d --build gateway` |

### Preguntas probables

| Pregunta | Respuesta corta |
|----------|-----------------|
| ¿Cómo sé que no son datos preparados? | Se acaba de construir desde cuatro ceros, recargando el navegador en cada paso. |
| ¿El sistema puede bloquear una IP? | No. No existe ninguna ruta que ejecute nada — certificado por `tests/test_no_autonomy.py`, que recorre el AST de todo el código. |
| ¿Y si la IA alucina un comando? | Los comandos salen de un catálogo fijo en `services/classifier/classifier.py`; el LLM no tiene *function calling*. Hay una prueba con un LLM hostil simulado. |
| ¿Por qué a veces el escaneo aparece sin regla del SIEM? | El clasificador lo detecta sin esperar a Kibana; si la alerta real ya disparó para esa IP, el panel la muestra. Ver "Los dos caminos de detección". |
| ¿Puedo reproducir esto desde cero? | Es literalmente lo que se acaba de hacer: `./scripts/start.sh` levanta el stack y despliega las 14 reglas. |
| ¿Cuánto está probado? | 1308 pruebas, 94 % de cobertura sobre el alcance declarado, SAST además de los tests, y una verificación 80/20 que demuestra que las pruebas detectan defectos inyectados. |

### Comandos, en una tarjeta

```bash
# Antes
./scripts/demo-desde-cero.sh --estado      # ¿en qué estado está?
./scripts/start.sh                         # si el stack está abajo
./scripts/siem.sh estado                   # ¿están arriba los microservicios?

# La demostración
./scripts/demo-desde-cero.sh               # el guion completo, narrado

# Después
./scripts/demo-auditoria.sh                # romper la cadena y detectarlo
./scripts/siem.sh auditoria                # verificar el registro real

# Variantes
./scripts/demo-desde-cero.sh --limpiar     # solo dejar todo en cero
./scripts/demo-desde-cero.sh --rapido      # sin pausas (para ensayar)
./scripts/demo-desde-cero.sh --sin-docker  # sin Hydra (no usar en la defensa)
```
