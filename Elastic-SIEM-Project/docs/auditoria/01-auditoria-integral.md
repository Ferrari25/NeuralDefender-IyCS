# Auditoría integral de SIEM-IA

> **Fecha:** 17-09-2026 · **Alcance:** todo el repositorio, el stack en ejecución
> y la ERS del Grupo 4 · **Método:** verificación contra el sistema corriendo, no
> lectura del diseño. Cada afirmación de esta auditoría se reprodujo ejecutando
> el código; los comandos están incluidos.
>
> **Actualización 17-09-2026 (tarea P1):** el hallazgo **F-01 está cerrado**. El
> panel exige autenticación, hay tres roles y el registro firma con la identidad
> de la sesión. Ver [`../15-autenticacion-y-roles.md`](../15-autenticacion-y-roles.md).
> Las secciones §3.1, §4.1, §5.3, §6 y §7 quedaron actualizadas; el resto del
> documento refleja el estado en que se hizo la auditoría.

---

## 1. Qué es el proyecto y qué se propone

**SIEM-IA** es una plataforma de detección y análisis asistido de incidentes de
seguridad **con supervisión humana obligatoria**. Integra herramientas de código
abierto (Elastic Stack) con una capa de razonamiento propia y una aplicación web
donde un analista decide.

El principio que gobierna todo el diseño:

> **La IA sugiere, el humano decide, y el sistema no ejecuta nada.**

No es una limitación que se compensa más adelante: es la propiedad central. Los
falsos positivos en seguridad tienen consecuencias reales — bloquear la IP
equivocada corta un servicio legítimo — así que la decisión queda siempre en una
persona, y cada decisión queda registrada de forma verificable.

### El recorrido completo de un evento

```
  Ataque simulado                Capa SIEM (Docker)                  Capa IA (Python)
  ──────────────      ────────────────────────────────────      ──────────────────────

  Hydra / nmap  ──▶  ssh-target  ──▶ Filebeat ──▶ Logstash ──▶ Elasticsearch
  simulaciones            │             (envío)    (parseo,        (almacén)
  NDJSON        ──────────┘                        GeoIP, fecha)        │
                                                                        │ reglas de
                                                                        ▼ detección
                                                                    7 alertas
                                                                        │
                        prepare-for-ia.py  ◀────────────────────────────┘
                                │  siem_clean.json
                                ▼
                        classifier.py         Agente 1 · determinístico
                                │             umbrales + playbook de comandos fijos
                                ▼
                        siem_agent.py         Agente 2 · LLM con respaldo
                                │             explica en lenguaje claro
                                ▼
                        siem_incidents.json
                                │
                                ▼
                        dashboard.py (Flask :5000)
                                │   el analista APRUEBA o DESCARTA
                                ▼
                        decisions.jsonl       append-only + cadena SHA-256
                                │
                                ▼
                        Una persona ejecuta el comando a mano. El sistema, nunca.
```

### Los tres ataques contemplados

| Ataque | MITRE | Cómo se genera | Cómo se detecta |
|--------|-------|----------------|-----------------|
| Fuerza bruta SSH | T1110 | Hydra contra `ssh-target` | `auth.log` → Filebeat → regla threshold |
| Escaneo de puertos | T1046 | `run-port-scan.sh` (NDJSON) | `network_logs/` → cardinalidad de puertos |
| Phishing / captura de credenciales | T1566 | `run-phishing.sh` (NDJSON) | POST con credenciales a `/login` |

### Qué pide la materia

Tres objetivos, que esta auditoría trata como criterio de evaluación:

1. **Pruebas de código estático (SAST)** — demostrar análisis estático real, con
   herramientas configuradas y hallazgos tratados.
2. **Pruebas de servicio** — demostrar que los endpoints y los componentes se
   verifican de forma automatizada.
3. **Desarrollo e implementación en un entorno de simulación** — que el sistema
   se despliegue, se ataque y se observe de punta a punta.

---

## 2. En qué situación está hoy

### 2.1 Verificado en ejecución, 17-09-2026

```bash
$ docker compose ps
elasticsearch   Up 2 hours (healthy)   127.0.0.1:9200->9200/tcp
kibana          Up 2 hours             127.0.0.1:5601->5601/tcp
logstash        Up 2 hours             127.0.0.1:5044->5044/tcp
filebeat        Up 2 hours
```

| Componente | Estado | Evidencia |
|------------|:------:|-----------|
| Elasticsearch | ✅ corriendo, salud `yellow` | 5 índices `filebeat-*`, **7364 documentos** ingeridos hoy |
| Kibana | ✅ corriendo | 4 reglas de detección activas |
| Logstash | ✅ corriendo | parseo SSH + fecha del evento + GeoIP condicional |
| Filebeat | ✅ corriendo | 3 entradas: contenedores, `auth.log`, `network_logs/` |
| Alertas de seguridad | ✅ | 7 alertas en `.internal.alerts-security.alerts-default` |
| Pipeline de IA | ✅ funciona | 3 incidentes clasificados en la corrida de verificación |
| Dashboard :5000 | ⚠️ apagado | arranca a demanda con `python3 dashboard.py` |

### 2.2 Tamaño y madurez

| Métrica | Valor |
|---------|-------|
| Código de la aplicación | 3 048 líneas (9 módulos Python + 1 plantilla) |
| Código de pruebas | 3 571 líneas — **más pruebas que aplicación** |
| Documentación | 3 188 líneas en 15 documentos |
| Catálogo de reglas | 429 líneas, 13 reglas documentadas |
| Pruebas automatizadas | **420 pasan**, 2 omitidas por diseño, en 11 s |
| Cobertura (alcance del plan) | **95 %** |
| Hallazgos de SAST | **0** en las 4 herramientas |
| Puntaje de pylint | **9,51 / 10** |
| Puerta de calidad completa | 28 s |

### 2.3 De dónde viene: tres fases de trabajo

| Fase | Qué hizo | Resultado |
|------|----------|-----------|
| **Fase 0** | Red de seguridad: fixtures, pruebas de caracterización, certificación de no-autonomía por AST, linters | 119 pruebas · 90 % cobertura · 24 bugs congelados |
| **Fase 1** | Correcciones P0: inyección de comandos, XSS, identidad del incidente, conteo de eventos, auditoría en el reset | 316 pruebas · 93 % · 16 bugs restantes |
| **Fase 2** | Robustez, integridad de auditoría con cadena de hash, API v1, refactors DRY | 420 pruebas · 95 % · **2 bugs restantes** |

El detalle completo está en [`../11-reporte-fase-0.md`](../11-reporte-fase-0.md) y
[`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md).

### 2.4 Lo que funciona bien y no hay que tocar

- **La arquitectura de dos agentes.** El clasificador determinístico decide;
  el LLM solo explica. Es la decisión de diseño más valiosa del proyecto: hace
  que el sistema sea auditable y que funcione sin red.
- **La degradación garantizada.** La cuota de Gemini está agotada, y el sistema
  funciona igual: el respaldo determinístico produce análisis completo. La demo
  no depende de un servicio externo.
- **La no-autonomía, certificada.** 34 pruebas recorren el AST de los 9 módulos.
  Probada contra 4 mutantes reales, incluido un `getattr(os, 'system')`
  disfrazado que un `grep` no ve.
- **El registro de auditoría.** Append-only con `flock`, `fsync`, permisos `0600`
  y cadena SHA-256 verificable con `audit_verify.py`.

---

## 3. Qué falla

Ordenado por severidad. Todo lo de esta sección está **verificado ejecutando el
sistema**, no inferido.

### 3.1 Bloqueante para la v1.0 — ✅ CERRADO (17-09-2026)

#### F-01 · No hay autenticación (API-01) — **RESUELTO**

> **Estado:** cerrado en la tarea P1. Se conserva el enunciado original porque
> explica por qué era la brecha más importante, y porque la ERS todavía declara
> estos requisitos como parciales o diferidos (ver §6).
>
> **Lo que hay ahora:** login con Argon2id, sesiones con expiración doble (30 min
> de inactividad, 8 h absoluta), CSRF, bloqueo por intentos con backoff, y tres
> roles (`viewer`/`analyst`/`auditor`) con los permisos en una sola tabla. El
> campo `analyst` del registro sale de `current_user`, más `analyst_rol`,
> `session_id` y `user_agent`. `ANALYST_NAME` fue eliminada. 126 pruebas nuevas.
>
> **Sigue pendiente:** TLS para publicar el panel hacia una red (`RQ-SEC-01`,
> parcial). Hoy se sirve en loopback.

*Enunciado original del hallazgo:*

`dashboard.py` expone 10 rutas y **ninguna pide credenciales**. Cualquiera con
acceso a `127.0.0.1:5000` lee todos los incidentes, registra decisiones y
consulta la auditoría completa.

Su consecuencia más seria no es el acceso, sino la **firma**:

```python
ANALYST = os.getenv("ANALYST_NAME", "analista-soc")
```

El campo `analyst` del registro inmutable sale de una variable de entorno. Quien
corre el proceso decide qué nombre queda firmando cada decisión. La cadena de
hash garantiza que el registro **no se alteró después de escribirse**; todavía no
garantiza **quién lo escribió**. Para un sistema cuya premisa es la supervisión
humana trazable, es la brecha más importante que queda.

> Congelado en dos pruebas: `test_API01_ningun_endpoint_pide_autenticacion` y
> `test_API01_el_analista_sale_del_entorno_no_de_la_sesion`. Son las **únicas 2**
> de las 24 originales que siguen abiertas.

Trazabilidad con la ERS: `RQ-SEC-08` [P], `RQ-SEC-11` [D], `RQ-SEC-13` [D],
`RF-DIF-04` [D].

### 3.2 Importante

#### F-02 · Solo 4 de las 13 reglas documentadas están desplegadas — **RESUELTO**

> **Estado:** cerrado en la tarea P3, 17-09-2026. Las 13 están versionadas en
> `rules/ndjson/` y se despliegan con `./scripts/deploy-rules.sh`, que corre
> automáticamente en `start.sh`. Verificado sobre el Kibana real: de 0 reglas a
> **13 activas con un comando**, sin tocar la consola, y las 13 ejecutan con
> estado `succeeded`. 153 pruebas nuevas. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.8.
>
> **Hallazgo lateral:** el catálogo de `rules.md` nombraba los campos de
> agrupación sin `.keyword`, y esas reglas **no corren** contra este índice
> (`Fielddata is disabled`). Corregido y documentado.

*Enunciado original del hallazgo:*

`rules/rules.md` documenta 13 reglas de detección con su consulta, umbral y
mapeo MITRE. En el Kibana que está corriendo hay **4**:

```
[ON] SSH Successful Login After Brute Force    (eql, critical)
[ON] SSH Brute Force – Aggressive per Source IP (threshold, high)
[ON] Credential Submission to Suspicious Login  (query, high)
[ON] Port Scan – Many Distinct Ports            (threshold, high)
```

Faltan A1, A3, A5, A6 (SSH), B2, B3, B4 (escaneo) y C2, C3 (phishing). Y las
cuatro que existen **se crearon a mano en la consola**: no se despliegan con el
sistema ni están versionadas como código.

Esto rompe la reproducibilidad, que es justamente lo que la materia evalúa en el
entorno de simulación: quien clone el repositorio y levante el stack **no obtiene
el mismo sistema**, porque las reglas no viajan con él. Hay que recrearlas a mano
siguiendo `docs/07`.

Trazabilidad con la ERS: `RF-DET-01` a `RF-DET-05` [P], `RF-DIF-03` [D].

#### F-03 · El JavaScript del panel no se analiza estáticamente — **RESUELTO**

> **Estado:** cerrado en la tarea P2 (refactor R-05), 17-09-2026. El JS vive en
> `static/app.js` (584 líneas) y `static/login.js`; ESLint analiza **649 líneas
> en 2 archivos** con 0 errores y 0 avisos. Los 17 hallazgos de la primera
> corrida se corrigieron sin una sola supresión — detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.7.
>
> `RNF-USA-08` (accesibilidad) pasó de diferido a implementado en lo esencial:
> los elementos interactivos son alcanzables por teclado.

*Enunciado original del hallazgo:*

`eslint-plugin-security` y `eslint-plugin-no-unsanitized` están configurados y
verificados (disparan correctamente contra un archivo de prueba), pero apuntan a
`static/**/*.js` y **ese directorio no existe**: las 718 líneas de la interfaz
viven embebidas en `templates/index.html`, que ESLint no analiza.

O sea: de los dos linters de código estático que el proyecto se propuso
demostrar, el de JavaScript hoy corre sobre cero archivos. Se cubre de forma
indirecta — `test_s02_xss_dashboard.py` ejecuta el `esc()` real en Node y
verifica que no queden handlers `on*=` — pero no es análisis estático del
lenguaje.

Depende del refactor **R-05** (extraer el script a su propio archivo).

#### F-04 · No hay pruebas de navegador

Cero pruebas end-to-end de interfaz. El flujo que se demuestra en la defensa —
abrir el panel, filtrar, seleccionar un incidente, aprobar una acción, ver el
estado persistir — no está cubierto por ninguna prueba automatizada.

Depende también de R-05: testear 718 líneas de HTML+CSS+JS en un archivo es
posible pero frágil.

### 3.3 Menor, pero real

#### F-05 · El contrato de `/api/v1/incidents` es inconsistente

Con 0 incidentes, la respuesta **no incluye** `analyst_mode`:

```bash
$ python3 prepare-for-ia.py && python3 classifier.py   # sin ataques en 24 h
$ curl -s localhost:5000/api/v1/incidents | jq 'keys'
["generated_at", "incident_count", "incidents", "source"]   # falta analyst_mode
```

Ocurre porque `siem_agent.py` retorna temprano cuando no hay incidentes, sin
escribir el campo. El panel lo tolera (JavaScript trata `undefined` como "sin
análisis"), pero **un consumidor programático se rompe** — de hecho se rompió el
script de verificación de esta auditoría, con `KeyError: 'analyst_mode'`.

Contradice `RF-API-01`, que especifica un contrato estable para integraciones.

#### F-06 · La demo depende de haber atacado en las últimas 24 horas — **MITIGADO**

> **Estado:** mitigado el 25-09-2026 con `scripts/demo.sh`, que prepara todo con
> un comando y aborta con mensaje claro si el panel quedaría vacío
> (`--estado` lo diagnostica sin tocar nada). El riesgo no desaparece —la ventana
> sigue siendo de 24 h— pero deja de depender de que alguien se acuerde.
>
> **Ampliado (D2, 25-09-2026):** `scripts/demo-ataque.sh` lanza un ataque con el
> panel proyectado, con IP nueva en cada corrida, así la defensa no depende de
> datos preexistentes: la detección ocurre delante del tribunal. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.12.

*Enunciado original del hallazgo:*

Verificado hoy: con el stack corriendo y 7 364 documentos ingeridos, el pipeline
devolvió **0 incidentes**, porque las 7 alertas y los logs de autenticación son
anteriores a la ventana de 24 h.

No es un defecto del código — la ventana es correcta y deliberada — pero sí un
riesgo de demostración: **si el día de la defensa nadie corre una simulación
antes, el panel se ve vacío.** El runbook tiene que decirlo de forma explícita.

#### D-01 · Una regla ruidosa tapaba a todas las demás — **RESUELTO**

> Hallado el 25-09-2026, fuera del plan. `prepare-for-ia.py` pedía las 10
> alertas más recientes; con 116 alertas de 8 reglas, las 10 eran todas de la
> más ruidosa. Quedaba afuera `SSH Successful Login After Brute Force`
> (crítica: la fuerza bruta funcionó). Corregido agrupando por regla en
> Elasticsearch. Detalle en [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.9.

#### D-02 · La víctima aparecía como atacante en las alertas — **RESUELTO**

> Hallado el 25-09-2026. Las alertas *threshold* dicen por qué campo agruparon, y
> ese dato se descartaba: una regla centrada en el host atacado producía un
> incidente que lo acusaba de atacante, con un `ufw deny` contra la propia
> víctima. Misma familia que L-02, por el camino de las alertas. Detalle en §4.10.

#### D-03 · El guion de la demostración imprimía una línea vacía — **RESUELTO**

> Hallado el 25-09-2026 al actualizar el paso 7 del guion. `demo.sh` lo imprime
> con un `cat <<GUION` **sin comillas**, deliberadamente, para expandir las
> credenciales del laboratorio; el efecto colateral es que los backticks del
> texto se **ejecutan** como sustitución de comandos. Escribir `` `campana` `` en
> la prosa —la sintaxis natural de Markdown— borró la línea en silencio.
>
> Además, el paso 7 mandaba a `run-port-scan.sh --offline`, con la IP fija
> 172.18.0.7 que `demo.sh` ya había usado al preparar el laboratorio: el ataque
> "en vivo" se habría fundido con un incidente existente, sin nada nuevo que
> señalar. Tres pruebas de regresión. Detalle en §4.12.

#### D-04 · El documento de evidencia declaraba carencias ya cerradas — **RESUELTO**

> Hallado el 25-09-2026. `03-evidencia-para-la-catedra.md` seguía instruyendo a
> declarar "sin autenticación" y "4 de 13 reglas, creadas a mano" —cerradas por
> P1 y P3— y a responder que el entorno **no** es reproducible. Habría hecho
> admitir en la defensa carencias que el proyecto ya no tiene. Corregido, y la
> tabla de limitaciones ahora lista las dos que sí quedan: la discrepancia de
> umbral de la regla A2 y la ERS sin actualizar (P11).

#### D-05 · El guion pedía editar la auditoría real a mano — **RESUELTO**

> Hallado el 25-09-2026 al construir D3. Para demostrar que el registro detecta
> manipulación, `03-evidencia-para-la-catedra.md` instruía *"editar a mano una
> decisión aprobada"* de `decisions.jsonl`, sin copia y sin decir cómo volver
> atrás. Seguirlo en la defensa habría dejado la auditoría del equipo con la
> cadena rota de forma permanente: restaurarla exige los bytes originales
> exactos. Reemplazado por `./scripts/demo-auditoria.sh`, que trabaja sobre una
> copia y prueba con SHA-256 que el archivo real no cambió. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.13.
>
> **Propiedad que quedó escrita:** alterar el **último** registro de la cadena no
> es detectable —el encadenado protege a través del eslabón siguiente—. Cerrarlo
> requiere un ancla externa, que hoy no existe. Hay una prueba que lo fija y que
> avisará si eso cambia.

#### D-06 · Insignias de severidad por debajo de WCAG AA — **RESUELTO**

> Hallado el 25-09-2026 en la tarea G1. `CRITICAL` daba **3.35:1** y `HIGH`
> **3.37:1** con texto blanco sobre sus propios rellenos; AA pide 4.5:1 para
> texto normal, y una insignia de 11px bold no califica como "texto grande".
> `MEDIUM` y `LOW` ya usaban texto oscuro: la incoherencia era la pista.
> Corregido en las cuatro. Completa `RNF-USA-08`, que hasta acá cubría solo
> navegación por teclado. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.14.
>
> **Hallazgo lateral, y más grave:** `.badge` fijaba `color:#fff` sin fondo, y el
> panel arma la clase como `"b-" + sev.toUpperCase()`. Una severidad fuera de las
> cuatro —`"alta"` produce `.b-ALTA`, que no existe— dejaba la insignia con letras
> blancas sobre el fondo del panel: invisible. El respaldo determinístico
> normalizaba, pero la salida del LLM se pasaba tal cual. Corregido por las dos
> capas: relleno neutro en `.badge` y normalización en
> `siem_agent.analyze_incident`, que ante un valor irreconocible usa la severidad
> **determinística** y no `MEDIUM` — defaultear habría degradado en silencio un
> incidente crítico.

#### D-07 · El login había quedado fuera del refactor R-05 — **RESUELTO**

> Hallado el 25-09-2026 en la tarea G2. `templates/login.html` seguía con 37
> líneas de CSS embebido y su **propio `:root`**: R-05 extrajo el CSS del panel y
> dejó esta pantalla atrás, fuera de la caché, del análisis estático y de los
> tokens. Ya había costado algo concreto — `--ok` valía `#238636` en el panel y
> `#3fb950` en el login: el mismo nombre con dos colores. Extraído a
> `static/login.css`, con los tokens compartidos en `static/tokens.css`. Detalle
> en [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.15.
>
> **Hallazgo lateral:** el `:hover` del botón de login **aclaraba** el fondo, y con
> texto blanco eso bajaba el contraste de 4.63:1 a **3.37:1** — el botón se volvía
> menos legible justo antes del clic. Se oscurece, lo que da la misma señal de
> interacción y sube a 5.41:1.

#### D-08 · El cuadrado rojo del encabezado decía algo que no era cierto — **RESUELTO**

> Hallado el 25-09-2026 en la tarea G3. El 🟥 del panel «Eventos de Seguridad
> Activos» no era un icono: era un cuadrado rojo, y rojo es el color de
> `CRITICAL` en este sistema. Un cuadrado rojo permanente en el encabezado
> afirmaba una severidad que no correspondía. Igual el 🟢 / 🟡 de la insignia de
> modo, cuyo verde y ámbar los ponía el sistema operativo y no el significado,
> pudiendo discrepar del color que ya definía la clase CSS.
>
> Los 16 emoji de color se reemplazaron por un sprite de 14 símbolos SVG con
> `currentColor`. Los glifos tipográficos (`→ ▸ ▾ ✕ ✔ ✘`) se dejaron como texto a
> propósito: ya son monocromos y ya heredan el color. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.16.
>
> **Hallazgo lateral:** el colapso de evidencia se generaba con un
> `style="display:none"` construido desde JavaScript — el último estilo en línea
> del proyecto, en el único lugar donde ninguna herramienta lo miraba.

#### D-09 · El chip de estado estaba pintado como el botón de la acción — **RESUELTO**

> Hallado el 25-09-2026 en la tarea G4. En la fila de cada acción recomendada, el
> chip `approved` y el botón `Aprobar` eran los dos **relleno verde saturado con
> texto blanco**, uno al lado del otro. Un relleno saturado dice "apretame": el
> chip invitaba a un clic que no existe, y el analista podía leer «aprobada» como
> si todavía tuviera que aprobar. En el panel donde la decisión humana es el único
> mecanismo de contención, esa ambigüedad no es cosmética.
>
> Los estados pasaron a tinte con borde (se leen como etiqueta) y los botones
> conservan el relleno sólido. El chip lleva además `✔` / `✘`, así la distinción no
> depende solo del color. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.17.
>
> **Hallazgo lateral:** el chip mostraba el valor crudo de la API (`approved`,
> `pending`) en un panel en español, mientras el historial de decisiones —unas
> líneas más abajo del mismo archivo— ya traducía con marca. Dos vocabularios para
> lo mismo en la misma pantalla; unificados.

#### D-10 · La fila de resumen no destacaba nada — **RESUELTO**

> Hallado el 25-09-2026 en la tarea G5. Siete recuadros del mismo tamaño y el mismo
> peso —Incidentes, Acciones, Pendientes, Críticos, Altos, Medios, Bajos—, así que
> nada guiaba la mirada; y como las severidades suelen concentrarse, tres de los
> siete mostraban 0 con la misma prominencia que el número que importa.
>
> Ese número es uno: cuántas acciones esperan una decisión humana, que es lo que el
> panel existe para resolver. Ahora es el único destacado, y se enciende solo si hay
> pendientes. La severidad pasó a una barra apilada con leyenda, que **sigue listando
> las cuatro** —un cero informa— sin que compitan. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.18.
>
> **Sin incidentes, el resumen mostraba siete ceros:** correcto y mudo. Ahora dice qué
> correr para generar uno.

#### D-11 · El panel atribuía a Elastic detecciones que no pasaron por Elastic — **RESUELTO**

> Hallado el 26-09-2026 al preparar la demostración desde cero. `detect_port_scans`
> y `detect_phishing` fijaban a mano `rule_name="Network port scan detection"` y
> `severity_siem="high"`. **Ninguno de esos nombres existe en Kibana** —el catálogo
> los llama «Port Scan – Many Distinct Ports» y «Credential Submission to Suspicious
> Login»— y esos dos detectores ni siquiera consultan Elasticsearch: leen
> `network_logs/`. El panel mostraba, bajo la etiqueta «Regla SIEM», una procedencia
> que no había ocurrido.
>
> Era peor que una imprecisión: el proyecto **sí** tiene algo que decir acá —hay dos
> caminos de detección y el sistema funciona aunque el SIEM no dispare— y el nombre
> inventado tapaba ese argumento con otro que no era cierto. Ahora cada incidente
> declara su procedencia en `detection_source`. Detalle en
> [`../12-registro-de-pruebas.md`](../12-registro-de-pruebas.md) §4.19.
>
> **Hallazgo lateral:** la cadena de respaldos de severidad del panel estaba repetida
> en **seis lugares** y no incluía la severidad determinística, así que vaciar
> `severity_siem` habría degradado incidentes a `MEDIUM` en silencio. Unificada en
> `severidadDe()`.

#### D-12 · Una agregación sin `.keyword` rompía toda la captura del SIEM — **RESUELTO**

> Hallado el 26-09-2026, y **solo visible arrancando de cero**. Con los índices de
> Filebeat recién creados, `siem_lib.source_ip_aggregation` agregaba sobre
> `source_ip` —que el mapeo dinámico deja como `text`— y Elasticsearch devolvía
> `Fielddata is disabled`: un HTTP 400 que abortaba la captura entera. El pipeline
> clasificaba solo desde `network_logs/`, sin un incidente de autenticación.
>
> El catálogo de reglas ya documentaba esta trampa y se corrigió en P3; `siem_lib`
> quedó afuera, porque las reglas son datos y esto es código. No se había notado
> porque la captura es una etapa **tolerable**: el pipeline seguía con el
> `siem_clean.json` anterior y terminaba en código 0. Detalle en §4.20.
>
> **Consecuencia para la defensa:** `demo-desde-cero.sh` ahora exige que la captura
> sea nueva y aborta si no lo es, porque mostrar datos viejos es exactamente lo que
> esa demostración afirma que no ocurre.

#### D-13 · Siete de las trece reglas disparan y su alerta se descarta — **ABIERTO**

> Hallado el 26-09-2026 al responder qué pasa si alguien escribe sus propias
> reglas en Kibana. `detect_auth_incidents` filtra las alertas por una lista
> blanca de **una sola técnica**:
>
> ```python
> _AUTH_MITRE_TECHNIQUES = {"T1110"}
> if technique_id and technique_id not in _AUTH_MITRE_TECHNIQUES:
>     continue
> ```
>
> El filtro es correcto en lo suyo —sin él, una alerta de port scan se procesaría
> como un incidente SSH con 0 eventos reales— pero deja un hueco: **ninguna otra
> ruta convierte una alerta en incidente**. Medido sobre el catálogo:
>
> | Familia | Reglas | Técnica | ¿Produce incidentes? |
> |---------|--------|---------|----------------------|
> | A1–A6 (SSH) | 6 | T1110 | Sí |
> | B1–B4 (escaneo) | 4 | T1046 | **No** |
> | C1–C3 (phishing) | 3 | T1566 | **No** |
>
> Los incidentes de escaneo y phishing que sí aparecen los produce el Agente 1
> leyendo `network_logs/` (ver D-11), no esas siete reglas.
>
> **Consecuencia práctica:** quien escriba una regla nueva solo la verá reflejada
> en el panel si la mapea a T1110 — o si la deja **sin** mapeo MITRE, en cuyo caso
> pasa el filtro y se procesa como incidente de autenticación aunque no lo sea.
>
> **Qué haría falta:** un detector que convierta en incidente cualquier alerta que
> los detectores específicos no reclamen, con un playbook genérico sin comando
> sugerido (revisión manual). No se implementó: cambia el modelo de incidentes y
> es una decisión de diseño del equipo, no una corrección.

#### F-07 · Cobertura desigual en el Agente 2 — **PARCIAL**

> **Estado:** 31 % → **39 %** el 25-09-2026. G1 le dio su primer archivo de
> pruebas propio (`tests/unit/test_severidad_del_agente.py`, 35 pruebas), que
> cubre la normalización de severidad y sustituye `_llm_analysis` con un doble en
> lugar de depender del paquete `google`. Sigue siendo la pieza menos verificada:
> el armado del prompt y el parseo de la respuesta real de Gemini no se prueban.

*Enunciado original del hallazgo:*

`siem_agent.py` está en **31 %**, muy por debajo del resto (95 %). Su camino
principal depende de la API de Gemini y solo se prueban el respaldo y un cliente
hostil simulado. Está fuera del umbral a propósito, pero es la pieza menos
verificada del sistema.

#### F-08 · La suite dependía de la fecha (corregido durante esta auditoría)

Al correr la puerta de calidad hoy, **4 pruebas fallaron sin que nadie tocara el
código**: los fixtures hostiles tienen fecha fija del 16-09 y la ventana de 24 h
que introdujo B-05 empezó a descartarlos al cambiar el día.

Se corrigió encauzando todas las lecturas de fixtures por
`tests.conftest.eventos_de_red()` y se agregó una guarda
(`test_ningun_test_lee_un_fixture_con_la_ventana_por_defecto`) que detecta
cualquier reincidencia, verificada con una mutación. Queda registrado porque
ilustra un riesgo general: **una suite que depende del día en que corre no es una
red de seguridad, es un aviso que llega tarde.**

### 3.4 Lo que NO falla, y conviene decirlo

Estos puntos se auditaron específicamente y están bien:

- **Ningún componente ejecuta acciones de contención.** Único `subprocess` en
  `siem_pipeline.py`, con lista literal, sin shell, sin datos de log. El LLM no
  tiene *function calling*. Ninguna de las 10 rutas HTTP ejecuta nada.
- **Ningún comando sugerido contiene datos sin validar.** Los payloads de
  inyección se rechazan y la acción se omite.
- **El registro de auditoría detecta manipulación.** Editar, borrar o insertar
  una línea rompe la cadena.
- **Los secretos no están versionados.** `.env` está en `.gitignore` con valores
  reales rotados; `.env.example` solo tiene marcadores.
- **Los puertos están bindeados a `127.0.0.1`.** Nada del stack se expone a la red.

---

## 4. Qué falta implementar

### 4.1 Tabla de pendientes, por prioridad

| # | Pendiente | Esfuerzo | Desbloquea | ERS |
|---|-----------|:--------:|------------|-----|
| ~~**P1**~~ | ~~Login, sesiones y roles~~ — ✅ **hecho 17-09-2026** | — | — | `RQ-SEC-08/11/13`, `RF-DIF-04` ✅ |
| ~~**P2**~~ | ~~R-05: extraer el JS~~ — ✅ **hecho 17-09-2026** | — | Desbloquea **P4** | `RNF-MANT-01` ✅ |
| ~~**P3**~~ | ~~Reglas como código~~ — ✅ **hecho 17-09-2026** | — | — | `RF-DIF-03` ✅ |
| **P4** | Suite E2E con Playwright | Medio | Objetivo 3 de la materia | `RNF-MANT-06` |
| **P5** | Vista de triage y pantalla de decisión como rutas separadas | Medio | MVP presentable | `RF-SUP-01/03` |
| **P6** | CI (GitHub Actions o equivalente) | Bajo | Evidencia continua de los objetivos 1 y 2 | `RNF-MANT-06` |
| **P7** | Contrato estable de la API (F-05) + `note` al aprobar | Bajo | `RF-API-01`, `RF-SUP-04` | `RF-API-01` |
| **P8** | Umbrales a configuración externa | Bajo | `RNF-MANT-04`, `RNF-COMP-01` | `RNF-MANT-04` |
| **P9** | Documentar la lógica determinística (por qué 20, 5000, 10) | Bajo | Defensa oral | `RNF-OTR-01` |
| **P10** | Reubicar documentación suelta a `/docs` | Bajo | Pilar 6 del plan | — |

### 4.2 Lo que queda fuera del alcance y conviene declararlo

Decirlo por escrito vale más que simularlo:

- **MFA, SSO, recuperación de contraseña.** Un archivo de usuarios protegido
  alcanza para un MVP de laboratorio.
- **Suricata / IDS de red real.** Las simulaciones NDJSON cumplen el rol.
- **LLM local (Ollama).** El respaldo determinístico ya permite operar sin nube.
- **Respaldos cifrados y retención (`RQ-SEC-05`, `RQ-SEC-17`).** Es la brecha
  normativa más relevante frente a la Ley 25.326 y está identificada, no resuelta.

---

## 5. Los tres objetivos de la materia

### 5.1 Pruebas de código estático — ✅ cumplido

**Cuatro herramientas configuradas y corriendo:**

| Herramienta | Configuración | Hallazgos hoy |
|-------------|---------------|:-------------:|
| `pylint` + **`pylint-secure-coding-standard`** | `.pylintrc` | 0 · puntaje **9,51/10** |
| `bandit` | `.bandit` | 0 de severidad alta (2 LOW justificados) |
| `ruff` | `ruff.toml` | 0 |
| `eslint` + **`eslint-plugin-security`** + `no-unsanitized` | `eslint.config.js` | 0 (ver F-03) |

**Más un análisis estático propio:** `tests/test_no_autonomy.py` recorre el AST
de los 9 módulos para hacer cumplir una propiedad del producto —que nada ejecute
comandos— con 34 pruebas.

**Lo que hace demostrable este objetivo no es que las herramientas estén
instaladas, sino que se probó que detectan.** Se inyectaron violaciones reales y
se verificó que la puerta las encuentra:

| Mutación inyectada | Detectada por |
|--------------------|---------------|
| `hashlib.md5()` nuevo | ruff `13 (base 12)` · bandit `3 (base 2)` |
| `os.system()` en `api_decision` | `test_sin_llamadas_de_ejecucion[dashboard.py]` |
| `getattr(os, 'system')` disfrazado | `test_sin_llamadas_de_ejecucion[classifier.py]` |
| `import paramiko` | `test_sin_imports_de_ejecucion[siem_agent.py]` |
| Ruta `POST /api/execute` | `test_el_dashboard_no_define_rutas_de_ejecucion` |
| `innerHTML` no saneado + `eval` | `no-unsanitized/property` · `security/detect-eval-with-expression` |

Las líneas de base están en **cero**: cualquier hallazgo nuevo rompe la puerta.

**Hallazgos reales que el SAST encontró y se corrigieron:** 2 usos de SHA-1
(`B324`), 2 escrituras sin modo explícito sobre el registro de auditoría
(`R8005` — el plugin señaló por su cuenta el escritor de la auditoría, sin estar
configurado para eso), y `subprocess.run` sin `check=` (`W1510`).

```bash
./scripts/check.sh --sast     # reproduce todo, ~10 s
```

### 5.2 Pruebas de servicio — ✅ cumplido

**111 pruebas de integración** que ejercitan componentes corriendo, no funciones
sueltas:

| Suite | Pruebas | Qué ejercita |
|-------|--------:|--------------|
| `test_api_v1.py` | 38 | Contrato `/api/v1/` completo con cliente Flask |
| `test_a02_a04_integridad.py` | 35 | Cadena de hash, concurrencia real (20 hilos), `audit_verify.py` como **proceso** |
| `test_api_caracterizacion.py` | 19 | Contrato histórico y compatibilidad |
| `test_a01_reset_preserva_auditoria.py` | 12 | El `reset.sh` **real** contra un sandbox |
| `test_auditoria_append_only.py` | 7 | Invariantes del registro; lanza `siem_agent.py` real |

**Cobertura de los endpoints:** las 10 rutas, códigos 200/201/400/404, validación
de tipos y límites, errores siempre en JSON, `Cache-Control`, y el caso que
importa — una decisión sobre una acción inexistente se rechaza **sin escribir** en
el registro inmutable.

**Dos defectos reales que encontraron estas pruebas:**

1. `data.get("note") or ""` convertía `[]` y `{}` en cadena vacía por ser
   *falsy*, saltándose el chequeo de tipo. Se corrigió el código, no la prueba.
2. `audit_verify.py` reportaba "CADENA ROTA · el registro fue modificado" para
   los 27 registros anteriores al encadenado. Falso y contraproducente: una
   alerta que siempre aparece y siempre es falso positivo enseña a ignorar la
   herramienta. Ahora distingue `ok` / `heredado` / `roto`.

```bash
./scripts/check.sh --tests    # 420 pruebas, ~11 s
```

### 5.3 Entorno de simulación — ⚠️ parcial

**Lo que sí está demostrado**, verificado hoy en ejecución:

```bash
$ docker compose ps          # 4 servicios arriba, ES healthy
$ # 7364 documentos ingeridos hoy · 7 alertas de seguridad · 4 reglas activas

$ python3 classifier.py
  Incidentes detectados: 3
   • INC-AUTH-203.0.113.77-a4a68599: ssh_brute_force [ALTA] — 24 eventos
   • INC-SCAN-203.0.113.77-f1b2a849: port_scan [ALTA] — 16 eventos
   • INC-PHISH-172.18.0.9-2959d492: credential_harvesting [ALTA] — 1 eventos

$ # decisión del analista → 201 · sudo ufw deny from 203.0.113.77
$ # auditoría → {'estado': 'ok', 'chain_ok': True, 'records': 1}
```

La cadena completa funciona: ataque → ingesta → detección → clasificación →
análisis → supervisión → registro verificable. Los tres tipos de ataque se
simulan y se detectan. El modo sin conexión permite demostrar todo sin Docker.

**Lo que falta para cerrarlo:**

| Falta | Por qué importa para este objetivo |
|-------|-----------------------------------|
| ~~Reglas como código (F-02)~~ | ✅ resuelto en P3: `docker compose up -d && ./scripts/deploy-rules.sh` ⇒ 13 reglas activas |
| ~~Login (F-01)~~ | ✅ resuelto en P1: el panel exige sesión y tres roles |
| E2E de navegador (F-04) | La interfaz es la parte del sistema que se demuestra, y es la única sin pruebas |
| Runbook de demo (F-06) | Sin correr una simulación antes, el panel se ve vacío el día de la defensa |

---

## 6. Trazabilidad con la ERS del Grupo 4

La ERS v1.0.0 (22-08-2026) declara **125 requisitos**: 83 implementados,
22 parciales, 20 diferidos. Las tres fases de trabajo posteriores cambiaron el
estado de varios. **La ERS está desactualizada respecto del código.**

### 6.1 Requisitos que pasaron a implementados y la ERS todavía no refleja

| Requisito | Estado en la ERS | Estado real hoy | Evidencia |
|-----------|:----------------:|:---------------:|-----------|
| `RF-DIF-07` — cadena de resúmenes criptográficos del registro | **[D] Diferido** | ✅ **Implementado** | `siem_lib.verificar_cadena()` · `audit_verify.py` · 35 pruebas |
| `RQ-SEC-14` — inmutabilidad detectable | **[P]** *"no hay detección de manipulación externa"* | ✅ **Implementado** | Editar una línea rompe la cadena |
| `RNF-MANT-06` — capacidad de ser testeado | **[D]** *"condición previa de todos los demás"* | ✅ **Implementado** | 420 pruebas · 95 % cobertura |
| `RQ-SEC-19` — validación de esquema | **[P]** *"cubre la interfaz de decisión, no la ingesta"* | ✅ **Implementado** | `siem_validators.py` valida la ingesta de red |
| `RNF-CONF-01` — madurez | **[D]** *"sin suite de pruebas"* | ✅ **Implementado** | La suite existe |
| `RQ-SEC-08` — identidad del analista | **[P]** *"sale de una variable de entorno"* | ✅ **Implementado** | Sale de `current_user` (P1) |
| `RQ-SEC-11` — CSRF | **[D]** | ✅ **Implementado** | `Flask-WTF`, token por header |
| `RQ-SEC-13` — gestión de sesiones | **[D]** | ✅ **Implementado** | Expiración doble, cookie firmada |
| `RF-DIF-04` — control de acceso por roles | **[D]** | ✅ **Implementado** | 3 roles, permisos en tabla |
| `RF-DIF-03` — detección como código | **[D]** | ✅ **Implementado** | `rules/ndjson/` + `deploy-rules.sh` (P3) |
| `RF-DET-01` a `RF-DET-05` | **[P]** *"se crean a mano; no se despliegan con el sistema"* | ✅ **Implementado** | Las 13 versionadas y desplegables |

> **Acción para la entrega:** actualizar la ERS a v1.1.0 con estos cambios de
> estado. Son **nueve** requisitos que el equipo puede reportar como ganados, y
> el panel de Historial de versiones de Google Docs —que la cátedra audita— debe
> registrar el hito.

### 6.2 Requisitos que siguen abiertos y son el trabajo pendiente

| Requisito | Estado | Pendiente asociado |
|-----------|:------:|--------------------|


| `RNF-MANT-04` — umbrales en configuración | [P] | **P8** |
| `RNF-USA-08` — accesibilidad verificada | [D] → **[P]** | Teclado y ARIA hechos en P2; falta un linter de accesibilidad |
| `RF-SUP-04` — nota al aprobar | [P] | **P7** |
| `RF-DIF-06` — historial de incidentes analizados | [D] | fuera de alcance v1.0 |
| `RQ-SEC-05`, `RQ-SEC-17` — respaldos y retención | [D] | fuera de alcance v1.0 |

### 6.3 Requisitos donde el código superó a la ERS

`RF-API-01` a `RF-API-03` especifican tres endpoints. El sistema hoy expone
**diez**, con versionado `/api/v1/`, sonda de salud y endpoint de verificación de
auditoría. La ERS debería incorporarlos, o declarar explícitamente que los
adicionales son extensiones no especificadas.

---

## 7. Riesgos para la entrega

| Riesgo | Probabilidad | Mitigación |
|--------|:------------:|------------|
| ~~El panel se ve vacío el día de la defensa~~ | Baja | ✅ mitigado: `./scripts/demo.sh` lo prepara todo y `--estado` lo diagnostica |
| **Nadie puede entrar al panel** porque falta `SECRET_KEY` o no hay usuarios | **Alta** | Nuevo desde P1: agregar al checklist de preparación (`crear` un usuario y generar la clave). El servidor avisa en el arranque |
| ~~La cátedra pide reproducir el entorno y faltan 9 reglas~~ | — | ✅ resuelto en P3: 13 reglas desplegables con un comando |
| ~~Se señala que el MVP no tiene login~~ | — | ✅ resuelto en P1 |
| ~~Se pide ver ESLint corriendo y no analiza nada~~ | — | ✅ resuelto en P2: 649 líneas analizadas |
| La ERS desactualizada se lee como que el estado no se verificó (§6.1) | Media | Actualizar a v1.1.0 con los 5 requisitos ganados |
| Un cambio de fecha vuelve a romper la suite (F-08) | Baja | Ya mitigado con la guarda; mantenerla |

---

## 8. Conclusión

**El núcleo del sistema está construido, verificado y es defendible.** La cadena
completa funciona de punta a punta, la propiedad central —que el sistema no
ejecuta nada— está certificada por análisis estático automatizado y probada
contra mutaciones, y el registro de decisiones pasó de ser inmutable por
convención a serlo de forma verificable.

De los tres objetivos de la materia, **dos están cumplidos con evidencia
reproducible** y el tercero está a cuatro tareas acotadas de estarlo. Ninguna de
esas cuatro es investigación: son trabajo conocido, con criterio de aceptación
escrito y una red de 420 pruebas que avisa si algo se rompe en el camino.

**Lo más valioso para la defensa no es el porcentaje de cobertura, sino poder
mostrar que las pruebas encuentran cosas.** Esta auditoría documenta ocho
defectos reales hallados por las herramientas —dos de ellos durante la propia
auditoría, incluida una suite que se rompía sola al cambiar el día— y eso
demuestra que el instrumental funciona mejor que cualquier métrica.

El orden recomendado para continuar está en
[`02-prompt-de-trabajo.md`](02-prompt-de-trabajo.md), que puede usarse tarea por
tarea sin perder el contexto entre sesiones.
