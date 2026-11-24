# Inventario para las pruebas de rendimiento (carga y estrés) con k6

Insumo para armar el plan. No hay ninguna prueba nueva escrita. Todo sale de `Grupo4-ERS.docx`, del código y de comprobaciones hechas el 23-11-2026 contra la malla aislada (gateway en `http://127.0.0.1:18080`). Las rutas son relativas a `Elastic-SIEM-Project/`.

## Resumen

| Tema | Resultado |
|---|---|
| Requisitos con valor numérico de rendimiento | 9 de la familia RNF-RD y 12 más de otras familias (sección 1) |
| Medibles con k6 sobre la malla | RNF-RD-01, RD-04, RD-05, RD-09, RNF-CONF-06, RNF-CONF-07, RQ-SEC-27, RQ-SEC-28 y, en parte, RNF-COMP-01 |
| No medibles con k6 | RNF-RD-02, RD-03, RD-06, RD-07, RD-08, RNF-CONF-01, CONF-03, CONF-05 y RNF-PORT-02 (sección 1.3) |
| Carga esperada en producción | 1 o 2 analistas (ERS 3.1); el k6 del repositorio dice 1 a 5. Las pruebas exigen 20, 50 y 100 concurrentes |
| Endpoints críticos del gateway | 7 de 15 (sección 3) |
| Limitador de peticiones | **No existe** (0 coincidencias de `flask_limiter` o `ratelimit`). Solo hay bloqueo de login por intentos fallidos |
| Sesiones por usuario | **Sin límite**: 30 inicios de sesión simultáneos del mismo usuario quedaron válidos a la vez |
| Usuarios en la malla | 3 (`analista00`, `observador00`, `auditor00`). Alcanzan: no hace falta crear más |
| Volumen de incidentes en la malla | **3**, y RNF-RD-01 exige hasta 100: hay que sembrar datos (sección 4.3) |
| k6 | **No está instalado** en el equipo. Docker 26.1.5 sí y el registro de `grafana/k6:1.3.0` responde, pero la imagen no está descargada |
| Pruebas k6 que ya existen | `tests/performance/neuraldefender.js` (206 líneas) y `scripts/pruebas_de_performance.sh`. No registran decisiones: falta cubrir RNF-RD-04 |

## 1. Requisitos de rendimiento de la ERS

Los textos están copiados de la ERS; entre corchetes, el valor numérico que se mide.

### 1.1 Familia RNF-RD (eficiencia y capacidad, ISO/IEC 25010)

| ID | Texto exacto (resumido solo donde se marca «…») | Valores |
|---|---|---|
| RNF-RD-01 | «El módulo de supervisión deberá responder a la consulta del listado de incidentes en menos de 2 segundos en el 95 % de las peticiones, con 20 analistas concurrentes y un volumen de hasta 100 incidentes activos (relacionado con RF-SUP-01 y RF-API-01). Se verifica con el perfil «carga» de k6 (tests/performance/neuraldefender.js) ejecutado con al menos 100 incidentes cargados en el pipeline.» | p95 < **2 s**; **20** analistas; **100** incidentes |
| RNF-RD-02 | «El proceso del Agente 2 no deberá superar los 256 MB de memoria residente durante una corrida completa de análisis, y el montón de memoria del almacén de eventos no deberá exceder los 512 MB asignados…» | **256 MB** y **512 MB** |
| RNF-RD-03 | «El sistema deberá procesar una corrida completa de pipeline sobre una ventana de 24 horas con hasta 50.000 eventos y hasta 100 incidentes resultantes, en menos de 5 minutos en modo de respaldo determinístico…» | **50.000** eventos; **100** incidentes; **5 min** |
| RNF-RD-04 | «El registro de una decisión del analista deberá completarse y quedar persistido en menos de 500 milisegundos desde la recepción de la petición… Se verifica sobre una malla aislada de los microservicios, nunca sobre el registro de auditoría de producción, que es inmutable: con 20 analistas concurrentes, el p95 del POST /api/v1/decision deberá ser menor a 500 ms.» | p95 < **500 ms**; **20** analistas |
| RNF-RD-05 | «Una corrida del pipeline de análisis no deberá degradar el tiempo de respuesta del módulo de supervisión por encima del doble de su valor nominal… El valor nominal es el p95 del perfil “carga” de k6 con el ciclo automático desactivado (SIEM_PIPELINE_INTERVALO=0). Se verifica repitiendo el perfil con el ciclo activo cada 2 minutos y comparando ambos p95.» | p95 con ciclo ≤ **2 ×** p95 nominal; ciclo cada **2 min** |
| RNF-RD-06 | «El módulo de supervisión deberá renderizar como máximo 100 incidentes por vista, ofreciendo el resto a través de los filtros…» | **100** incidentes por vista |
| RNF-RD-07 | «El intervalo entre la generación de una alerta por el motor de detección y su disponibilidad como incidente analizado en la interfaz de supervisión no deberá superar los 3 minutos, con la corrida programada cada 2 minutos y el refresco del panel cada 15 segundos…» | **3 min**; ciclo **2 min**; refresco **15 s** |
| RNF-RD-08 | «El modelo de lenguaje local deberá liberar la memoria que ocupa tras 5 minutos sin uso, y el Agente 2 no deberá volver a ejecutarlo sobre incidentes cuyo análisis siga vigente…» | **5 min** |
| RNF-RD-09 | «El módulo de supervisión deberá atender hasta 100 analistas concurrentes sin errores (menos del 1 % de peticiones fallidas) y con un p95 menor a 500 ms en todas las lecturas del panel, y deberá volver a su latencia nominal en menos de un minuto después de un pico. Se verifica con los perfiles «estrés» y «pico» de k6.» | **100** analistas; fallos < **1 %**; p95 < **500 ms**; recuperación < **1 min** |

### 1.2 Otros requisitos con tiempos, usuarios concurrentes, volumen o disponibilidad

| ID | Texto exacto (resumido solo donde se marca «…») | Valores |
|---|---|---|
| RNF-CONF-01 | «El módulo de supervisión deberá estar disponible al menos el 99 % del tiempo durante la jornada operativa de la organización…» | disponibilidad ≥ **99 %** |
| RNF-CONF-03 | «Tras una caída del sistema, el estado vigente de todas las decisiones deberá reconstruirse íntegramente mediante la reproducción del registro de auditoría, sin pérdida de ninguna decisión previamente registrada y en menos de 5 segundos para el volumen previsto…» | **5 s** |
| RNF-CONF-05 | «El orquestador de contenedores deberá verificar la salud de cada servicio de la capa SIEM cada 30 segundos y reiniciar automáticamente aquel que no responda tras tres verificaciones consecutivas fallidas, con una indisponibilidad máxima de 90 segundos…» | **30 s**; **3** verificaciones; **90 s** |
| RNF-CONF-06 | «El almacén de usuarios deberá mantenerse íntegro ante inicios de sesión concurrentes: con 50 clientes simultáneos, ningún usuario válido deberá ser rechazado por un error del almacén y el archivo no deberá quedar dañado…» | **50** clientes; **0** rechazos |
| RNF-CONF-07 | «Los archivos de intercambio entre capas… deberán escribirse de forma atómica… Con 100 analistas concurrentes y el ciclo automático activo, ninguna lectura deberá fallar por esta causa.» | **100** analistas; **0** lecturas fallidas |
| RNF-COMP-01 | «El sistema deberá operar en un host compartido con otros productos sin impacto adverso sobre ellos, entendido como ningún reinicio, ninguna verificación de salud fallida, ningún sondeo funcional de más de 2 segundos y ningún proceso terminado por falta de memoria… Medida: ISO/IEC 25023 CCo-1-G, X_COE = Prod_OK / Prod_Esp, con Prod_Esp = 7 productos…, en corridas de 60 s con 1 a 50 clientes concurrentes. Mínimo aceptable: X_COE ≥ 0,85…» | **1 a 50** clientes; corridas de **60 s**; sondeo < **2 s**; X_COE ≥ **0,85** |
| RQ-SEC-27 | «Al menos el 99 % de los accesos de usuario —inicios de sesión exitosos, fallidos o bloqueados, decisiones y operaciones sobre la memoria del agente— deberá quedar registrado y atribuido a quien lo realizó, con la cadena de hash verificable; la meta es la totalidad… X_TRA = Acc_Reg / Acc_Tot, también con 50 clientes concurrentes. Mínimo aceptable: X_TRA ≥ 0,99…» | **50** clientes; X_TRA ≥ **0,99** |
| RQ-SEC-28 | «Al menos el 99 % de los intentos de autenticación deberá resolverse según la regla que les corresponde, también con 50 clientes concurrentes, y ningún impostor deberá ser aceptado en ningún caso… X_AUT = Aut_OK / Aut_Tot. Mínimo aceptable: X_AUT ≥ 0,99…» | **50** clientes; X_AUT ≥ **0,99**; impostores aceptados: **0** |
| RQ-SEC-13 | «Las sesiones de supervisión deberán expirar tras 30 minutos de inactividad o al alcanzar una duración absoluta de 8 horas.» | **30 min**; **8 h** |
| RF-AUT-04 | «El sistema deberá bloquear el inicio de sesión tras 5 intentos fallidos en 15 minutos por usuario y origen, con espera creciente…» | **5** intentos; **15 min** |
| RF-SUP-07 | «…actualizar automáticamente la información presentada cada quince segundos…» | **15 s** |
| RNF-PORT-02 | «El sistema deberá poder instalarse y ponerse en marcha desde cero en menos de 30 minutos…» | **30 min** |

### 1.3 Qué se puede medir con k6 sobre la malla

| Requisito | ¿Con k6 y la malla? | Observación |
|---|---|---|
| RNF-RD-01 | Sí | Necesita 100 incidentes cargados; la malla trae 3 (sección 4.3) |
| RNF-RD-04 | Sí | El k6 existente no registra decisiones; hay que escribir ese escenario. La malla es el entorno que el requisito exige |
| RNF-RD-05 | Sí, con trabajo extra | Exige el ciclo activo cada 2 min. La malla lo fuerza en 0 (`levantar_malla.py.txt:34`) y el programador acepta como mínimo 30 s (`programador.py:31`). Además el ciclo del collector lee el Elasticsearch real |
| RNF-RD-09 | Sí | Perfiles `estres` y `pico`. El k6 existente llega a 150 usuarios virtuales en `estres` y a 100 en `pico` |
| RNF-CONF-06, RQ-SEC-28 | Sí | 50 inicios de sesión simultáneos; ver sección 5 sobre el costo de Argon2id y el bloqueo |
| RQ-SEC-27 | Sí | Contar registros de acceso y de decisiones contra las peticiones enviadas (`/api/v1/reportes` o `/v1/access` del servicio audit) |
| RNF-CONF-07 | En parte | Mide solo que ninguna lectura falle con el ciclo activo, con el mismo requisito de ciclo que RD-05 |
| RNF-COMP-01 | En parte | Los 7 productos de la medida (Elasticsearch, Kibana, Logstash, Filebeat, Ollama, backup, autoheal) no forman parte de la malla; solo se puede medir el sondeo funcional de menos de 2 s |
| RNF-RD-02, RD-03, RD-07, RD-08 | No | Memoria residente, 50.000 eventos, latencia de detección y descarga del modelo no pasan por el gateway |
| RNF-RD-06 | No con k6 | Es del navegador; está en las pruebas de interfaz (CP-UI-53) |
| RNF-CONF-01, CONF-03, CONF-05, RNF-PORT-02 | No | Disponibilidad a lo largo de la jornada, reconstrucción tras una caída, `autoheal` e instalación desde cero quedan fuera de una corrida de k6 |

## 2. Carga esperada

| Fuente | Dato |
|---|---|
| ERS 3.1 (objetivos) | «dotar a un equipo de una o dos personas de una capacidad de triage… equivalente a la de un SOC de varios analistas». Producción: **1 o 2 analistas** |
| `tests/performance/neuraldefender.js` (comentario del perfil) | «Un SOC chico tiene 1-5; `carga` usa 20 (4x lo esperado)» |
| ERS, modelo de carga (sección sobre las pruebas) | Cada analista virtual refresca cada **1 a 3 s**, de 5 a 15 veces más seguido que el refresco real de 15 s. Por eso 20 usuarios virtuales equivalen a **100 a 300** analistas reales. El modelo se declara pesimista a propósito |
| Requisitos | Escalones de **20** (RD-01, RD-04), **50** (CONF-06, RQ-SEC-27, RQ-SEC-28, COMP-01) y **100** analistas (RD-09, CONF-07) |
| Ritmo de refresco del panel | Cada refresco del panel hace 3 lecturas: `incidents`, `decisions` y `memoria`, más `me` al abrirlo (`app.js:206-261`) |

Umbrales internos que declara la ERS en 7.6 y que usa el k6 existente: 500 ms para las lecturas del panel y 300 ms para `/me` y `/healthz`, frente a los 2 s de RNF-RD-01.

## 3. Endpoints candidatos del gateway

Autenticación: todas las rutas salvo `login` y `healthz` exigen la cookie `siem_session`. Los POST exigen además la cabecera `X-CSRFToken` con el `csrf_token` que devuelve el login (salvo el propio login, exento). Latencia: mediana de 5 lecturas en serie sobre la malla, con 3 incidentes y un solo cliente (referencia, no resultado de prueba).

| # | Endpoint (`dashboard.py`) | Método | Permiso | Escribe datos | Crítico | Qué hace por dentro | Mediana medida |
|---|---|---|---|---|---|---|---|
| 1 | `/api/v1/login` (:356) | POST | ninguno (sin CSRF) | Sí: registro de acceso en audit; limpia los fallos de intentos | **Sí** | Argon2id y alta de sesión | 130 ms (1 cliente) |
| 2 | `/api/v1/logout` (:417) | POST | sesión | Sí: registro de acceso `logout` | No | Cierra la sesión | no medido |
| 3 | `/api/v1/me` (:455) | GET | sesión | No | **Sí** (lo usa el panel al abrir) | Lee la cookie | 2 ms |
| 4 | `/api/v1/healthz` (:477) | GET | ninguno | No | **Sí** (sonda de salud, RNF-COMP-01) | Responde ok | 2 ms |
| 5 | `/api/v1/incidents` (:493) | GET | `ver_incidentes` | No | **Sí** (RNF-RD-01, RD-09) | Pide el reporte al pipeline y el estado de las decisiones a audit en cada llamada (`_load_incidents`, :307-328) | 5 ms |
| 6 | `/api/v1/incidents/<id>` (:502) | GET | `ver_incidentes` | No | No | Igual que el anterior, para un incidente | no medido |
| 7 | `/api/v1/decision` (:514) | POST | `decidir` + CSRF | **Sí**: línea en el registro de auditoría y un caso en la memoria (knowledge) | **Sí** (RNF-RD-04) | Valida, escribe en audit y después en knowledge | 8 ms (3 llamadas) |
| 8 | `/api/v1/decisions` (:647) | GET | `ver_auditoria` | No | **Sí** (lo lee cada refresco) | Lista las decisiones de audit | 3 ms |
| 9 | `/api/v1/audit/verify` (:656) | GET | `verificar_cadena` (solo auditor) | No | No (ocasional) | Recorre toda la cadena de hashes; el costo crece con el registro | no medido con permiso (el analista recibe 403) |
| 10 | `/api/v1/memoria` (:729) | GET | `ver_incidentes` | No | **Sí** (lo lee cada refresco) | Lecciones y documentos de knowledge | 4 ms |
| 11 | `/api/v1/memoria/documentos` (:740) | POST | `decidir` + CSRF | Sí | No | Carga un documento | no medido |
| 12 | `/api/v1/memoria/lecciones` (:750) | POST | `decidir` + CSRF | Sí | No | Propone una lección | no medido |
| 13 | `/api/v1/memoria/lecciones/<id>/revision` (:760) | POST | `decidir` + CSRF | Sí | No | Aprueba o rechaza | no medido |
| 14 | `/api/v1/reportes` (:774) | GET | `ver_auditoria` | No | No | Arma el reporte desde audit (CSV o JSON, con rango opcional) | no medido |
| 15 | `/` (HTML) y `/static/*` | GET | sesión (el HTML) | No | No | Plantilla y archivos estáticos | no medido |

Críticos para las pruebas (7): `login`, `me`, `healthz`, `incidents`, `decisions`, `decision` y `memoria`; `healthz` se mide como sonda de salud. El perfil existente de k6 recorre `me`, `incidents`, `decisions`, `memoria`, un incidente al azar, `audit/verify` en 1 de cada 10 iteraciones y `healthz`.

Lo que sale del código y condiciona el diseño:

- Cada `GET /api/v1/incidents` reconstruye el estado de las acciones desde el registro de decisiones. Si una prueba registra miles de decisiones, **las lecturas se vuelven más lentas durante la misma prueba**. Conviene medir las lecturas (RD-01, RD-09) y las escrituras (RD-04) en perfiles separados y reiniciar la malla entre ellos.
- Una misma acción puede decidirse varias veces: tres `POST /api/v1/decision` seguidos sobre la misma acción respondieron `201` en 8 ms cada uno. El registro conserva todas y la última gana. No hace falta tener tantas acciones como peticiones.
- Cada decisión además crea un caso en la memoria (knowledge) y puede disparar la propuesta automática de lecciones; son escrituras extra por petición.

## 4. Límites que pueden interferir

### 4.1 Resumen

| Límite | Valor | Dónde | Efecto en las pruebas |
|---|---|---|---|
| Limitador de peticiones (rate limiting) | **No existe** | 0 coincidencias de `flask_limiter` o `ratelimit` en `services/`, `libs/` y los `requirements` | Ninguna petición se rechaza por frecuencia: lo que se vea será capacidad real. Los 429 que menciona la ERS en 7.6 son los disyuntores de Elasticsearch, no del gateway |
| Bloqueo por intentos (RF-AUT-04) | 5 fallos en 15 min por **(usuario, IP)**; el sexto espera `60 × 2^exceso` s, con tope de 15 min; un login correcto borra los fallos | `siem_auth.py:67-68`, `334-372` | Solo cuentan los **fallos**. Con `127.0.0.1` como origen único, una contraseña errónea repetida bloquea al usuario 15 min. Los escenarios de impostor (RQ-SEC-28) deben usar un usuario descartable, nunca `analista00` ni `auditor00` |
| CSRF | Token exigido en todo POST salvo el login; sin vencimiento propio (`WTF_CSRF_TIME_LIMIT=None`) | `dashboard.py:125`, `135` | k6 tiene que conservar el `csrf_token` que devuelve el login y mandarlo en `X-CSRFToken` junto con la cookie de esa misma sesión. Un POST sin él da 403 antes de revisar la sesión |
| Cuerpo máximo | 64 KB | `dashboard.py:70`, `117` | Irrelevante para decisiones; sí para cargas de documentos grandes (el panel limita a 32 KB) |
| Vencimiento de sesión | 30 min de inactividad y 8 h absolutas | `sesion_web.py:36-37` | Una corrida de más de 30 min sin tráfico de un usuario virtual lo deja sin sesión; las corridas del plan duran minutos |
| Servidor del gateway en producción | `gunicorn` con **1 worker y 8 hilos**, timeout de 900 s | `services/gateway/Dockerfile:26-27` | Es el límite de concurrencia real: 8 peticiones en simultáneo |
| Servidor del gateway en la malla | `werkzeug` con `threaded=True` (un hilo por petición, sin tope), **los 8 servicios en un solo proceso de Python** | `levantar_malla.py.txt:61-78` | Los 8 servicios comparten el intérprete (GIL) y la CPU. Un login con Argon2id ocupa el proceso entero y retrasa a los demás. Las latencias de la malla **no son comparables** con las del stack en contenedores, que ya tiene resultados previos |
| Recursos del equipo | 16 CPUs, 14,9 GiB; con el stack Elastic corriendo había unos 1,4 GiB libres y 3,3 GiB de caché | `nproc`, `free -m` | Generador de carga y malla comparten el equipo. Conviene registrar el uso de CPU y memoria durante las corridas y no correr a la vez otras tareas |
| Directorio de datos de la malla | Temporal, se pierde al detenerla | `malla.sh` | `malla.sh reiniciar` devuelve el estado inicial: 3 incidentes y cero decisiones |

### 4.2 Estado de la malla durante este inventario

Mis comprobaciones dejaron huellas en la malla en ejecución: 31 inicios de sesión de `analista00` y 3 decisiones sobre una misma acción. Antes de cualquier medición hay que ejecutar `./entregables/2-servicios/postman/malla.sh reiniciar`. Los datos de estas pruebas se descartan con ese reinicio.

### 4.3 Volumen de incidentes

La malla se arranca con el reporte `tests/fixtures/siem_clean.min.json` y `network_logs`, y quedan **3 incidentes** (`INC-SCAN-…`, `INC-AUTH-…`, `INC-PHISH-…`, con 8, 15 y 7 acciones). El reporte vive en `data/siem_incidents.json` dentro del directorio temporal de la malla (`siem-medicion-*`, `medicion_iso25023.py:382` y `411`). RNF-RD-01 exige **al menos 100 incidentes cargados**. Hoy no hay forma incluida en `malla.sh` de sembrarlos: habría que escribir ese archivo con 100 incidentes (por ejemplo, copias con identificadores distintos) o ampliar `levantar_malla.py.txt`. Es una decisión pendiente. No verifiqué si el servicio pipeline relee el archivo en cada petición o lo guarda en memoria.

## 5. Usuarios y sesiones

| Pregunta | Respuesta | Evidencia |
|---|---|---|
| ¿Un mismo usuario puede tener muchas sesiones a la vez? | **Sí, sin límite visible.** La sesión es una cookie firmada en el cliente; el servidor no guarda un registro de sesiones por usuario | 30 inicios de sesión simultáneos de `analista00`: los 30 respondieron `/me` con 200, y la sesión original siguió válida. Código en `sesion_web.py:127-159` y `dashboard.py:396-410` |
| ¿Cerrar una sesión cierra las otras? | No (confirmado antes con CP-UI-10) | Prueba de interfaz |
| ¿Hace falta crear usuarios? | No para el plan: alcanzan los 3 usuarios con la contraseña de la malla | `malla_postman.py:32`, `levantar_malla.py.txt` |
| ¿Qué usuario para cada escenario? | `analista00` para lecturas y decisiones (rol `analyst`); `auditor00` para `/api/v1/audit/verify` (el analista recibe 403); `observador00` para lecturas de solo lectura | Comprobado con inicio de sesión real |
| Costo de iniciar sesión | 130 ms con un solo cliente. 30 inicios simultáneos tardaron 1,3 s en total, con 1,1 s por login: Argon2id se serializa en el proceso único de la malla | Medido el 23-11 |
| ¿50 clientes simultáneos (RQ-SEC-28, CONF-06)? | Pueden compartir `analista00` o usar usuarios propios. La malla se crea con `clientes=1` (un solo `analista00`); para usuarios `analista00…analista49` habría que arrancarla con ese parámetro (`MallaFija.__init__` pasa `clientes=1`) | `levantar_malla.py.txt:57`, `medicion_iso25023.py:381-420` |
| Usuario para el bloqueo y los impostores | `victima00x00` es el usuario descartable que usan CP-SERV-06 y CP-UI-05 para provocar el bloqueo; la malla solo crea `analista00`, `auditor00` y `observador00`, así que se usa solo con contraseñas erróneas | `NeuralDefender-malla.postman_environment.json` |

Recomendación de diseño que sale de esto: iniciar sesión **una vez por usuario virtual en `setup()`** (como hace el k6 existente con una sola sesión compartida) y reservar un escenario aparte, a tasa baja, para medir el login. Es válido repartir una sola sesión entre todos los usuarios virtuales porque no hay límite por usuario, pero entonces `session_id` y el atribuido a quien decide es siempre el mismo, lo que **no sirve para RQ-SEC-27** si se quiere atribuir cada decisión a un cliente distinto.

## 6. k6 y el entorno de ejecución

| Elemento | Estado |
|---|---|
| `k6 version` | **No instalado**: `command not found` |
| Docker | 26.1.5, funcionando |
| Imagen `grafana/k6` | No está descargada. `docker manifest inspect grafana/k6:1.3.0` responde: el registro es accesible. El script del proyecto fija esa versión (variable `K6_IMAGEN` de `scripts/pruebas_de_performance.sh`) |
| Cómo alcanza la malla | `docker run --network host`: el contenedor comparte el loopback del equipo y ve `127.0.0.1:18080` (así lo usa el script del proyecto con el puerto 5000) |
| Reporte | `K6_WEB_DASHBOARD=true` con exportación HTML y `--summary-export` a JSON (ya está en el script) |

Lo que ya existe:

| Archivo | Contenido | Brecha respecto del plan |
|---|---|---|
| `tests/performance/neuraldefender.js` | Perfiles `humo` (1 VU, 30 s), `carga` (20 VUs, 0,5 + 3 + 0,5 min), `estres` (20, 50, 100, 150 VUs, 1 min cada uno), `pico` (5, 100, 5 VUs) y `login` (1 por segundo). Umbrales: fallos < 1 %, lecturas p95 < 500 ms, `me` y `healthz` < 300 ms, verificación de la cadena < 2 s. Una sola sesión, creada en `setup()` | Usa por defecto `127.0.0.1:5000` (stack Docker); para la malla hay que pasar `BASE_URL` y las credenciales. **No registra decisiones** (RNF-RD-04). No tiene escenario de 50 clientes con login (CONF-06, RQ-SEC-28), ni de impostores, ni de conteo de registros (RQ-SEC-27) |
| `scripts/pruebas_de_performance.sh` | Lanza k6 en contenedor y guarda `reportes/performance/<fecha>-<perfil>.{html,json}` | Apunta a `:5000` y crea un usuario `k6-carga` con `docker compose exec`, que no existe en la malla; hay que pasar `K6_USUARIO` y `K6_CLAVE` (por ejemplo `auditor00` y la contraseña de la malla). Guarda fuera de `entregables/4-rendimiento/` |
| `pruebas_de_performance.md` | Citado por el script y por `CLAUDE.md` | **No existe** en el repositorio |
| `reportes/performance/` | 10 corridas del 12 y 19-11-2026 contra el stack en contenedores | Sirven de referencia (tabla siguiente), no de resultado para la malla |

Resultados previos contra el stack Docker (`:5000`), que usan el mismo script (cantidad de incidentes no registrada):

| Perfil | Fecha | Peticiones | Fallidas | p95 `incidentes` | p95 `decisiones` | p95 `memoria` |
|---|---|---|---|---|---|---|
| carga (20 VUs) | 12-11 | 12.594 | 0 % | 20,6 ms | 13,8 ms | 16,9 ms |
| carga (20 VUs) | 19-11 (dos corridas) | 12.584 y 12.605 | 0 % | 17,0 a 18,2 ms | 10,8 a 11,2 ms | 13,3 a 13,8 ms |
| estrés (hasta 150 VUs) | 12-11 y 19-11 | 42.835 y 45.083 | 0 % | 351,1 y 304,6 ms | 333,8 y 286,3 ms | 340,1 y 294,5 ms |
| pico (100 VUs) | 12-11 (dos) y 19-11 | 16.194; 16.072; 18.771 | 0 a 0,01 % | 156,7 a 250,8 ms | 137,2 a 226,8 ms | 147,5 a 237,7 ms |

## 7. Decisiones y puntos abiertos para el plan

| # | Punto | Por qué importa |
|---|---|---|
| 1 | Cómo sembrar 100 incidentes en la malla | RNF-RD-01 y RNF-RD-06 lo exigen y hoy la malla trae 3 |
| 2 | Cómo activar el ciclo automático cada 2 min en la malla | RNF-RD-05 y RNF-CONF-07 lo exigen; la malla lo desactiva y su collector lee el Elasticsearch real |
| 3 | Escenario de decisiones (POST) con 20 clientes | El k6 existente no lo cubre y RNF-RD-04 exige el p95 < 500 ms. Hay que reiniciar la malla después, porque llena el registro de auditoría de la malla |
| 4 | Una sesión compartida o una sesión por usuario virtual | Una sola sesión simplifica; una por usuario permite atribuir cada decisión a un cliente (RQ-SEC-27) |
| 5 | Ampliar la malla a más de un usuario analista | Solo si se quieren 50 identidades distintas |
| 6 | Instalar k6 o usar `grafana/k6:1.3.0` en Docker | Hace falta descargar la imagen (red y espacio) |
| 7 | Límites distintos entre la malla y producción | Un proceso con GIL contra gunicorn con 8 hilos: los números de la malla no reemplazan a los del stack real |
