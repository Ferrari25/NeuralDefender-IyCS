# NeuralDefender - Inventario de servicios (API) para el plan de pruebas con Postman

Fecha: 22 de noviembre de 2026. Commit base: `43fd91c`, con cambios sin confirmar en el árbol de trabajo (los de los entregables 1.x y 2).

Este documento es el inventario previo al plan. No contiene casos de prueba escritos. Todo sale del código fuente y de corridas reales hechas para este documento: la corrida de Newman sobre la colección existente, 9 archivos de pytest, 211 sondeos con `curl` a los servicios internos y 87 sondeos con `curl` al gateway. Los archivos crudos están en `entregables/2-servicios/evidencia/` (sección 7).

## Resumen

| Concepto | Resultado |
|---|---|
| Servicios con API HTTP | 8: gateway (puerto 5000) y 7 internos (puerto 8000) |
| Endpoints en total | **56**: 20 del gateway, 29 funcionales de los servicios internos y 7 de salud |
| Endpoints core / secundarios | **41 core** y 15 secundarios |
| El 80 % | **45 de 56** (44,8 redondeado hacia arriba). Equivale a los 41 core más 4 secundarios |
| ERS en el repositorio | **No existe.** Los identificadores aparecen en comentarios de pruebas y scripts, sin definición |
| Colección de Postman existente | 113 pedidos, 392 aserciones, **0 fallos** (con Elasticsearch arriba). Cubre 52 de los 56 endpoints |
| Pruebas de pytest que llaman a la API | 9 archivos (8 de integración y `test_no_autonomy.py`), 336 pruebas, todas pasan |
| Contrato de errores (298 sondeos con curl) | **4 respuestas 500** (defectos), las 4 en servicios internos. El gateway no devolvió ningún 5xx |
| No se puede probar localmente | TLS de la cookie de sesión, el LLM en la nube sin clave válida, y cualquier escritura sobre la auditoría real (es inmutable) |

## 1. Endpoints

### 1.0 Convenciones comunes

**Servicios internos** (auth, audit, collector, classifier, analyst, pipeline, knowledge). Definidas en `libs/siem_servicios.py`.

| Aspecto | Comportamiento | Línea |
|---|---|---|
| Puerto | 8000. No se publica al host: solo se llega desde la red de Docker `elastic-siem-project_ia-net` (URL `http://<servicio>:8000`) | 42 |
| Autenticación | Cabecera `X-Internal-Token` con el valor de `SIEM_INTERNAL_TOKEN` (mínimo 32 caracteres, sin valor por defecto). Comparación en tiempo constante | 163-172 |
| Excepción | `GET /v1/healthz` no pide token | 47-49, 178-180 |
| Token ausente o falso | `401 {"error":"token interno ausente o inválido"}`. Se comprueba **antes** de resolver la ruta: una ruta inexistente sin token da 401, no 404 | 163-172 |
| Errores de Flask | Siempre JSON: `{"error": "<descripción>", "status": <código>}` para 404, 405, 413 | 174-176 |
| Cuerpo máximo | 16 MB, superado devuelve 413 | 53, 161 |
| Cuerpo JSON | `cuerpo_json()` devuelve nada si el cuerpo no es un objeto JSON: arreglo, texto, vacío o malformado dan 400 `se esperaba un cuerpo JSON` | 185-188 |

**Gateway** (`services/gateway/dashboard.py`, `sesion_web.py`).

| Aspecto | Comportamiento | Línea |
|---|---|---|
| Puerto | 5000, publicado solo en `127.0.0.1:5000` | docker-compose.yml |
| Autenticación | Sesión por cookie `siem_session` (HttpOnly, SameSite=Lax) obtenida con `POST /api/v1/login` | dashboard.py:115-126 |
| CSRF | Todo `POST` salvo el login exige el encabezado `X-CSRFToken` con el valor `csrf_token` que devuelve el login o `/api/v1/me`. **Se comprueba antes que la sesión**: un POST sin sesión ni token da 403, no 401 | dashboard.py:135, 155-162 |
| Rutas públicas | `healthz`, `api_login`, `vista_login` y los estáticos | dashboard.py:79 |
| Vigencia de sesión | 30 minutos de inactividad o 8 horas absolutas. Vencida: `401 {"error":"<motivo>","expirada":true}` | sesion_web.py:36-37, dashboard.py:167-187 |
| Usuario en cada petición | Cada petición autenticada consulta `GET /v1/users/<usuario>` al servicio auth: una baja tiene efecto inmediato. Si auth no responde, 503 | sesion_web.py:102-122 |
| Errores en `/api/` | JSON `{"error":"...","status":N}`. Fuera de `/api/` (por ejemplo `/no-existe`) devuelve HTML de Werkzeug | dashboard.py:192-201 |
| Cuerpo máximo | 64 KB, superado devuelve 413 | dashboard.py:70 |
| Servicio interno caído | `503 {"error":"...","status":503}` | dashboard.py:204-211 |

**Roles y permisos** (definidos en `services/auth/siem_auth.py:87-92`):

| Rol | Permisos |
|---|---|
| `viewer` | `ver_incidentes`, `ver_auditoria` |
| `analyst` | `ver_incidentes`, `ver_auditoria`, `decidir` |
| `auditor` | `ver_incidentes`, `ver_auditoria`, `verificar_cadena` |

Ningún rol puede ejecutar acciones: `puede_ejecutar_acciones` es siempre `false`. Sin el permiso: `403 {"error":"el rol 'viewer' no tiene permiso para 'decidir'","permiso_requerido":"decidir"}`.

**Respuestas comunes del gateway**, válidas para todos los endpoints `/api/` y que no se repiten abajo:

| Código | Cuándo | Ejemplo real |
|---|---|---|
| 401 | Sin sesión, cookie inválida o sesión vencida | `{"error":"se requiere autenticación"}` |
| 403 | Falta el permiso | `{"error":"el rol 'analyst' no tiene permiso para 'verificar_cadena'","permiso_requerido":"verificar_cadena"}` |
| 403 | POST sin token CSRF o con token inválido | `{"error":"token CSRF inválido o ausente: The CSRF token is missing."}` |
| 404 | Ruta inexistente | `{"error":"The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.","status":404}` |
| 405 | Método no permitido | `{"error":"The method is not allowed for the requested URL.","status":405}` |
| 413 | Cuerpo de más de 64 KB | `{"error":"The data value transmitted exceeds the capacity limit.","status":413}` |
| 503 | Un servicio interno no responde o responde algo inesperado | `{"error":"el servicio de autenticación no está disponible","status":503}` |

### 1.1 Índice de los 56 endpoints

| ID | Método y ruta | Servicio | Definido en | Autenticación | Clase | Área |
|---|---|---|---|---|---|---|
| G01 | GET `/login` | gateway | dashboard.py:348 | Pública | Secundario | Vista HTML |
| G02 | POST `/api/v1/login` | gateway | dashboard.py:356 | Pública (sin CSRF) | Core | Autenticación |
| G03 | POST `/api/v1/logout` | gateway | dashboard.py:417 | Sesión + CSRF | Core | Autenticación |
| G04 | GET `/api/v1/me` | gateway | dashboard.py:455 | Sesión | Core | Autenticación |
| G05 | GET `/` | gateway | dashboard.py:471 | Sesión (redirige) | Secundario | Vista HTML |
| G06 | GET `/api/v1/healthz` | gateway | dashboard.py:477 | Pública | Secundario | Salud |
| G07 | GET `/api/v1/incidents` | gateway | dashboard.py:493 | Sesión + `ver_incidentes` | Core | Alertas |
| G08 | GET `/api/v1/incidents/<incident_id>` | gateway | dashboard.py:502 | Sesión + `ver_incidentes` | Core | Alertas |
| G09 | POST `/api/v1/decision` | gateway | dashboard.py:514 | Sesión + CSRF + `decidir` | Core | Auditoría |
| G10 | GET `/api/v1/decisions` | gateway | dashboard.py:647 | Sesión + `ver_auditoria` | Core | Auditoría |
| G11 | GET `/api/v1/audit/verify` | gateway | dashboard.py:656 | Sesión + `verificar_cadena` | Core | Auditoría |
| G12 | GET `/api/v1/memoria` | gateway | dashboard.py:729 | Sesión + `ver_incidentes` | Core | Análisis |
| G13 | POST `/api/v1/memoria/documentos` | gateway | dashboard.py:740 | Sesión + CSRF + `decidir` | Core | Análisis |
| G14 | POST `/api/v1/memoria/lecciones` | gateway | dashboard.py:750 | Sesión + CSRF + `decidir` | Core | Análisis |
| G15 | POST `/api/v1/memoria/lecciones/<leccion_id>/revision` | gateway | dashboard.py:760 | Sesión + CSRF + `decidir` | Core | Análisis |
| G16 | GET `/api/v1/reportes` | gateway | dashboard.py:774 | Sesión + `ver_auditoria` | Core | Auditoría |
| G17 | GET `/api/incidents` (alias de G07) | gateway | dashboard.py:812 | Igual que G07 | Secundario | Compatibilidad |
| G18 | POST `/api/decision` (alias de G09) | gateway | dashboard.py:813 | Igual que G09 | Secundario | Compatibilidad |
| G19 | GET `/api/decisions` (alias de G10) | gateway | dashboard.py:814 | Igual que G10 | Secundario | Compatibilidad |
| G20 | GET `/static/<path:filename>` | gateway | dashboard.py:113 (carpeta `static/`) | Pública | Secundario | Estáticos |
| A01 | POST `/v1/authenticate` | auth | auth_service.py:29 | Token interno | Core | Autenticación |
| A02 | GET `/v1/users/<username>` | auth | auth_service.py:53 | Token interno | Core | Autenticación |
| A03 | GET `/v1/users-summary` | auth | auth_service.py:62 | Token interno | Secundario | Resumen |
| U01 | POST `/v1/decisions` | audit | audit_service.py:143 | Token interno | Core | Auditoría |
| U02 | GET `/v1/decisions` | audit | audit_service.py:155 | Token interno | Core | Auditoría |
| U03 | GET `/v1/decisions/verify` | audit | audit_service.py:162 | Token interno | Core | Auditoría |
| U04 | POST `/v1/analysis-history` | audit | audit_service.py:167 | Token interno | Core | Auditoría |
| U05 | GET `/v1/analysis-history/verify` | audit | audit_service.py:181 | Token interno | Core | Auditoría |
| U06 | POST `/v1/activity` | audit | audit_service.py:186 | Token interno | Core | Auditoría |
| U07 | GET `/v1/activity` | audit | audit_service.py:198 | Token interno | Core | Auditoría |
| U08 | GET `/v1/activity/verify` | audit | audit_service.py:203 | Token interno | Core | Auditoría |
| U09 | POST `/v1/access` | audit | audit_service.py:225 | Token interno | Core | Auditoría |
| U10 | GET `/v1/access` | audit | audit_service.py:237 | Token interno | Core | Auditoría |
| U11 | GET `/v1/access/verify` | audit | audit_service.py:242 | Token interno | Core | Auditoría |
| U12 | GET `/v1/reports` | audit | audit_service.py:247 | Token interno | Core | Auditoría |
| C01 | POST `/v1/snapshots` | collector | collector_service.py:27 | Token interno | Core | Ingesta |
| C02 | GET `/v1/snapshots/latest` | collector | collector_service.py:39 | Token interno | Core | Ingesta |
| K01 | POST `/v1/classify` | classifier | classifier_service.py:33 | Token interno | Core | Clasificación |
| N01 | POST `/v1/analyze` | analyst | analyst_service.py:75 | Token interno | Core | Análisis |
| P01 | POST `/v1/cycles` | pipeline | pipeline_service.py:33 | Token interno | Core | Análisis |
| P02 | GET `/v1/incidents` | pipeline | pipeline_service.py:43 | Token interno | Core | Alertas |
| P03 | GET `/v1/incidents/<incident_id>` | pipeline | pipeline_service.py:50 | Token interno | Core | Alertas |
| M01 | GET `/v1/documents` | knowledge | knowledge_service.py:48 | Token interno | Core | Análisis |
| M02 | POST `/v1/documents` | knowledge | knowledge_service.py:53 | Token interno | Core | Análisis |
| M03 | POST `/v1/cases` | knowledge | knowledge_service.py:61 | Token interno | Core | Análisis |
| M04 | GET `/v1/lessons` | knowledge | knowledge_service.py:67 | Token interno | Core | Análisis |
| M05 | POST `/v1/lessons` | knowledge | knowledge_service.py:72 | Token interno | Core | Análisis |
| M06 | POST `/v1/lessons/<leccion_id>/review` | knowledge | knowledge_service.py:80 | Token interno | Core | Análisis |
| M07 | POST `/v1/context` | knowledge | knowledge_service.py:90 | Token interno | Core | Análisis |
| H01 a H07 | GET `/v1/healthz` (uno por servicio interno) | auth, audit, collector, classifier, analyst, pipeline, knowledge | libs/siem_servicios.py:178 | Pública | Secundario | Salud |

Notas sobre este índice:
- Cada servicio interno define sus rutas en `services/<servicio>/<servicio>_service.py`. El gateway las define en `services/gateway/dashboard.py`.
- `G20` no está escrito como ruta: Flask la crea sola porque `static_folder` está definido en `dashboard.py:113`.
- Los 3 alias (`G17` a `G19`) son el mismo código que `G07`, `G09` y `G10` con otro nombre. Existen para scripts viejos.
- Hay 7 sondas de salud internas (una por servicio) y 1 del gateway (`G06`). Las 7 internas son la misma función, definida una vez en `libs/siem_servicios.py:178`.
- Cuenta por servicio: gateway 20, auth 3, audit 12, collector 2, classifier 1, analyst 1, pipeline 3, knowledge 7 y salud interna 7. Total 56. Se contó con una búsqueda de los decoradores `@app.get`, `@app.post` y `@app.route` en el código.

### 1.2 Gateway

#### G01 - GET `/login` (dashboard.py:348)

| Aspecto | Detalle |
|---|---|
| Entrada | Ninguna |
| Respuestas | `200` HTML de la pantalla de login. `302` a `/` si ya hay sesión |
| Validaciones | Ninguna |
| Depende de | Nada |

#### G02 - POST `/api/v1/login` (dashboard.py:356)

| Aspecto | Detalle |
|---|---|
| Entrada | Cuerpo JSON `{"username": "<texto>", "password": "<texto>"}`. Ejemplo: `{"username":"api-analista","password":"<contraseña>"}` |
| Validaciones | El cuerpo debe ser un objeto JSON. Si `username` o `password` no son texto, o están vacíos, se responde como credenciales incorrectas. Después de 5 fallos seguidos del mismo usuario desde la misma IP, bloqueo con espera creciente (60 s, 120 s, 240 s, hasta 15 minutos). La IP sale de la conexión: `X-Forwarded-For` se ignora |
| Depende de | Servicio auth (`POST /v1/authenticate`) y servicio audit (`POST /v1/access`, registra el acceso antes de abrir la sesión) |

| Código | Cuándo | Ejemplo real |
|---|---|---|
| 200 | Credenciales correctas | `{"csrf_token":"<token>","expira_como_maximo_en_horas":8,"expira_por_inactividad_en_minutos":30,"ok":true,"permisos":["decidir","ver_auditoria","ver_incidentes"],"rol":"analyst","usuario":"api-analista"}` |
| 400 | Cuerpo que no es un objeto JSON | `{"error":"se esperaba un cuerpo JSON"}` |
| 401 | Usuario inexistente, dado de baja o contraseña incorrecta. El mensaje es siempre el mismo | `{"error":"usuario o contraseña incorrectos"}` |
| 413 | Más de 64 KB | `{"error":"The data value transmitted exceeds the capacity limit.","status":413}` |
| 429 | Demasiados intentos fallidos | `{"error":"demasiados intentos fallidos; reintentá en 60 s","reintentar_en":60}` |
| 503 | Auth o audit no responden | `{"error":"el servicio de autenticación no está disponible"}` |

#### G03 - POST `/api/v1/logout` (dashboard.py:417)

| Aspecto | Detalle |
|---|---|
| Entrada | Sin cuerpo. Encabezado `X-CSRFToken` |
| Validaciones | Exige sesión y CSRF. Registra el cierre en la auditoría; si la auditoría falla, igual cierra la sesión |
| Respuestas | `204` sin cuerpo. `403` sin CSRF (probado). `401` si hay CSRF pero no hay sesión, según el código del manejador (no se probó) |
| Depende de | Servicio audit (`POST /v1/access`), pero un fallo no impide el cierre |

#### G04 - GET `/api/v1/me` (dashboard.py:455)

| Aspecto | Detalle |
|---|---|
| Entrada | Ninguna |
| Respuestas | `200 {"csrf_token":"<token>","permisos":["decidir","ver_auditoria","ver_incidentes"],"puede_ejecutar_acciones":false,"rol":"analyst","usuario":"api-analista"}`. `401` sin sesión |
| Depende de | Servicio auth (la carga del usuario) |

#### G05 - GET `/` (dashboard.py:471)

| Aspecto | Detalle |
|---|---|
| Respuestas | `200` HTML del panel con sesión. `302` a `/login` sin sesión |
| Depende de | Nada (los datos los pide el navegador a la API) |

#### G06 - GET `/api/v1/healthz` (dashboard.py:477)

| Aspecto | Detalle |
|---|---|
| Entrada | Ninguna. Pública |
| Respuestas | Siempre `200 {"incidents_file":true,"status":"ok"}`. `incidents_file` vale `false` si el pipeline no tiene reporte o no respondió |
| Depende de | Servicio pipeline (`GET /v1/incidents`), pero responde aunque esté caído |

#### G07 - GET `/api/v1/incidents` (dashboard.py:493)

| Aspecto | Detalle |
|---|---|
| Entrada | Ninguna |
| Respuestas | `200` con el reporte de incidentes y el estado de cada acción (`pending`, `approved` o `dismissed`). Campos de primer nivel: `analyst_mode`, `analyzed_at`, `generated_at`, `incident_count`, `incidents`, `source`. Campos de cada incidente: `incident_id`, `classification`, `severity_siem`, `source_ip`, `attacker_ips`, `recommended_actions`, `analysis`, `mitre`, `risk_score`, entre otros. Si el pipeline aún no tiene reporte: `200 {"incidents":[],"analyst_mode":null,"missing":true}`. Encabezado `Cache-Control: no-store` |
| Depende de | Servicios pipeline y audit. **El campo `analysis` es texto generado por el LLM** (o por el análisis de respaldo, indicado en `analyst_mode`), pero este endpoint no llama al LLM |

#### G08 - GET `/api/v1/incidents/<incident_id>` (dashboard.py:502)

| Aspecto | Detalle |
|---|---|
| Entrada | Ruta: `incident_id`, por ejemplo `INC-SCAN-203.0.113.10-5663da03` |
| Respuestas | `200` con el incidente. `404 {"error":"incidente 'INC-NO-EXISTE' no encontrado"}` |
| Depende de | Servicios pipeline y audit |

#### G09 - POST `/api/v1/decision` (dashboard.py:514)

| Aspecto | Detalle |
|---|---|
| Entrada | Cuerpo JSON: `{"incident_id":"INC-SCAN-172.18.0.7-8e58721f","action_id":"INC-SCAN-172.18.0.7-8e58721f-3af475","decision":"approved","note":"Prueba de servicio"}` |
| Validaciones | `decision` solo `approved` o `dismissed`. `incident_id` y `action_id` obligatorios y de tipo texto no vacío. `note` opcional, de tipo texto y hasta 500 caracteres (se recorta). **La acción tiene que existir** en ese incidente: una decisión sobre una acción inventada se rechaza para no contaminar el registro. La identidad del analista sale de la sesión, no del cuerpo |
| Depende de | Servicios pipeline (comprueba la acción), audit (`POST /v1/decisions`, escritura inmutable) y knowledge (`POST /v1/cases`, no condiciona el resultado) |

| Código | Cuándo | Ejemplo real |
|---|---|---|
| 201 | Decisión registrada | `{"lecciones_propuestas":0,"memoria":"registrada","ok":true,"record":{"accion":"Bloquear la IP que realiza el escaneo en el firewall","action_id":"INC-SCAN-172.18.0.7-8e58721f-3af475","analyst":"analista00","analyst_rol":"analyst","attack_type":"port_scan","decision":"approved","incident_id":"INC-SCAN-172.18.0.7-8e58721f","note":"Prueba de servicio","prev_hash":"<hash>","ts":"<fecha>", ...}}`. `memoria` vale `no_disponible` si knowledge no respondió |
| 400 | Cuerpo no JSON | `{"error":"se esperaba un cuerpo JSON"}` |
| 400 | `decision` inválida | `{"error":"decision inválida (approved\|dismissed)"}` |
| 400 | Faltan o no son texto los ids | `{"error":"faltan incident_id / action_id"}` |
| 400 | `note` no es texto | `{"error":"note debe ser texto"}` |
| 400 | `note` de más de 500 caracteres | `{"error":"note supera 500 caracteres (501)"}` |
| 404 | La acción no existe en ese incidente | `{"error":"no existe la acción 'ACCION-INVENTADA' en el incidente 'INC-SCAN-172.18.0.7-8e58721f'"}` |
| 503 | Audit rechazó o no respondió | `{"error":"el servicio audit rechazó la decisión (HTTP 400): ...","status":503}` |

#### G10 - GET `/api/v1/decisions` (dashboard.py:647)

| Aspecto | Detalle |
|---|---|
| Respuestas | `200` con la lista completa de decisiones, por ejemplo `[{"accion":"Habilitar rate-limiting / fail2ban en el servicio SSH","action_id":"INC-AUTH-desconocida-7c808c94-...","analyst":"analista","decision":"approved", ...}]`. `Cache-Control: no-store` |
| Depende de | Servicio audit |

#### G11 - GET `/api/v1/audit/verify` (dashboard.py:656)

| Aspecto | Detalle |
|---|---|
| Entrada | Ninguna. Solo el rol `auditor` tiene el permiso |
| Respuestas | `200 {"chain_ok":true,"estado":"ok","first_broken":null,"reason":null,"records":19}`. `403` para `analyst` y `viewer` |
| Depende de | Servicio audit (`GET /v1/decisions/verify`) |

#### G12 - GET `/api/v1/memoria` (dashboard.py:729)

| Aspecto | Detalle |
|---|---|
| Respuestas | `200 {"documentos":[...],"lecciones":[...]}`. `Cache-Control: no-store` |
| Depende de | Servicio knowledge |

#### G13 - POST `/api/v1/memoria/documentos` (dashboard.py:740)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"titulo":"Procedimiento SSH","contenido":"Bloquear tras 20 fallos."}`. `subido_por` lo pone el gateway con el usuario de la sesión |
| Validaciones | `titulo` texto obligatorio de hasta 120 caracteres. `contenido` texto obligatorio de hasta 32 KB. Máximo 50 documentos. Cuerpo JSON obligatorio |
| Respuestas | `201 {"documento":{"caracteres":50,"doc_id":"DOC-a797df3843","subido_por":"analista00","titulo":"Procedimiento SSH","ts":"<fecha>"},"ok":true}`. `400 {"error":"'titulo' debe ser texto"}` o `{"error":"se esperaba un cuerpo JSON","status":400}`. `403` sin `decidir` |
| Depende de | Servicio knowledge (guarda) y servicio audit (`POST /v1/activity`, registra el evento) |

#### G14 - POST `/api/v1/memoria/lecciones` (dashboard.py:750)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"texto":"Escaneos desde el monitoreo interno son legítimos.","attack_type":"port_scan","ip":"10.0.0.9"}` |
| Validaciones | `texto` obligatorio, hasta 400 caracteres. `attack_type` opcional, solo `ssh_brute_force`, `port_scan`, `credential_harvesting` o `suspicious_auth`. `ip` opcional, hasta 64 caracteres. La lección nace como `propuesta` |
| Respuestas | `201 {"leccion":{"estado":"propuesta","leccion_id":"LEC-26e063284e",...},"ok":true}`. `400 {"error":"'texto' debe ser texto"}` o `{"error":"attack_type desconocido: 'no-existe'"}` |
| Depende de | Servicios knowledge y audit |

#### G15 - POST `/api/v1/memoria/lecciones/<leccion_id>/revision` (dashboard.py:760)

| Aspecto | Detalle |
|---|---|
| Entrada | Ruta: `LEC-` más 10 caracteres hexadecimales. Cuerpo: `{"decision":"aprobar"}` o `{"decision":"rechazar"}` |
| Validaciones | El identificador debe cumplir `^LEC-[0-9a-f]{10}$`. Una lección ya revisada no se reabre |
| Respuestas | `200 {"leccion":{"estado":"aprobada",...},"ok":true}`. `400 {"error":"identificador de lección inválido"}`. `400 {"error":"decision inválida (aprobar\|rechazar)"}`. `404 {"error":"no existe la lección 'LEC-0000000000'"}`. Un identificador con barra codificada (`..%2Fetc`) no llega a la vista y da `404` genérico |
| Depende de | Servicios knowledge y audit |

#### G16 - GET `/api/v1/reportes` (dashboard.py:774)

| Aspecto | Detalle |
|---|---|
| Entrada | Consulta: `desde` y `hasta` (AAAA-MM-DD, opcionales) y `formato` (`json` por defecto, o `csv`) |
| Validaciones | `formato` solo `json` o `csv`. Las fechas deben existir en el calendario. `desde` no puede ser posterior a `hasta` |
| Respuestas | `200` JSON con `accesos`, `actividad`, `decisiones`, `generado_en`, `integridad`, `periodo` y `resumen`. Con `formato=csv`: `200` con `Content-Type: text/csv` y `Content-Disposition: attachment; filename="reporte-neuraldefender_<desde>_<hasta>.csv"`. `400 {"error":"formato inválido (json\|csv)"}`, `{"error":"'desde' debe ser una fecha AAAA-MM-DD"}`, `{"error":"'desde' es posterior a 'hasta'"}` |
| Depende de | Servicio audit (`GET /v1/reports`) |

#### G17, G18 y G19 - alias sin versionar (dashboard.py:812-814)

Son el mismo código y las mismas respuestas que `G07` (`GET /api/incidents`), `G09` (`POST /api/decision`) y `G10` (`GET /api/decisions`).

#### G20 - GET `/static/<path:filename>` (Flask, `static_folder` en dashboard.py:113)

Sirve `app.js`, `login.js` y las hojas de estilo del panel. Pública. `200` con el archivo o `404` si no existe. No tiene validaciones propias.

### 1.3 Servicio auth

#### A01 - POST `/v1/authenticate` (auth_service.py:29)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"username":"analista00","password":"<contraseña>","client_ip":"127.0.0.9"}` |
| Validaciones | Cuerpo objeto JSON. `client_ip` debe ser texto no vacío; si no, usa `desconocida`. Mismo control de 5 intentos que `G02`. Argon2id para verificar |
| Respuestas | `200 {"permisos":["decidir","ver_auditoria","ver_incidentes"],"rol":"analyst","usuario":"analista00"}`. `400 {"error":"se esperaba un cuerpo JSON"}`. `401 {"error":"usuario o contraseña incorrectos"}`. `429 {"error":"demasiados intentos fallidos; reintentá en 60 s","reintentar_en":60}` |
| Depende de | Su propio almacén `data/auth/users.json` y el control de intentos en memoria |

#### A02 - GET `/v1/users/<username>` (auth_service.py:53)

| Aspecto | Detalle |
|---|---|
| Entrada | Ruta: `username` |
| Respuestas | `200 {"activo":true,"permisos":["decidir","ver_auditoria","ver_incidentes"],"rol":"analyst","username":"analista00"}` (nunca el hash). `404 {"error":"usuario inexistente"}` |
| Depende de | Su almacén de usuarios, que se relee en cada consulta |

#### A03 - GET `/v1/users-summary` (auth_service.py:62)

| Aspecto | Detalle |
|---|---|
| Respuestas | `200 {"activos_por_rol":{"analyst":1,"auditor":1,"viewer":13},"total":16}`. **`500 {"error":"<detalle>"}` por diseño** (línea 66-67) si el archivo de usuarios está corrupto; ese caso no se pudo provocar sin dañar los datos reales |
| Depende de | Su almacén de usuarios |

### 1.4 Servicio audit

Todas las escrituras agregan una línea encadenada por hash a un archivo append-only. El servicio no tiene ningún endpoint de modificación ni de borrado: `DELETE` da 405. El sello de tiempo `ts` lo pone el servicio, no quien llama.

#### U01 - POST `/v1/decisions` (audit_service.py:143)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"incident_id":"INC-SCAN-172.18.0.7-8e58721f","action_id":"INC-SCAN-172.18.0.7-8e58721f-3af475","decision":"approved","analyst":"postman"}` |
| Validaciones | Lista blanca de campos: `incident_id`, `action_id`, `decision`, `analyst`, `analyst_rol`, `session_id`, `user_agent`, `note`, `source_ip`, `attacker_ips`, `accion`, `attack_type`, `severidad`, `falso_positivo`, `detection_source`. Un campo desconocido se rechaza. Obligatorios y de tipo texto no vacío: `incident_id`, `action_id`, `decision`, `analyst`. `decision` solo `approved` o `dismissed`. `note` texto de hasta 500. `attacker_ips` lista de textos. Los campos de contexto, texto de hasta 300 |
| Respuestas | `201 {"ok":true,"record":{"action_id":"...","analyst":"postman","decision":"approved","incident_id":"...","prev_hash":"<hash>","ts":"<fecha>"}}`. `400 {"error":"campos no permitidos: comando"}`, `{"error":"falta o es inválido 'analyst'"}`, `{"error":"decision inválida (approved\|dismissed)"}`, `{"error":"note supera 500 caracteres (501)"}`, `{"error":"attacker_ips debe ser una lista de textos"}` |
| Depende de | Su archivo `data/audit/decisions.jsonl` |

#### U02 - GET `/v1/decisions` (audit_service.py:155)

`200` con una lista de registros. Tolera líneas corruptas: marca ese registro en lugar de fallar. No depende de nadie más.

#### U03 - GET `/v1/decisions/verify` (audit_service.py:162)

`200 {"chain_ok":true,"estado":"ok","first_broken":null,"reason":null,"records":19}`. Si la cadena está rota, `chain_ok` es `false` y `first_broken` indica el registro.

#### U04 - POST `/v1/analysis-history` (audit_service.py:167)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"analyst_mode":"fallback","incident_count":1,"incident_ids":["INC-POSTMAN"]}` |
| Validaciones | Campos permitidos: `analyst_mode`, `incident_count`, `incident_ids`. `analyst_mode` obligatorio y de tipo texto |
| Respuestas | `201 {"ok":true,"record":{...,"prev_hash":"<hash>","ts":"<fecha>"}}`. `400 {"error":"campos no permitidos: extra"}`, `{"error":"falta 'analyst_mode'"}` |

#### U05 - GET `/v1/analysis-history/verify` (audit_service.py:181)

`200` con el estado de la cadena de las corridas, mismo formato que `U03`. No existe `GET /v1/analysis-history` (solo se agrega y se verifica).

#### U06 - POST `/v1/activity` (audit_service.py:186)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"evento":"documento_cargado","actor":"postman","detalle":"prueba"}` |
| Validaciones | Campos permitidos: `evento`, `actor`, `actor_rol`, `leccion_id`, `doc_id`, `detalle`, `attack_type`, `ip`. `evento` solo `documento_cargado`, `leccion_propuesta`, `leccion_aprobada` o `leccion_rechazada`. `actor` obligatorio. El resto, texto de hasta 500 |
| Respuestas | `201 {"ok":true,"record":{...}}`. `400 {"error":"evento inválido (documento_cargado\|leccion_propuesta\|leccion_aprobada\|leccion_rechazada)"}`, `{"error":"falta o es inválido 'actor'"}` |

#### U07 y U08 - GET `/v1/activity` y `/v1/activity/verify` (audit_service.py:198, 203)

`200` con la lista de eventos de memoria y con el estado de su cadena, respectivamente.

#### U09 - POST `/v1/access` (audit_service.py:225)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"evento":"login_exitoso","usuario":"postman","ip":"127.0.0.1"}` |
| Validaciones | Campos permitidos: `evento`, `usuario`, `rol`, `ip`, `session_id`, `user_agent`. `evento` solo `login_exitoso`, `login_fallido`, `login_bloqueado` o `logout`. `usuario` obligatorio. Los demás: texto imprimible de hasta 200 caracteres (un carácter de control se rechaza) |
| Respuestas | `201 {"ok":true,"record":{...}}`. `400 {"error":"evento inválido (login_exitoso\|login_fallido\|login_bloqueado\|logout)"}`, `{"error":"'usuario' debe ser texto imprimible de hasta 200 caracteres"}` |

#### U10 y U11 - GET `/v1/access` y `/v1/access/verify` (audit_service.py:237, 242)

`200` con la lista de accesos y con el estado de su cadena.

#### U12 - GET `/v1/reports` (audit_service.py:247)

| Aspecto | Detalle |
|---|---|
| Entrada | Consulta: `desde`, `hasta`, `formato` (`json` o `csv`) |
| Validaciones | Mismas que `G16` |
| Respuestas | `200` JSON del reporte. Con `formato=csv`: `200 {"csv":"ts,registro,analista,rol,evento,...","periodo":{...}}` (el CSV viaja como texto dentro del JSON). `400 {"error":"formato inválido (json\|csv)"}` |

### 1.5 Servicios collector, classifier, analyst y pipeline

#### C01 - POST `/v1/snapshots` (collector_service.py:27)

| Aspecto | Detalle |
|---|---|
| Entrada | Sin cuerpo |
| Respuestas | `201 {"ok":true,"snapshot":{"alerts":[...],"auth_failure_logs":[...],"context":{...},"generated_at":"<fecha>","summary":{...}}}`. `503 {"error":"<detalle>","hay_captura_previa":true}` si Elasticsearch no responde (la captura anterior se conserva). Este 503 se observó de verdad cuando Elasticsearch estaba caído |
| Depende de | **Elasticsearch** (el único servicio que lo consulta). Escribe `data/collector/siem_clean.json` |

#### C02 - GET `/v1/snapshots/latest` (collector_service.py:39)

`200 {"snapshot":{...}}` con la última captura. `404 {"error":"todavía no hay ninguna captura del SIEM"}` si nunca hubo una. No consulta Elasticsearch: lee el archivo guardado.

#### K01 - POST `/v1/classify` (classifier_service.py:33)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"siem_data":{...captura...},"anteriores":[{"incident_id":"...","first_seen":"...","last_seen":"..."}]}`. Ambos campos son opcionales |
| Validaciones | Cuerpo objeto JSON. `siem_data` debe ser un objeto (por defecto vacío). `anteriores`, si no es lista, se ignora. **No valida el contenido de `siem_data`**: ver los defectos D1 y D2 de la sección 6 |
| Respuestas | `200 {"generated_at":"<fecha>","incident_count":6,"incidents":[...],"source":...}`. `400 {"error":"se esperaba un cuerpo JSON"}`, `{"error":"siem_data debe ser un objeto"}` |
| Depende de | La carpeta `network_logs/` (solo lectura) y la ventana de análisis `SIEM_VENTANA`. No usa LLM. Es determinístico |

#### N01 - POST `/v1/analyze` (analyst_service.py:75)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"incidents":[...incidentes clasificados...],"previos":{"<incident_id>":{...análisis...}},"plazo_s":600}`. Solo `incidents` es obligatorio |
| Validaciones | Cuerpo objeto JSON con `incidents` de tipo lista. `previos`, si no es un objeto, se ignora. `plazo_s` solo cuenta si es número positivo. **No valida que cada elemento de `incidents` sea un objeto**: ver el defecto D3 |
| Respuestas | `200 {"analyst_mode":"fallback","analyzed_at":"<fecha>","incidents":[...]}`. `400 {"error":"se esperaba {incidents: [...]}"}`. `503 {"error":"sin acceso a los antecedentes: ..."}` si audit no responde |
| Depende de | **El LLM**, según `SIEM_USE_LLM` y `SIEM_LLM_PROVEEDOR` (`gemma` local, `gemma-nube` o `gemini`); sin LLM, o si falla, usa el análisis determinístico de respaldo y lo declara en `analyst_mode`. También de **audit** (`GET /v1/decisions`, obligatorio) y de **knowledge** (`POST /v1/context`, opcional: si no responde se analiza sin memoria) |

#### P01 - POST `/v1/cycles` (pipeline_service.py:33)

| Aspecto | Detalle |
|---|---|
| Entrada | Sin cuerpo |
| Respuestas | `200 {"etapas":[{"estado":"ok","etapa":"collector"},{"estado":"ok","etapa":"classifier"},{"estado":"ok","etapa":"analyst"},{"estado":"ok","etapa":"audit"}],"report":{...}}`. `409 {"error":"ya hay un ciclo de análisis en curso"}`. `502 {"error":"<etapa que falló>"}` si falla una etapa crítica |
| Depende de | **Todo**: collector (Elasticsearch), classifier, analyst (**LLM**) y audit (escribe `POST /v1/analysis-history`). Además corre solo cada 120 s (`SIEM_PIPELINE_INTERVALO`), por lo que el estado cambia aunque nadie lo llame. Con el LLM en la nube tarda unos 25 s; con Gemma local, varios minutos |

#### P02 - GET `/v1/incidents` (pipeline_service.py:43)

`200` con el último reporte guardado (sin el estado de las decisiones). `404 {"error":"todavía no hay incidentes analizados","missing":true}` si no hay reporte.

#### P03 - GET `/v1/incidents/<incident_id>` (pipeline_service.py:50)

`200` con el incidente. `404 {"error":"incidente 'INC-NO-EXISTE' no encontrado"}`.

### 1.6 Servicio knowledge

#### M01 - GET `/v1/documents` (knowledge_service.py:48)

`200` con la lista de metadatos (sin el contenido): `[{"caracteres":45,"doc_id":"DOC-05b168d525","subido_por":"postman","titulo":"Guía de escaneo","ts":"<fecha>"}]`.

#### M02 - POST `/v1/documents` (knowledge_service.py:53)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"titulo":"Guía de escaneo","contenido":"Un escaneo de 100 puertos en 1 min es hostil.","subido_por":"postman"}` |
| Validaciones | `titulo` texto obligatorio de hasta 120 caracteres. `contenido` texto obligatorio de hasta 32 KB. `subido_por` obligatorio, hasta 64. Máximo 50 documentos |
| Respuestas | `201 {"documento":{...sin el contenido...},"ok":true}`. `400 {"error":"'titulo' debe ser texto"}`, `{"error":"'contenido' supera 32768 caracteres (N)"}`, `{"error":"se alcanzó el máximo de 50 documentos"}` |

#### M03 - POST `/v1/cases` (knowledge_service.py:61)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"incident_id":"INC-POSTMAN","action_id":"A1","decision":"dismissed","analyst":"postman","attack_type":"ssh_brute_force","note":"olvido de contraseña"}` |
| Validaciones | `decision` solo `approved` o `dismissed`. `incident_id`, `action_id`, `analyst` y `attack_type` obligatorios, de tipo texto. `attacker_ips` y `target_users` listas de textos (hasta 20 elementos). Cuando un mismo patrón se repite en 2 incidentes distintos con el mismo desenlace, se **propone** una lección |
| Respuestas | `201 {"caso":{...},"lecciones_propuestas":[...],"ok":true}`. `400 {"error":"decision inválida (approved\|dismissed)"}` y los mensajes de tipo de campo |

#### M04 - GET `/v1/lessons` (knowledge_service.py:67)

`200` con todas las lecciones en cualquier estado (`propuesta`, `aprobada`, `rechazada`).

#### M05 - POST `/v1/lessons` (knowledge_service.py:72)

Igual que `G14`, con `propuesta_por` en el cuerpo en lugar de la sesión: `{"texto":"...","attack_type":"port_scan","ip":"10.0.0.9","propuesta_por":"postman"}`. `201 {"leccion":{...},"ok":true}`. `400` con los mismos mensajes.

#### M06 - POST `/v1/lessons/<leccion_id>/review` (knowledge_service.py:80)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"decision":"rechazar","revisor":"postman"}` |
| Validaciones | `decision` solo `aprobar` o `rechazar`. `revisor` obligatorio. La lección debe existir y estar en estado `propuesta` |
| Respuestas | `200 {"leccion":{"estado":"rechazada",...},"ok":true}`. `400 {"error":"decision inválida (aprobar\|rechazar)"}`, `{"error":"la lección ya fue aprobada"}`. `404 {"error":"no existe la lección 'LEC-0000000000'"}` |

#### M07 - POST `/v1/context` (knowledge_service.py:90)

| Aspecto | Detalle |
|---|---|
| Entrada | `{"incidents":[{"incident_id":"INC-1","attack_type":"ssh_brute_force","source_ip":"10.0.0.5"}]}` |
| Validaciones | `incidents` de tipo lista y cada elemento un objeto con `incident_id` de tipo texto. **No valida el tipo de `attacker_ips` ni `target_hosts`**: ver el defecto D4 |
| Respuestas | `200 {"INC-1":{"casos_similares":[...],"documentos":[...],"lecciones":[...]}}`. `400 {"error":"se esperaba {incidents: [...]}"}`, `{"error":"cada incidente necesita un 'incident_id'"}` |
| Depende de | Sus tres archivos de memoria. No usa LLM. El texto de los documentos se entrega como contexto, nunca como instrucción |

### 1.7 Salud (H01 a H07)

`GET /v1/healthz` en cada servicio interno (`libs/siem_servicios.py:178`): `200 {"servicio":"auth","status":"ok"}` (con el nombre del servicio). Pública, sin token. `POST /v1/healthz` da `405`. Es la sonda que usa Docker cada 30 s con 3 reintentos (docker-compose.yml, líneas 36-41 y 89-92 en adelante).

## 2. Clasificación

### 2.1 Criterio

- **Core**: el endpoint implementa una de las seis funciones del sistema: autenticación, ingesta, clasificación, alertas, auditoría y análisis.
- **Secundario**: salud, vistas HTML, estáticos, alias de compatibilidad y el resumen de usuarios que usa el arranque del panel.

La memoria del Agente 2 (el servicio knowledge y las rutas `/api/v1/memoria`) está en **Análisis**, porque su único fin es dar contexto al análisis. La corrida completa del pipeline (`P01`) también.

### 2.2 Cuenta

| Área | Endpoints | Cantidad |
|---|---|---|
| Autenticación | G02, G03, G04, A01, A02 | 5 |
| Ingesta | C01, C02 | 2 |
| Clasificación | K01 | 1 |
| Alertas | G07, G08, P02, P03 | 4 |
| Auditoría | G09, G10, G11, G16, U01 a U12 | 16 |
| Análisis | G12, G13, G14, G15, N01, P01, M01 a M07 | 13 |
| **Core** | | **41** |

| Secundarios | Endpoints | Cantidad |
|---|---|---|
| Salud | G06, H01 a H07 | 8 |
| Vistas HTML | G01, G05 | 2 |
| Estáticos | G20 | 1 |
| Alias de compatibilidad | G17, G18, G19 | 3 |
| Resumen de usuarios | A03 | 1 |
| **Secundarios** | | **15** |

| Total | 41 core + 15 secundarios | **56** |
|---|---|---|

### 2.3 El 80 %

El 80 % de 56 es 44,8, es decir **45 endpoints**. Para llegar a esa cifra hay que cubrir los 41 core y 4 secundarios más. Si se mide solo sobre los core, el 80 % de 41 es 32,8, es decir 33.

Hoy la colección de Postman existente cubre 52 de los 56 (93 %): los 41 core y 11 secundarios. Ver la sección 4.


## 3. Mapeo a la ERS

### 3.1 Resultado de la búsqueda

**La ERS no existe en el repositorio.** Se buscó por nombre de archivo (`*ers*`, `*requisit*`, `*requerim*`) y por contenido. Lo que sí hay:

- Identificadores de requisitos (`RQ-SEC-xx`, `RNF-xx-xx`, `RF-xx-xx`) citados en comentarios de pruebas, scripts y código. **Ningún archivo los define**: no hay una tabla con el identificador y su texto.
- Dos textos que hablan de la ERS como un documento externo: `tests/integration/test_pipeline_programado.py:1` ("sección 7.9.2 de la ERS") y `tests/integration/test_api01_autenticacion.py:19` ("Cierra los requisitos ... de la ERS").
- La carpeta `docs/` se borró durante este trabajo. En el momento de la búsqueda existía y su único apartado "Requerimientos" (`docs/00-arquitectura.md:188`) listaba CPU, memoria y software, sin identificadores RF ni RNF.

Si la ERS existe, está fuera del repositorio (por ejemplo en el Drive del equipo). No se usó, porque el pedido fue buscar en el repositorio, y no se inventó ningún identificador.

### 3.2 Endpoints y requisitos citados

"Directo" significa que el repositorio nombra el requisito al hablar de ese endpoint o de su prueba. "Inferido" significa que el vínculo lo deduje yo del contexto y no está escrito así: conviene confirmarlo contra la ERS.

| Endpoints | Requisito citado | Dónde se cita | Vínculo |
|---|---|---|---|
| G03, G04, G05, G07, G08, G09, G10, G11, G17, G18, G19 | RQ-SEC-08, RQ-SEC-11, RQ-SEC-13, RF-DIF-04 | `tests/integration/test_api01_autenticacion.py:19`. La lista `RUTAS_PROTEGIDAS` (líneas 35-47) enumera exactamente estas rutas | Directo, **por grupo**: el repositorio no dice qué identificador corresponde a qué ruta |
| G02 | Los mismos cuatro | La misma prueba cubre el login (inicio de sesión, bloqueo por intentos) | Directo, por grupo |
| A01, A02 | Los mismos cuatro | Son la autenticación que esa prueba ejercita a través del gateway | Inferido |
| G09 | RNF-RD-04 (responde en menos de 500 ms) | `tests/postman/generar_coleccion.py:176` | Directo |
| G09, U01, U04, U06, U09 | RF-AUD-03 (el registro de auditoría es inmutable) | `scripts/pruebas_de_api_postman.sh:7`, `tests/postman/malla_postman.py:6` | Inferido: se cita como motivo para no escribir en el registro real |
| P01 | RNF-RD-07 y "sección 7.9.2 de la ERS" (corrida programada del pipeline) | `tests/integration/test_pipeline_programado.py:1` | Directo |
| K01 | RF-SIM-05 (fallos de autenticación leídos de `network_logs/`) y RNF-MANT-04 (umbrales por entorno) | `services/classifier/classifier.py:1255` y `:50` | Inferido: se citan en funciones internas, no en el endpoint |
| C01 | RNF-MANT-04 y RNF-PORT-05 (ventana de análisis por entorno) | `libs/siem_lib.py:184` | Inferido |
| N01 | RNF-CONF-04 (degradación garantizada: sin LLM el sistema funciona con el análisis de respaldo) | `scripts/demo.sh:156` | Inferido |
| G06, H01 a H07 | RNF-CONF-05 (la capa SIEM se verifica cada 30 s y se reinicia tras 3 fallos) | `tests/unit/test_despliegue_compose.py` (descripción del módulo). Los healthchecks de `docker-compose.yml` líneas 273 y 460 llaman a estas rutas | Inferido |
| G05, G20 | RNF-USA-07 y RNF-USA-08 (icono estable por tipo de ataque, contraste y teclado de la interfaz) | `tests/unit/test_iconos.py:235`, `tests/unit/test_contraste_de_la_interfaz.py:1`, `tests/unit/test_s02_xss_dashboard.py:314` | Inferido: son requisitos de la interfaz que estas rutas sirven |
| Los 52 endpoints que cubre la colección de Postman | RNF-RD-01 (responde en menos de 2 s) y RQ-SEC-18 (no expone trazas ni rutas internas) | `tests/postman/generar_coleccion.py:315-316`, como aserción global de toda la colección | Directo |

### 3.3 Endpoints sin requisito identificado

Aparte de los dos requisitos globales de la última fila de la tabla 3.2 (tiempo de respuesta y no filtrar trazas), el repositorio no vincula ningún identificador a estos **25 endpoints**: G01, G12, G13, G14, G15, G16, A03, U02, U03, U05, U07, U08, U10, U11, U12, C02, P02, P03, M01, M02, M03, M04, M05, M06, M07.

Entre ellos están todas las rutas de memoria del agente (`G12` a `G15`, `M01` a `M07`) y de reportes (`G16`, `U12`). La prueba de autenticación **no** las incluye en `RUTAS_PROTEGIDAS`, así que ni siquiera el grupo de requisitos de acceso les está atribuido. Los otros 31 endpoints (de los 56) sí tienen algún requisito en la tabla 3.2.

### 3.4 Identificadores citados que no corresponden a ningún endpoint

`RQ-SEC-05` (respaldo cifrado), `RQ-SEC-17` (retención de datos personales), `RQ-SEC-24` (red aislada de simulación), `RNF-COMP-01` y `RNF-RD-02` (topes de memoria de los contenedores), `RF-DIF-03` (reglas de detección como código), `RF-SIM-05` fuera del clasificador (simulación sin conexión), `RNF-MANT-05`, `RNF-SEG-xx`, `RNF-FIA-01`, `RNF-CAL-01` y `RNF-MAN-xx`. Se citan en scripts, en la configuración de Docker o en documentos que ya no están.

## 4. Pruebas existentes

### 4.1 Colección de Postman

| Dato | Detalle |
|---|---|
| Archivo | `tests/postman/neuraldefender.postman_collection.json` (se regenera con `tests/postman/generar_coleccion.py`) |
| Contenido | 113 pedidos en 8 carpetas: 01 Salud y token interno, 02 Sesión y fuerza bruta, 03 Incidentes y decisiones, 04 Memoria y reportes, 05 Auth (interno), 06 Audit (interno), 07 Knowledge (interno), 08 Pipeline, collector, classifier y analyst |
| Entornos | **No hay archivo de entorno guardado.** `tests/postman/malla_postman.py --entorno <archivo>` lo genera en cada corrida, con las variables `url_<servicio>`, `token`, `password`, `analista`, `dado_de_baja`, `auditor`, `observador` y `victima` |
| Cómo se corre | `./scripts/pruebas_de_api_postman.sh`: levanta la **malla aislada** (los 8 servicios reales en procesos locales con datos temporales), corre Newman 6 en Docker y guarda el reporte en `reportes/postman/newman-<fecha>.json` |
| Por qué una malla | Para poder escribir decisiones, documentos y lecciones sin tocar la auditoría real, que es inmutable |

**Resultados de hoy:**

| Corrida | Pedidos | Aserciones | Fallos | Causa |
|---|---|---|---|---|
| Con Elasticsearch caído | 113 | 392 | **5** | Todas en la carpeta 08. El collector devolvió 503 al capturar, y de ahí se encadenan "Última captura" (404), "las 4 etapas en ok" y "Un incidente del pipeline" (404). Es un problema del entorno, no del código |
| Con Elasticsearch sano | 113 | 392 | **0** | Duración total 4,7 s, tiempo medio de respuesta 22 ms |

### 4.2 Qué endpoints cubre la colección

La colección ejercita **52 de los 56 endpoints**: los 41 core y 11 secundarios. Los 4 que no cubre:

| ID | Endpoint | Observación |
|---|---|---|
| G17 | GET `/api/incidents` | Alias sin versionar. Sí lo cubre pytest |
| G18 | POST `/api/decision` | Alias sin versionar. Sí lo cubre pytest |
| G19 | GET `/api/decisions` | Alias sin versionar. Sí lo cubre pytest |
| G20 | GET `/static/<path:filename>` | Estáticos del panel |

Lo que la colección **no** ejercita, aunque cubra el endpoint: los tipos de dato equivocados dentro de un JSON válido (origen de los defectos D1 a D4 de la sección 6), los cuerpos de más de 64 KB o 16 MB, y los métodos no permitidos (solo prueba `DELETE /v1/decisions`). Tiene además una aserción global de tiempo de respuesta (RNF-RD-01) y de que no se filtren trazas (RQ-SEC-18).

### 4.3 Pruebas de pytest que llaman a la API

Corridas hoy, archivo por archivo, con `.devtools/bin/pytest`:

| Archivo | Pruebas | Resultado | Qué cubre (según su descripción) |
|---|---|---|---|
| `tests/integration/test_api01_autenticacion.py` | 72 | Pasan | Autenticación, sesiones y control de acceso (hallazgo API-01) |
| `tests/integration/test_memoria_del_agente.py` | 22 | Pasan | Memoria del Agente 2: aprende solo con aprobación |
| `tests/integration/test_api_v1.py` | 38 | Pasan | Contrato de la API `/api/v1/` (hallazgos API-02 a API-05) |
| `tests/integration/test_api_caracterizacion.py` | 17 | Pasan | Caracterización de la API REST del panel |
| `tests/integration/test_microservicios.py` | 40 | Pasan | Contratos de la malla de microservicios |
| `tests/integration/test_reportes.py` | 17 | Pasan | Reportes de la supervisión humana y actividad de memoria |
| `tests/integration/test_auditoria_append_only.py` | 7 | Pasan | El registro de decisiones es de solo agregar |
| `tests/integration/test_a02_a04_integridad.py` | 35 | Pasan | Integridad real del registro de auditoría |
| `tests/test_no_autonomy.py` | 88 | Pasan | Enumera por análisis del código la API completa de cada servicio |
| **Total** | **336** | **Todas pasan** | |

Una búsqueda de texto de las rutas en esos archivos encuentra mención literal de 47 de los 49 endpoints funcionales del gateway y de los servicios internos. Las dos sin mención literal son las rutas de revisión de lecciones (`G15` y `M06`), que esas pruebas arman con el identificador dentro del texto; no se verificó a mano que estén cubiertas. Es una medida aproximada.

### 4.4 Otras

| Elemento | Detalle | Estado hoy |
|---|---|---|
| `tests/performance/neuraldefender.js` (k6) | Llama a `healthz`, `login`, `me`, `incidents`, `incidents/<id>`, `decisions`, `audit/verify` y `memoria`. Solo lecturas. Se corre con `./scripts/pruebas_de_performance.sh [humo\|carga\|estres\|pico\|login]` en un contenedor | **No se corrió.** k6 no está instalado en el equipo y el script lo baja en Docker |
| `tests/calidad/medicion_iso25023.py` | Mide con la misma malla aislada | No se corrió |

## 5. Entorno

### 5.1 Cómo levantar el sistema

Desde `Elastic-SIEM-Project/`:

```
./scripts/start.sh
```

Levanta Elasticsearch, Kibana, Logstash, Filebeat y los 8 servicios, despliega las reglas de detección y la política de retención, y espera a que todo esté sano. Tarda unos 4 a 5 minutos la primera vez. Requisitos: Docker y un archivo `.env` con `SECRET_KEY`; `SIEM_INTERNAL_TOKEN` lo genera el propio script si falta. Para comprobar: `docker compose ps`.

| Qué | URL o puerto | Publicado al host |
|---|---|---|
| Gateway (panel y API) | `http://127.0.0.1:5000` | Sí, solo en loopback |
| Elasticsearch | `http://127.0.0.1:9200` | Sí, en loopback |
| Kibana | `http://127.0.0.1:5601` | Sí, en loopback |
| Los 7 servicios internos | `http://<servicio>:8000`, con `<servicio>` en `auth`, `audit`, `collector`, `classifier`, `analyst`, `pipeline`, `knowledge` | **No.** Solo dentro de la red de Docker `elastic-siem-project_ia-net` |

Para llamar a un servicio interno con `curl` desde el equipo:

```
TOK="$(grep '^SIEM_INTERNAL_TOKEN=' .env | cut -d= -f2-)" \
docker run --rm --network elastic-siem-project_ia-net -e TOK curlimages/curl:latest \
  sh -c 'curl -s -H "X-Internal-Token: $TOK" http://audit:8000/v1/decisions/verify'
```

**Alternativa para pruebas que escriben:** `./scripts/pruebas_de_api_postman.sh` levanta una malla aislada con datos temporales. Es la forma segura de probar `POST` de decisiones, documentos y lecciones, porque en el sistema real esos registros son inmutables. Solo necesita Elasticsearch sano para las rutas del collector.

### 5.2 Credenciales

**Gateway** (sesión). Crear un usuario por rol, con la contraseña pasada por entorno para no escribirla en el historial:

```
SIEM_NEW_PASSWORD='<contraseña>' ./scripts/siem.sh usuarios crear <nombre> --rol analyst
SIEM_NEW_PASSWORD='<contraseña>' ./scripts/siem.sh usuarios crear <nombre> --rol viewer
SIEM_NEW_PASSWORD='<contraseña>' ./scripts/siem.sh usuarios crear <nombre> --rol auditor
```

Roles: `analyst`, `viewer` y `auditor` (sección 1.0). Dar de baja: `./scripts/siem.sh usuarios baja <nombre>`. Iniciar sesión y usar el token CSRF:

```
curl -s -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"username":"<nombre>","password":"<contraseña>"}' http://127.0.0.1:5000/api/v1/login
# copiar "csrf_token" de la respuesta y mandarlo en los POST:
curl -s -b cookies.txt -H 'X-CSRFToken: <csrf_token>' -H 'Content-Type: application/json' \
  -d '{"incident_id":"...","action_id":"...","decision":"approved"}' http://127.0.0.1:5000/api/v1/decision
```

Para este trabajo se crearon tres usuarios de prueba dedicados: `api-analista`, `api-observador` y `api-auditor`. Su contraseña no se guarda en este documento. Siguen activos: conviene darlos de baja al terminar.

**Servicios internos** (token). El valor de `SIEM_INTERNAL_TOKEN` está en `.env`, se manda en la cabecera `X-Internal-Token` y tiene al menos 32 caracteres. **No se copia a este documento.**

**Postman.** El entorno se genera solo con la malla aislada (sección 4.1); no hace falta crear credenciales.

### 5.3 Datos de prueba

| Dato | Cómo conseguirlo |
|---|---|
| Incidentes | `bash simulation/run-brute-force.sh --offline`, `run-port-scan.sh --offline` y `run-phishing.sh --offline` (cada uno acepta `--ip <IP>`), y después `./scripts/siem.sh pipeline`. Ese ciclo usa el LLM |
| Estado actual del sistema | 8 incidentes en el reporte (`INC-AUTH-desconocida-7c808c94`, `INC-AUTH-203.0.113.30-20e28259`, `INC-AUTH-198.51.100.250-352ddf6f`, `INC-AUTH-198.51.100.76-e498a032`, `INC-AUTH-198.51.100.151-e98048c4`, `INC-AUTH-172.18.0.3-0893f53f`, `INC-SCAN-203.0.113.10-5663da03` e `INC-PHISH-172.18.0.9-a15a7d0c`), 19 decisiones y 4 usuarios propios más los 3 de prueba |
| `incident_id` y `action_id` para una decisión | Salen de `GET /api/v1/incidents`: cada incidente trae `recommended_actions[]` con su `action_id` y su `status` (`pending`, `approved` o `dismissed`) |
| Lecciones y documentos | No hacen falta: se crean con `POST`. Máximo 50 documentos |

### 5.4 Qué no se puede probar localmente, o con cuidado

| Tema | Motivo |
|---|---|
| Cookie `Secure` y TLS | `SIEM_TLS=true` exige HTTPS y el despliegue local es HTTP en loopback |
| Texto del LLM en la nube | Necesita una `GEMINI_API_KEY` válida y red. La respuesta de `N01` y el campo `analysis` cambian en cada corrida: conviene aserciones de estructura y no de contenido. Con Gemma local, un ciclo tarda varios minutos y usa unos 4 GB de RAM |
| Escrituras sobre la auditoría real | `U01`, `U04`, `U06` y `U09` agregan líneas que no se pueden borrar. Usar la malla aislada |
| Bloqueo por intentos (429) | Está en memoria durante 15 minutos por usuario e IP. Probarlo solo con un usuario descartable |
| Ciclos reales del pipeline | El programador corre un ciclo cada 120 s (`SIEM_PIPELINE_INTERVALO`), por lo que el estado cambia aunque nadie llame. Se desactiva con `SIEM_PIPELINE_INTERVALO=0` |
| Servicio caído (502 y 503) | Se puede provocar parando un contenedor (`docker stop siem-audit`), pero afecta al sistema entero. Solo se observó el 503 del collector con Elasticsearch caído |
| Carga y rendimiento | k6 no está instalado localmente |

### 5.5 Estado del entorno durante este trabajo

Al mover la carpeta del proyecto, los contenedores quedaron apuntando a la ruta vieja: Elasticsearch, Kibana, Logstash y Filebeat se cayeron, y los servicios `siem-*` montaron carpetas `data/` vacías en la ruta vieja (sin usuarios ni auditoría). Se volvió a levantar todo con `./scripts/start.sh` desde la carpeta nueva y las pruebas de este documento corrieron después de eso. **Si se vuelve a mover la carpeta, hay que repetir ese paso.** En la ruta vieja quedaron directorios `data/` vacíos creados por Docker con dueño `root`, que se borran con `sudo`.

## 6. Contrato de errores

### 6.1 Cómo se probó

Con `curl`, contra el sistema real levantado, con 298 sondeos: 211 contra los 7 servicios internos (desde un contenedor `curl` dentro de la red de Docker) y 87 contra el gateway (desde el equipo, con sesión real de los tres roles). Los scripts están en `entregables/2-servicios/evidencia/`. Todos los cuerpos de entrada son inválidos a propósito, para que se rechacen antes de escribir:

- **Servicios internos:** la auditoría tiene exactamente las mismas líneas antes y después (112 accesos, 185 corridas, 19 decisiones).
- **Gateway:** agregó 9 registros de acceso (de 103 a 112), que son los esperados: 3 intentos fallidos y un inicio y un cierre de sesión por cada uno de los 3 roles.

### 6.2 Resultado por tipo de error

| Caso | Servicios internos (211 sondeos) | Gateway (87 sondeos) |
|---|---|---|
| **JSON mal formado** (`{bad`) | `400 {"error":"se esperaba un cuerpo JSON"}` en las 12 rutas con cuerpo | `400 {"error":"se esperaba un cuerpo JSON"}` en login, decisión, documentos y revisión |
| **Cuerpo que no es un objeto** (arreglo, texto plano, vacío) | `400` en las 12 rutas, para los tres casos | `400` en login y decisión |
| **Campo faltante** (`{}`) | `400` con el campo que falta en 10 de las 12 rutas. `auth` responde `401` (credenciales incorrectas). `classifier` responde `200`: una captura vacía es válida | Decisión `400 {"error":"decision inválida (approved\|dismissed)"}`. Documentos `400 {"error":"'titulo' debe ser texto"}`. Login `401` |
| **Token inválido o ausente** | `401 {"error":"token interno ausente o inválido"}` en las 29 rutas funcionales, con y sin token falso. También en rutas inexistentes (se comprueba antes que la ruta) | Sin sesión: `401 {"error":"se requiere autenticación"}`. Cookie falsa: `401`. POST sin token CSRF o con token falso: `403 {"error":"token CSRF inválido o ausente: ..."}` |
| **Recurso inexistente** | Ruta inexistente con token: `404` en los 7 servicios. `/v1/users/<no existe>`, `/v1/incidents/<no existe>` y `/v1/lessons/<no existe>/review`: `404`. Path traversal en la ruta: `404` | Incidente `404 {"error":"incidente 'INC-NO-EXISTE' no encontrado"}`. Acción `404`. Lección `404 {"error":"no existe la lección 'LEC-0000000000'"}`. Ruta inexistente: `404` |
| **Método no permitido** | `405 {"error":"The method is not allowed for the requested URL.","status":405}` en las 29 rutas (con `DELETE`) y en las 7 sondas de salud (con `POST`) | `405` en login (`PUT`), incidentes (`DELETE`), decisión (`GET`) y `me` (`PUT`) |
| **Cuerpo demasiado grande** | `413` con 17 MB (el tope es 16 MB) | `413` con 70 KB (el tope es 64 KB) en login y decisión |
| **Falta de permiso** | No aplica | `403 {"error":"el rol 'viewer' no tiene permiso para 'decidir'","permiso_requerido":"decidir"}`. Probado con los tres roles sobre la verificación de cadena, la decisión y las tres rutas de memoria que escriben |

Ejemplo de reproducción de un caso en el gateway:

```
curl -s -i -X POST -H 'Content-Type: application/json' -d '{bad' http://127.0.0.1:5000/api/v1/login
# HTTP/1.1 400 BAD REQUEST
# {"error":"se esperaba un cuerpo JSON"}
```

Todas las respuestas de los servicios internos y todas las de `/api/` del gateway tienen `Content-Type: application/json`.

### 6.3 Defectos: respuestas 5xx

La cátedra considera defecto cualquier respuesta 5xx. Se encontraron **4**, todas en servicios internos, todas con el mismo origen: el servicio no valida el tipo de un campo dentro de un JSON válido y falla con una excepción no controlada. El cuerpo de la respuesta no filtra el rastro ni las rutas internas (`{"error":"The server encountered an internal error and was unable to complete your request. ..."}`).

| ID | Endpoint | Entrada que lo provoca | Código | Causa (según el log del contenedor) |
|---|---|---|---|---|
| D1 | K01 POST `/v1/classify` | `{"siem_data":{"alerts":"x"}}` | 500 | `services/classifier/classifier.py:852` (`detect_auth_incidents`): `a.get("mitre")` sobre algo que no es un objeto, `AttributeError: 'str' object has no attribute 'get'` |
| D2 | K01 POST `/v1/classify` | `{"siem_data":{"alerts":[1,2]}}` | 500 | El mismo punto: `AttributeError: 'int' object has no attribute 'get'` |
| D3 | N01 POST `/v1/analyze` | `{"incidents":[1,2]}` | 500 | `services/analyst/analyst_service.py:57` (`_memoria_del_agente`): `inc.get("incident_id")` sobre un número, `AttributeError: 'int' object has no attribute 'get'` |
| D4 | M07 POST `/v1/context` | `{"incidents":[{"incident_id":"a","attacker_ips":5}]}` o `"target_hosts":9` | 500 | `services/knowledge/memoria.py:163` (`_ips_de`): `set(registro.get("attacker_ips") or [])` con un número, `TypeError: 'int' object is not iterable` |

Aislando campo por campo se comprobó que en D4 rompen `attacker_ips` y `target_hosts` cuando no son listas; `target_users`, `source_ip` y `attack_type` con tipo equivocado dan 200. En D1, `alerts: []` da 200 y cualquier elemento que no sea un objeto da 500.

Reproducción (desde `Elastic-SIEM-Project/`, sin modificar datos):

```
TOK="$(grep '^SIEM_INTERNAL_TOKEN=' .env | cut -d= -f2-)" \
docker run --rm --network elastic-siem-project_ia-net -e TOK curlimages/curl:latest sh -c '
curl -s -w " -> HTTP %{http_code}\n" -H "X-Internal-Token: $TOK" -H "Content-Type: application/json" \
  -d "{\"siem_data\":{\"alerts\":[1,2]}}" http://classifier:8000/v1/classify
curl -s -w " -> HTTP %{http_code}\n" -H "X-Internal-Token: $TOK" -H "Content-Type: application/json" \
  -d "{\"incidents\":[1,2]}" http://analyst:8000/v1/analyze
curl -s -w " -> HTTP %{http_code}\n" -H "X-Internal-Token: $TOK" -H "Content-Type: application/json" \
  -d "{\"incidents\":[{\"incident_id\":\"a\",\"attacker_ips\":5}]}" http://knowledge:8000/v1/context'
```

**Alcance real.** Los 4 defectos solo se pueden provocar con el token interno, desde dentro de la red de Docker, así que el navegador y el gateway no los alcanzan con datos del usuario. Aun así cumplen el criterio de la cátedra, y el plan de pruebas debería incluir un caso por cada uno que espere `400`. La colección de Postman actual no los cubre.

**5xx que el código define a propósito** (no se provocaron, salvo el segundo):

| Endpoint | Código | Cuándo |
|---|---|---|
| A03 GET `/v1/users-summary` | 500 | El archivo de usuarios está corrupto (`auth_service.py:66-67`) |
| C01 POST `/v1/snapshots` | 503 | Elasticsearch no responde. **Observado de verdad** cuando estaba caído |
| P01 POST `/v1/cycles` | 502 | Falla una etapa crítica del ciclo |
| N01 POST `/v1/analyze` | 503 | El servicio audit no responde |
| Gateway, rutas con servicios internos | 503 | Un servicio interno no responde o responde algo inesperado |

### 6.4 Observaciones sobre el contrato que conviene decidir en el plan

No son defectos, pero cambian qué código espera una prueba:

1. **Un POST sin sesión da 403 y no 401.** El token CSRF se comprueba antes que la sesión. La prueba de pytest `test_sin_sesion_no_se_accede` espera 401 porque su cliente de prueba no activa el CSRF; contra el sistema real, `POST /api/v1/decision`, `/api/v1/logout` y `/api/v1/memoria/documentos` sin sesión responden 403.
2. **Los 404 fuera de `/api/` son HTML** (`/no-existe`), no JSON.
3. **Dos formatos de error en la misma API.** Algunos errores traen `{"error":"..."}` (por ejemplo el login con JSON mal formado) y otros `{"error":"...","status":400}` (por ejemplo `POST /api/v1/memoria/documentos` con JSON mal formado, y todo error generado por Flask).
4. **Identificador de lección con barra codificada** (`/api/v1/memoria/lecciones/..%2Fetc/revision`): el código prevé un `400`, pero la ruta no llega a la vista y responde un `404` genérico.
5. **`POST /api/v1/logout` responde `204` con `Content-Type: text/html`** y sin cuerpo.
6. **En un servicio interno, una ruta inexistente sin token da 401**, no 404.

## 7. Archivos de evidencia

Todos en `entregables/2-servicios/evidencia/`.

| Archivo | Contenido |
|---|---|
| `sondeo_internos.sh` y `sondeo_internos.txt` | Los 211 sondeos a los servicios internos y su salida cruda |
| `sondeo_gateway.sh` y `sondeo_gateway.txt` | Los 87 sondeos al gateway y su salida cruda |
| `auditoria-antes.txt`, `auditoria-antes-2.txt` | Cantidad de registros de auditoría antes de cada sondeo |

Además, en `reportes/postman/`: `newman-20261122-192251.json` (con Elasticsearch caído, 5 fallos) y `newman-20261122-192600.json` (sano, 0 fallos).
