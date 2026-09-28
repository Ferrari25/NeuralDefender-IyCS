# Prompt de trabajo — continuar SIEM-IA tarea por tarea

> **Cómo se usa.** La **Parte A** es contexto: se pega igual al inicio de cada
> sesión nueva. La **Parte B** es la tarea: se elige una sola del catálogo y se
> pega debajo. La **Parte C** son las reglas de trabajo, que también van siempre.
>
> Está pensado para no perder contexto entre sesiones y para que cada tarea se
> cierre completa —código, pruebas y documentación— antes de empezar la
> siguiente.

---

## Parte A · Contexto (pegar siempre)

```
Actúa como Arquitecto de Seguridad y Desarrollador Python Senior.

PROYECTO: SIEM-IA — plataforma de detección y análisis asistido de incidentes de
seguridad con supervisión humana obligatoria. Trabajo de la materia Ingeniería de
Software (Grupo 4, ciclo 2026).

UBICACIÓN: /home/test/Descargas/SIEM-IA-main/Elastic-SIEM-Project

PRINCIPIO RECTOR, NO NEGOCIABLE:
  La IA sugiere, el humano decide, y el sistema NO ejecuta ninguna acción de
  contención. Ningún cambio puede introducir ejecución de comandos. Está
  certificado por tests/test_no_autonomy.py (34 pruebas sobre el AST) y hay que
  mantenerlo así.

ARQUITECTURA:
  Capa SIEM (Docker)  : Elasticsearch + Kibana + Logstash + Filebeat
  Capa IA (Python)    : classifier.py (Agente 1, determinístico)
                        siem_agent.py (Agente 2, LLM con respaldo determinístico)
                        siem_lib.py, siem_validators.py, audit_verify.py
  Supervisión (Flask) : dashboard.py + templates/ + static/app.js, puerto 5000
                        (el JS se escapa con la plantilla etiquetada `html`)
  Registro            : decisions.jsonl — append-only, cadena SHA-256 verificable

ESTADO ACTUAL (17-09-2026, tras la tarea P1), verificado en ejecución:
  - 724 pruebas pasan en ~75 s; cobertura 95 %
  - SAST en CERO hallazgos: pylint(9,65) + secure-coding-standard, bandit, ruff,
    y ESLint sobre 649 líneas REALES de JS (static/app.js + static/login.js)
  - Puerta de calidad completa: ./scripts/check.sh (~120 s)
  - NO queda ningún bug congelado: `pytest -m bug` no colecta nada
  - El panel EXIGE LOGIN (3 roles). Sin SECRET_KEY no arranca; sin usuarios nadie entra:
        python3 manage_users.py crear <nombre> --rol analyst
  - Las 13 reglas de detección están versionadas en rules/ndjson/ y se despliegan
    con ./scripts/deploy-rules.sh (start.sh ya lo hace). Idempotente.

DOCUMENTACIÓN QUE HAY QUE LEER ANTES DE EMPEZAR:
  docs/auditoria/01-auditoria-integral.md  ← estado real, qué falla, qué falta
  docs/10-plan-de-accion.md                ← plan aprobado y sus hallazgos (IDs)
  docs/12-registro-de-pruebas.md           ← qué se verifica y qué dio
  CLAUDE.md                                ← mapa del código

ENTORNO:
  Las herramientas de desarrollo están en .devtools/ (PEP 668: no se puede tocar
  el Python del sistema). Antes de cualquier cosa:
      export PYTHONPATH="$PWD/.devtools"
```

---

## Parte B · Catálogo de tareas

Elegir **una sola** y pegarla debajo de la Parte A. Están en orden recomendado:
cada una desbloquea a las siguientes.

---

### ✅ Tarea P1 · Login, sesiones y roles — COMPLETADA (17-09-2026)

> Cerrada. Ver `docs/15-autenticacion-y-roles.md`. Se conserva el enunciado
> como referencia de alcance y criterio de aceptación.

```
TAREA: Implementar autenticación, gestión de sesiones y control de acceso por
roles en el dashboard. Cierra el hallazgo F-01 de la auditoría y los requisitos
RQ-SEC-08, RQ-SEC-11, RQ-SEC-13 y RF-DIF-04 de la ERS.

POR QUÉ IMPORTA: hoy el campo `analyst` del registro inmutable sale de la
variable de entorno ANALYST_NAME. Quien corre el proceso decide qué nombre firma
cada decisión. La cadena de hash garantiza que el registro no se alteró después
de escribirse; todavía no garantiza quién lo escribió. Para un sistema cuya
premisa es la supervisión humana trazable, es la brecha más importante que queda.

ALCANCE — HACER:
  1. Almacén de usuarios en users.json (fuera del repo, chmod 600), gestionado
     por un CLI manage_users.py (crear, listar, cambiar contraseña, desactivar).
  2. Hash de contraseña con Argon2id (argon2-cffi). No usar el default de
     werkzeug.
  3. Flask-Login + cookie de sesión firmada. SECRET_KEY desde .env, y que el
     servidor NO ARRANQUE si falta (nada de valores por defecto).
  4. Flags de cookie: HttpOnly, SameSite=Lax, Secure cuando haya TLS.
  5. CSRF con Flask-WTF, token por header X-CSRFToken (la API es JSON).
  6. Expiración: 30 min de inactividad, 8 h absoluta.
  7. Anti-fuerza bruta: 5 intentos / 15 min por usuario+IP, con backoff.
     (Es irónico que un sistema que detecta fuerza bruta sea vulnerable a ella.)
  8. Tres roles con decorador @require_role, permisos en una tabla y no
     dispersos en ifs:
        viewer  : ve triage y auditoría; NO decide
        analyst : ve y decide
        auditor : ve, NO decide, y puede verificar la cadena de hash
  9. El campo `analyst` de decisions.jsonl pasa a salir de current_user.username.
     Agregar también session_id (derivado, no la cookie) y user_agent.
 10. ELIMINAR la variable de entorno ANALYST_NAME del camino de decisión.

ALCANCE — NO HACER (declararlo en la documentación):
  MFA, SSO/LDAP, recuperación de contraseña, alta de usuarios por interfaz,
  multi-tenancy. Para un MVP de laboratorio, un archivo de usuarios protegido
  alcanza, y es más honesto decirlo que simularlo.

NOTA DE DISEÑO QUE HAY QUE DOCUMENTAR:
  Ningún rol puede ejecutar acciones. El RBAC controla QUIÉN DECIDE, no quién
  ejecuta — porque nadie ejecuta. Que quede escrito para que un lector no asuma
  que `admin` es el rol que aprieta el botón rojo: ese botón no existe.

PRUEBAS QUE TIENE QUE DEJAR:
  - Las 2 pruebas congeladas de API-01 se dan vuelta y se reescriben como
    regresión (hoy afirman que NO hay autenticación).
  - 401 sin sesión en los 10 endpoints, salvo /api/v1/healthz y /api/v1/login.
  - 403 cuando un `viewer` intenta decidir.
  - El registro guarda el usuario de la sesión, no la variable de entorno.
  - Sesión expirada ⇒ 401.
  - CSRF ausente o inválido ⇒ 403.
  - 6 intentos fallidos ⇒ bloqueo temporal.
  - El servidor no arranca sin SECRET_KEY.

CRITERIO DE ACEPTACIÓN:
  ./scripts/check.sh en verde · pytest -m bug no colecta nada · cobertura ≥ 80 %
```

---

### ✅ Tarea P2 · Extraer el JavaScript (refactor R-05) — COMPLETADA (17-09-2026)

> Cerrada. ESLint analiza 649 líneas con 0 hallazgos. Ver
> `docs/12-registro-de-pruebas.md` §4.7.

```
TAREA: Separar templates/index.html (718 líneas de HTML + CSS + JS) en
static/app.js, static/app.css y la plantilla. Cierra F-03 y desbloquea P4.

POR QUÉ IMPORTA: eslint-plugin-security y eslint-plugin-no-unsanitized están
configurados y verificados, pero apuntan a static/**/*.js y ese directorio no
existe. De los dos linters de código estático que el proyecto se propuso
demostrar, el de JavaScript hoy corre sobre CERO archivos.

ALCANCE:
  1. Extraer el <script> a static/app.js y el <style> a static/app.css.
  2. La plantilla los referencia con url_for('static', ...).
  3. NO cambiar comportamiento en este paso: es un movimiento, no un rediseño.
  4. Correr `npm run lint:js` y corregir lo que aparezca. Es la primera vez que
     ESLint ve este código: esperar hallazgos reales.
  5. Convertir los <tr> y <span> clicables en <button> o agregarles
     role/tabindex — hoy no son navegables por teclado (RNF-USA-08).

CUIDADO CON:
  - S-02 ya está corregido: no hay handlers inline y los datos viajan en
    atributos data-*. NO reintroducir onclick al mover el código.
  - tests/unit/test_s02_xss_dashboard.py extrae el esc() de la plantilla por
    posición de texto; hay que actualizarlo para que lo lea de static/app.js.
  - test_la_plantilla_no_ejecuta_nada_del_lado_del_cliente también lee el HTML.

PRUEBAS QUE TIENE QUE DEJAR:
  - ESLint corriendo sobre archivos reales, con 0 errores.
  - Las 28 pruebas de S-02 siguen pasando, apuntando al archivo nuevo.
  - Una prueba que verifique que la plantilla NO tiene <script> embebido.

CRITERIO DE ACEPTACIÓN:
  ./scripts/check.sh en verde · `npm run lint:js` analiza > 0 archivos con 0 errores
```

---

### ✅ Tarea P3 · Reglas de detección como código — COMPLETADA (17-09-2026)

> Cerrada. 13 reglas versionadas en `rules/ndjson/`, desplegables con
> `./scripts/deploy-rules.sh`. Ver `docs/12-registro-de-pruebas.md` §4.8.

```
TAREA: Versionar las 13 reglas de detección y poder desplegarlas por API. Cierra
F-02 y el requisito RF-DIF-03 de la ERS.

POR QUÉ IMPORTA: rules/rules.md documenta 13 reglas, pero en el Kibana que corre
hay 4, creadas a mano en la consola. Quien clone el repositorio y levante el
stack NO obtiene el mismo sistema. Eso rompe la reproducibilidad, que es
justamente lo que evalúa el objetivo del entorno de simulación.

ALCANCE:
  1. Directorio rules/ndjson/ con una regla por archivo, en el formato de
     exportación de Elastic Security (NDJSON).
  2. Exportar primero las 4 que YA existen en Kibana, para no inventar el
     formato:
        GET /api/detection_engine/rules/_export
  3. Escribir las 9 faltantes (A1, A3, A5, A6, B2, B3, B4, C2, C3) tomando
     rules/rules.md como fuente: la consulta, el umbral y el mapeo MITRE ya
     están especificados ahí.
  4. Script scripts/deploy-rules.sh que las importe:
        POST /api/detection_engine/rules/_import
     Idempotente: correrlo dos veces no puede duplicar reglas.
  5. Script scripts/export-rules.sh para el camino inverso, y así mantener
     sincronizado lo que está en Kibana con lo que está versionado.
  6. Integrarlo en scripts/start.sh, después de que Kibana responda.

CUIDADO CON:
  - NO usar `deploy` como sinónimo de ejecutar acciones de contención. Esto
    despliega REGLAS DE DETECCIÓN en Kibana, no acciones sobre infraestructura.
    La no-autonomía no se toca.
  - El script usa credenciales de .env: no hardcodearlas ni imprimirlas.

PRUEBAS QUE TIENE QUE DEJAR:
  - Cada archivo NDJSON es válido y trae rule_id, name, type, severity, threat.
  - Los rule_id son únicos.
  - Las 13 reglas del catálogo tienen su archivo (comparar contra rules.md).
  - El script de despliegue es idempotente (verificable con un Kibana simulado).

CRITERIO DE ACEPTACIÓN:
  Desde cero: docker compose up -d && ./scripts/deploy-rules.sh ⇒ 13 reglas
  activas en Kibana, sin tocar la consola a mano.
```

---

### Tarea P4 · Suite E2E con Playwright

```
TAREA: Pruebas de navegador sobre el flujo completo del analista. Cierra F-04 y
el objetivo 3 de la materia. REQUIERE P1 y P2 terminadas.

ALCANCE:
  1. pytest-playwright, solo Chromium (Firefox/WebKit no aportan acá).
  2. Fixture de sesión que levanta el servidor y espera a /api/v1/healthz.
  3. network_logs/ y los .jsonl en tmp_path: las pruebas NUNCA tocan datos reales.
  4. UN SOLO flujo, el que se demuestra en la defensa:
       a. Login con credenciales válidas → llega al triage
       b. La tabla muestra los incidentes del fixture
       c. Filtrar por severidad CRITICAL → la tabla se reduce
       d. Click en un incidente → abre la pantalla de decisión con evidencia
       e. Aprobar una acción → el estado pasa a `approved` sin recargar
       f. Descartar otra con nota → aparece en el historial
       g. Recargar → los estados persisten (replay del registro)
       h. Logout → / redirige al login
  5. Una prueba de seguridad aparte: cargar el fixture con el source_ip
     malicioso de S-02 y afirmar que NO se dispara ningún diálogo y que el texto
     se ve literal en pantalla.

REGLAS PARA QUE NO SEA INESTABLE:
  - Esperar por selector, nunca por tiempo.
  - --retries=1, trazas y video solo --on-first-retry.
  - Datos fijos, no generados al azar.
  - Presupuesto: la suite E2E completa en menos de 150 segundos.

CRITERIO DE ACEPTACIÓN:
  Suite completa (SAST + unit + integración + E2E) en menos de 5 minutos.
```

---

### Tarea P5 · Triage y pantalla de decisión

```
TAREA: Consolidar el MVP presentable. Requiere P2.

ALCANCE:
  1. / → vista de triage: lista priorizada. Agregar sobre lo que ya existe:
     columna de antigüedad, indicador de acciones pendientes por incidente, y
     filtros persistidos en la URL (para compartir y para que Playwright navegue
     directo).
  2. /incident/<id> → pantalla de decisión como ruta propia (hoy es un panel
     lateral). Evidencia y factores del clasificador a la izquierda; análisis y
     acciones con Aprobar/Descartar a la derecha.
  3. Hacer que el falso_positivo_probabilidad sea imposible de pasar por alto:
     es el dato que decide si el analista aprueba o no.
  4. Reemplazar prompt() por un modal con textarea y contador (500 caracteres).
     prompt() no se estila, no se testea bien y bloquea el hilo.
  5. Pedir nota también al APROBAR, no solo al descartar (RF-SUP-04 [P]).
  6. Estado vacío honesto: distinguir "no hay incidentes" de "todavía no corriste
     el pipeline". El backend ya manda `missing: true`; la interfaz lo ignora.
  7. Mantener el aviso permanente de que el sistema no ejecuta nada.

CRITERIO DE ACEPTACIÓN:
  Las pruebas E2E de P4 cubren el flujo nuevo · ./scripts/check.sh en verde
```

---

### Tarea P6 · Integración continua

```
TAREA: Llevar scripts/check.sh a CI. Cierra RNF-MANT-06 de forma demostrable.

ALCANCE:
  .github/workflows/ci.yml (o el equivalente de la plataforma del grupo) con
  cuatro jobs:
      sast  : ruff · pylint(+scs) · bandit · gitleaks · eslint(+security)
      unit  : pytest tests/unit --cov --cov-fail-under=80
      integ : pytest tests/integration
      e2e   : pytest tests/e2e --browser chromium   (depende de que unit pase)

  sast, unit e integ en paralelo. e2e depende de unit: no tiene sentido abrir un
  navegador si la clasificación está rota.

  Agregar gitleaks: el repositorio ya tuvo secretos versionados una vez
  (hallazgos S1/S2 de la auditoría de junio). Esto evita la tercera.

  Publicar el reporte de cobertura como artefacto — sirve de evidencia para la
  materia sin tener que correr nada.

CRITERIO DE ACEPTACIÓN:
  Un push corre los cuatro jobs y quedan en verde, con el badge en el README.
```

---

### Tarea P7 · Contrato estable de la API

```
TAREA: Cerrar F-05 y completar RF-API-01.

ALCANCE:
  1. /api/v1/incidents debe devolver SIEMPRE las mismas claves, incluida
     `analyst_mode`, aunque haya 0 incidentes. Hoy siem_agent.py retorna
     temprano sin escribir el campo, y un consumidor programático se rompe con
     KeyError (pasó al verificar esta auditoría).
  2. Que siem_agent.py escriba analyst_mode incluso con 0 incidentes.
  3. Documentar el contrato completo en docs/16-api-rest.md: las 10 rutas, con
     ejemplos de request/response y todos los códigos de error.
  4. Devolver 409 Conflict si se decide una acción ya decidida con el mismo
     valor: ayuda a distinguir un doble clic de una revisión real.

PRUEBAS QUE TIENE QUE DEJAR:
  - Las claves de la respuesta son idénticas con 0, 1 y N incidentes.
  - 409 al repetir la misma decisión.

CRITERIO DE ACEPTACIÓN:
  Una prueba parametrizada verifica el contrato en los tres escenarios.
```

---

### Tarea P8 · Umbrales a configuración externa

```
TAREA: Sacar los umbrales del código. Cierra RNF-MANT-04 [P] y RNF-COMP-01 [P].

ALCANCE:
  1. BRUTE_FORCE_THRESHOLD (20), CRITICAL_FAILURE_COUNT (5000),
     PORT_SCAN_DISTINCT_PORTS (10) y la ventana de 24 h pasan a config.yaml o
     a variables de .env, con los valores actuales como default.
  2. Validar los valores al cargarlos: un umbral negativo o no numérico tiene
     que fallar al arrancar, con un mensaje claro.
  3. Documentar cada umbral con su justificación (ver P9).

CUIDADO CON:
  Hay pruebas que afirman los valores actuales (test_umbrales_declarados). Deben
  seguir verificando los DEFAULT, y sumarse otras que verifiquen la carga desde
  configuración.

CRITERIO DE ACEPTACIÓN:
  Cambiar un umbral en la configuración cambia la clasificación, sin tocar código.
```

---

### Tarea P9 · Documentar la lógica determinística

```
TAREA: Escribir docs/13-logica-deterministica.md.

POR QUÉ IMPORTA: los umbrales (20 fallos, 5000 para crítica, 10 puertos) hoy son
constantes sin fundamento escrito. Es lo primero que va a preguntar un evaluador,
y es el documento que sostiene todas las decisiones del clasificador.

CONTENIDO:
  1. Por qué 20 fallos y no 10 ni 50. Qué tasa de falsos positivos implica.
  2. Por qué 5000 eleva a crítica.
  3. Por qué 10 puertos distintos es un escaneo.
  4. Por qué la ventana es de 24 h, y por qué la misma en Elasticsearch y en
     network_logs/ (si no coincidieran, el conteo mentiría).
  5. Por qué se toma el MÁXIMO entre log_event_count y alert_event_count y no la
     suma: describen el mismo ataque desde dos ángulos.
  6. Por qué la identidad del incidente es la IP ATACANTE y no la víctima
     (hallazgo L-02: agruparlos al revés partía un ataque en dos incidentes).
  7. Por qué las campañas se correlacionan solo por IP de atacante (L-04).
  8. Qué pasa cuando un dato no valida: la acción se omite, no se emite un
     placeholder (S-01 y L-03).

CRITERIO DE ACEPTACIÓN:
  Cada constante del código tiene su párrafo, y el documento se puede leer sin
  abrir el código.
```

---

### Tarea P10 · Consolidar la documentación

```
TAREA: Cumplir el pilar 6 del plan: toda la documentación en /docs.

ALCANCE — mover y fusionar:
  DEPLOYMENT.md (raíz)  → fusionar en docs/03-instalacion-y-montaje.md
  brute_force.md (raíz) → fusionar en docs/05-simulaciones-de-ataque.md
  rules/rules.md        → docs/rules/ (o anexo de docs/07)
  .claude/claude-context/outputs/auditoria-*.md → docs/audit/
  Grupo4-ERS.docx, *.pdf → docs/ers/

ALCANCE — crear:
  docs/14-pruebas.md             estrategia de testing y cómo correr la suite
  docs/15-autenticacion-y-roles.md   (después de P1)
  docs/16-api-rest.md            contrato completo (ver P7)
  docs/17-guia-de-estilo.md      convenciones Python/JS y configuración del SAST

REGLA A HACER CUMPLIR:
  Fuera de /docs solo pueden quedar README.md, CLAUDE.md y CONTRIBUTING.md.
  Agregar un chequeo en CI que falle si aparece otro .md en la raíz.

CRITERIO DE ACEPTACIÓN:
  El índice de docs/README.md está al día y no hay enlaces internos rotos.
```

---

### Tarea P11 · Actualizar la ERS a v1.1.0

```
TAREA: Sincronizar la ERS con el código. NO es trabajo de código.

POR QUÉ IMPORTA: la ERS v1.0.0 (22-08-2026) declara 125 requisitos con su estado
verificado contra el repositorio. Las tres fases posteriores cambiaron varios, y
el documento quedó desactualizado. La cátedra audita el panel de Historial de
versiones de Google Docs, así que el hito tiene que quedar registrado ahí.

CAMBIOS DE ESTADO A REGISTRAR (de diferido/parcial a implementado):
  RF-DIF-07   [D] → [I]  cadena de resúmenes criptográficos del registro
  RQ-SEC-14   [P] → [I]  detección de manipulación externa del archivo
  RNF-MANT-06 [D] → [I]  capacidad de ser testeado (420 pruebas, 95 %)
  RQ-SEC-19   [P] → [I]  validación de esquema, ahora también en la ingesta
  RNF-CONF-01 [D] → [I]  madurez

AGREGAR A LA ERS:
  Los 7 endpoints nuevos (RF-API-01 a RF-API-03 especifican 3; hay 10), o
  declarar explícitamente que son extensiones no especificadas.

RECALCULAR: la tabla 12.4 de recuento por estado.

CRITERIO DE ACEPTACIÓN:
  ERS v1.1.0 congelada en el Historial de versiones, con el estado de cada
  requisito verificado contra el repositorio y no supuesto.
```

---

## Parte C · Reglas de trabajo (pegar siempre)

```
CÓMO TRABAJAR:

1. LEER PRIMERO. docs/auditoria/01-auditoria-integral.md y docs/10-plan-de-accion.md
   antes de escribir una línea. Los hallazgos tienen identificadores (S-01, L-02,
   A-04, API-01…) que se usan en todo el proyecto: usalos.

2. CORRER LA PUERTA ANTES Y DESPUÉS.
       export PYTHONPATH="$PWD/.devtools"
       ./scripts/check.sh
   Si está roja ANTES de tus cambios, arreglá eso primero o decilo. Si la rompés,
   no sigas: las líneas de base están en cero y cualquier hallazgo nuevo es tuyo.

3. NO ROMPAS LA NO-AUTONOMÍA. Ningún cambio puede introducir subprocess, os.system,
   eval, exec, paramiko, docker-py ni una ruta HTTP que ejecute algo. Si
   tests/test_no_autonomy.py falla, NO lo silencies: o el cambio introduce
   autonomía y hay que revertirlo, o es una decisión consciente que exige
   actualizar docs/10 §6, este prompt y CONTRIBUTING.md.

4. LAS PRUEBAS CONGELADAS SE DAN VUELTA, NO SE BORRAN. `pytest -m bug` colecta las
   que afirman un comportamiento incorrecto a propósito. Al corregir el bug, esa
   prueba falla: reescribila para que afirme el comportamiento nuevo y movela a
   un archivo de regresión nombrado por el hallazgo. El diff del test es la
   evidencia de qué cambió.

5. CADA CORRECCIÓN DEJA UNA PRUEBA QUE FALLA SI EL BUG VUELVE. No vale "lo probé a
   mano".

6. SI UNA PRUEBA FALLA, AVERIGUÁ QUIÉN TIENE RAZÓN. Varias veces en este proyecto
   el código estaba bien y la prueba mal (el `ufw deny` de phishing apunta al
   servidor, no a la víctima), y varias veces al revés (la coerción de `note`, la
   resincronización de la cadena). Decidilo mirando, no asumiendo.

7. FIXTURES CON FECHA FIJA: usá tests.conftest.eventos_de_red(). Un
   read_network_logs() directo sobre un fixture funciona hoy y falla mañana —ya
   pasó, rompió 4 pruebas al cambiar el día—. Hay una guarda que lo detecta.

8. NO TOQUES LOS DATOS REALES. decisions.jsonl, analysis_history.jsonl y
   network_logs/ del proyecto son datos del equipo. Toda prueba corre en tmp_path
   con el CWD cambiado (fixture `sandbox`). Para experimentar, usá un directorio
   temporal.

9. DOCUMENTÁ EN /docs, EN ESPAÑOL. Al terminar una tarea, actualizá
   docs/12-registro-de-pruebas.md con lo que se ejecutó y qué dio: resultados
   reales, no esperados. Si creás un documento, sumalo al índice de docs/README.md.

10. UNA TAREA POR VEZ, COMPLETA. Código + pruebas + documentación antes de pasar a
    la siguiente. Al terminar: decí qué se hizo, qué se verificó, qué encontraste
    que no estaba previsto, y qué quedó afuera.

11. SI ENCONTRÁS ALGO QUE NO ESTABA EN EL PLAN, DECILO. Las mejores correcciones de
    este proyecto salieron de hallazgos laterales: el verificador que gritaba
    "manipulación" ante registros simplemente viejos, la suite que se rompía sola
    al cambiar el día. No los arregles en silencio ni los ignores: reportalos.

12. HONESTIDAD SOBRE EL ESTADO. Si algo quedó a medias, decilo. Una entrega que
    declara con precisión qué hace y qué no vale más que una que promete de más.
    La ERS ya adopta ese criterio con sus marcas [I]/[P]/[D]: mantenelo.
```

---

## Orden recomendado

```
✅ P1 (login) ─┬──▶  P5 (triage y decisión)  ──┐
               │                               ├──▶  P4 (E2E Playwright)  ──▶  P6 (CI)
✅ P2 (R-05) ──┴───────────────────────────────┘

P3 (reglas como código)   ── independiente, alta prioridad para la demo
P7, P8, P9, P10           ── independientes, bajo esfuerzo
P11 (ERS v1.1.0)          ── al final, cuando el estado esté estabilizado
```

**Si hay poco tiempo antes de la entrega**, el orden que más mueve la aguja para
los objetivos de la materia es: **P11** (la ERS refleja la realidad: ya hay
**dieciséis** requisitos ganados sin registrar) → **P4** (pruebas de navegador,
desbloqueadas por P2) → **P6** (CI, que convierte todo en evidencia continua).
