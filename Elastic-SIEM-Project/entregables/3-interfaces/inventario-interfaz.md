# Inventario de la interfaz de usuario de NeuralDefender

Insumo para el plan de pruebas de interfaz con Playwright. No hay ninguna prueba nueva escrita. Todo sale de la lectura del código (`services/gateway/`), de la ERS (`Grupo4-ERS.docx`) y de corridas hechas el 23-11-2026 contra la malla aislada y contra `tests/interfaz`. Las rutas son relativas a `Elastic-SIEM-Project/`. Las líneas de `index.html`, `login.html`, `login.js` y `app.js` son las del código actual.

## Resumen

| Tema | Resultado |
|---|---|
| Pantallas reales | 2 páginas HTML (`/login` y `/`). Detalle de incidente, memoria, reportes y ayuda **no son páginas aparte**: viven dentro de `/` como paneles o desplegables |
| Selectores | No hay ningún `data-testid` (0 coincidencias en `services/gateway`). Casi todo lo interactivo tiene `id`, `data-accion` o un rol; los datos dinámicos (resumen, badges, tarjetas de lección) solo se alcanzan por clase CSS o texto |
| Roles | 3: `viewer` (observador), `analyst`, `auditor`. Los tres ven el mismo panel; cambia qué controles se muestran |
| Pruebas existentes | 13 en `tests/interfaz/test_panel.py`. Hoy se saltean todas por falta del Chromium de Playwright. Con el Chrome del sistema: 12 pasan y 1 falla |
| Entorno | Playwright 1.64.1 (módulo) y 1.65.2 (CLI) en `.devtools/`; navegadores de Playwright **no** instalados; Chrome y Chromium del sistema 154.0.8037.57 sí |
| Hallazgos para el plan | Ver sección 7 |

## 1. Pantallas y vistas

| # | Pantalla o vista | URL | Quién la ve | Archivo | Observación |
|---|---|---|---|---|---|
| P1 | Inicio de sesión | `GET /login` | Cualquiera sin sesión. Con sesión redirige a `/` (`dashboard.py:348-353`) | `templates/login.html`, `static/login.js` | Única ruta HTML pública |
| P2 | Panel principal (triage) | `GET /` | Cualquier usuario con sesión. Sin sesión responde 302 a `/login` (verificado con curl) | `templates/index.html`, `static/app.js` | Contiene P3 a P8 |
| P3 | Resumen superior | dentro de `/` | Los tres roles | `app.js:372-427` (`renderSummary`) | Pendientes, totales y leyenda por severidad |
| P4 | Tabla de eventos con filtros | dentro de `/` | Los tres roles | `index.html:65-82`, `app.js:429-476` | |
| P5 | Detalle de incidente | dentro de `/`, al elegir una fila | Los tres roles ven el detalle. Los botones Aprobar y Descartar solo los ve quien tiene el permiso `decidir` | `app.js:484-608` | No tiene URL propia |
| P6 | Barra lateral: Ataques recientes e Historial de decisiones | dentro de `/` | Los tres roles | `index.html:86-110`, `app.js:810-934` | |
| P7 | Reportes («Sacar un reporte») | desplegable en la barra lateral; descarga `GET /api/v1/reportes` | Los tres roles (el permiso es `ver_auditoria`, que tienen todos) | `index.html:95-109`, `app.js:1028-1039` | |
| P8 | Memoria del agente | tarjeta en la barra lateral | Lecciones y documentos: los tres roles. Botones y formularios: solo `decidir` | `index.html:111-152`, `app.js:935-1026` | |
| P9 | Ayuda («Cómo funciona este panel») | panel desplegable en la cabecera | Los tres roles | `index.html:16` y `24-60`, `app.js:1041` | No existe una pantalla de ayuda separada |
| P10 | Cuadro de confirmación | diálogo modal `<dialog id="confirmacion">` | Quien tiene `decidir` | `index.html:161-170`, `app.js:1127-1244` | Se abre antes de aprobar, descartar o revisar una lección |
| P11 | Aviso (toast) | `#toast` | Todos | `index.html:157`, `app.js:1055-1062` | Dura 3,2 s |

Roles y permisos (`services/auth/siem_auth.py:85-93`), confirmados el 23-11 con inicio de sesión real contra la malla:

| Rol | Usuario de la malla | Permisos | Efecto en la interfaz |
|---|---|---|---|
| `viewer` | `observador00` | `ver_incidentes`, `ver_auditoria` | `body.solo-lectura` oculta todo `.ctrl` (`app.css:235`): sin Aprobar, Descartar, formularios de memoria ni Aprobar/Rechazar lección |
| `analyst` | `analista00` | además `decidir` | Ve todos los controles |
| `auditor` | `auditor00` | `ver_incidentes`, `ver_auditoria`, `verificar_cadena` | Sin `decidir`, ve la misma interfaz de solo lectura que el observador. `GET /api/v1/audit/verify` responde 200 solo para este rol, pero **ningún elemento de la interfaz lo invoca** (0 coincidencias de `audit/verify` en `app.js`) |

Los tres roles obtuvieron 200 en `/api/v1/incidents`, `/decisions`, `/memoria` y `/reportes`; `/audit/verify` dio 403 para analista y observador. La contraseña de la malla es `PruebaMalla#2026` para los tres.

## 2. Elementos por pantalla y selector recomendado

Convenciones. **Estable** significa que tiene `id`, `data-accion` con atributos de identidad, un rol con nombre accesible o un texto fijo. **Frágil** significa que solo se alcanza por clase CSS o por posición. **Sin selector estable** significa que hay que construir uno por contexto o pedir un `data-testid` (ver sección 7).

### 2.1 Login (`login.html`, `login.js`)

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Formulario | `#form` | Estable | `login.html:20` |
| Campo usuario | `#username` o `get_by_label("Usuario")` | Estable | `login.html:21-23` |
| Campo contraseña | `#password` o `get_by_label("Contraseña")` | Estable | `login.html:25-26` |
| Botón enviar | `#enviar` o `get_by_role("button", name="Iniciar sesión")` | Estable. Durante el envío dice «Verificando…» y queda deshabilitado | `login.html:28`, `login.js:31-32` |
| Aviso de error | `#aviso` (`role="alert"`); clases `.aviso.error` o `.aviso.espera` | Estable | `login.html:31`, `login.js:18-21` |
| Marca y título | `h1` con texto «NeuralDefender» | Estable | `login.html:16` |
| Nota «La IA sugiere, el analista decide» | `.nota` | Frágil (clase) | `login.html:33-39` |

### 2.2 Cabecera y ayuda (`index.html`)

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Título | `h1` con «Panel de supervisión» | Estable | `index.html:14` |
| Enlace «Cómo funciona este panel» | `[data-accion="about"]` | Estable, pero es un `<span>` sin `role`, sin `tabindex` y sin estado `aria-expanded`: no se alcanza con teclado | `index.html:16`, `app.js:1257` |
| Panel de ayuda | `#aboutPanel`; abierto cuando tiene la clase `open` | Estable | `index.html:24`, `app.js:1042` |
| Usuario y rol de la sesión | `#sesion` y `#sesion .rol` | Estable | `index.html:17`, `app.js:211-218` |
| Botón «Cerrar sesión» | `#salir` | Estable | `index.html:18`, `app.js:227` |
| Distintivo del modo de análisis | `#modeBadge`. Textos: «IA (Gemma local)», «IA (Gemma en la nube)», «IA (Gemini)», «Fallback determinístico», «— sin análisis todavía —» | Estable (id y texto) | `index.html:19`, `app.js:333-346` |
| Última actualización | `#meta` («actualizado hh:mm:ss») | Estable | `index.html:20`, `app.js:348` |

### 2.3 Resumen y filtros

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Contenedor del resumen | `#summary` | Estable | `index.html:61` |
| Pendientes: número y leyenda | `#summary .principal .n` y `.l` («acción espera tu decisión», «acciones esperan tu decisión», «sin decisiones pendientes») | Frágil (clases) | `app.js:405-410` |
| Totales («N incidentes», «N acciones sugeridas») | `#summary .secundarias .par` | Frágil | `app.js:411-413` |
| Leyenda por severidad | `#summary .leyenda li` | Frágil | `app.js:415-420` |
| Estado vacío del resumen | `.resumen-vacio` («Sin incidentes en la ventana de 24 horas…») | Frágil | `app.js:376-380` |
| Texto «↻ auto cada 15s» | `.toolbar` | Frágil | `app.js:374` |
| Filtro de severidad | `#fSeverity` (opciones con valor `""`, CRITICAL, HIGH, MEDIUM, LOW) | Estable | `index.html:68-74` |
| Filtro de tipo de ataque | `#fType` (las opciones se arman con los tipos presentes) | Estable | `index.html:75-77`, `app.js:305-312` |
| Buscador por IP | `#fSearch` (placeholder «Buscar por IP…») | Estable. Sin etiqueta asociada: solo placeholder | `index.html:78` |

### 2.4 Tabla de eventos

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Contenedor | `#eventsTableWrap` | Estable | `index.html:80` |
| Tabla | `table.events`; columnas ID, Severidad, IP origen, Tipo de ataque, Regla disparada, Análisis de IA | Estable por clase de tabla | `app.js:436-438` |
| Fila de incidente | `tr[data-incidente="INC-…"]` o `get_by_role("button", name="Abrir el detalle del incidente INC-…")`. Tiene `role="button"` y `tabindex="0"` | Estable | `app.js:466-468` |
| Fila seleccionada | clase `selected` | Frágil | `app.js:454` |
| Badge de severidad | `.badge.b-CRITICAL` (o HIGH, MEDIUM, LOW) | Frágil | `app.js:119`, `471` |
| Marca «✔ resuelto» y «✔ IP bloqueada» | `.resuelto-tag` | Frágil | `app.js:458-460` |
| Icono de campaña | `.campaign-icon` (con `title` «Parte de una campaña de N incidentes») | Frágil | `app.js:456-457` |
| Estado vacío | `.empty` «No hay eventos que coincidan con el filtro.» | Frágil | `app.js:432` |

### 2.5 Detalle de incidente

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Contenedor | `#detailWrap` y, adentro, `.card` | Estable | `index.html:81`, `app.js:552` |
| Cabecera: severidad, tipo, id, origen | `.card-head .badge`, `.title`, `.id`, `.src` | Frágil | `app.js:560-566` |
| Botón «cerrar ✕» | `.card-head button[data-accion="seleccionar"]` | Estable | `app.js:565` |
| Banner de campaña con enlaces | `a[data-accion="seleccionar"][data-incidente]` | Estable | `app.js:643-651` |
| Aviso de bloqueo vigente | enlace al incidente origen, mismo selector | Estable | `app.js:629-640` |
| Ficha técnica (Detección, Eventos, MITRE, Falso pos., Ventana) | `.card-body .grid` con pares `.k` y valor | Frágil | `app.js:576-586` |
| Enlace MITRE | `a[href^="https://attack.mitre.org/techniques/"]` | Estable | `app.js:92-98` |
| Fuente del análisis (LLM o respaldo) | dentro de `.analysis` | Frágil | `app.js:499-513` |
| Análisis: «Qué pasó», «Metodología», «Riesgo en este entorno» | `.analysis p` con `.lbl` | Frágil | `app.js:589-593` |
| Factores de la severidad | `.factors li` | Frágil | `app.js:600-604` |
| Evidencia: botón de despliegue | `button[data-accion="evidencia"]` con `aria-expanded` y `aria-controls` | Estable | `app.js:684-686` |
| Lista de acciones | `.actions` y `.action` | Frágil | `app.js:605-608`, `708` |
| Estado de una acción | `.action .state` con texto «pendiente», «✔ aprobada», «✘ descartada», «✔ aplicada por regla» | Frágil por clase, estable por texto | `app.js:40-48`, `711` |
| Comando sugerido | `.cmd` («$ comando») y `.cmd-explain` | Frágil | `app.js:696-698` |
| **Aprobar** | `button[data-accion="decidir"][data-action-id="…"]` | Estable | `app.js:722-724` |
| **Descartar** | `button[data-accion="pedir-motivo"][data-action-id="…"]` | Estable | `app.js:725-727` |
| Marca de quién decidió | `.decided` («por analista · fecha · nota: …») | Frágil | `app.js:699-700` |
| Alternativas | `button[data-accion="alternativas"]` con `aria-expanded` (texto «Otras formas de hacerlo (N)») | Estable | `app.js:747-750` |
| Formulario del motivo | `#motivo-<action_id>` (textarea), botones `[data-accion="confirmar-descarte"]` («Confirmar descarte») y `[data-accion="cancelar-motivo"]` («Cancelar») | Estable | `app.js:794-808` |

### 2.6 Barra lateral

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Ataques recientes | `#recentAttacks .recent-item`; vacío «Sin actividad todavía.» | Frágil | `index.html:88`, `app.js:810-850` |
| Historial: contenedor | `#decisionHistory`; vacío «Todavía no se registraron decisiones.» | Estable | `index.html:92`, `app.js:857-860` |
| Historial: cabecera de un incidente | `button[data-accion="toggle-decisiones"][data-incidente]` con `aria-expanded` | Estable | `app.js:919-921` |
| Historial: detalle | `#dec-<incident_id>` y `.decision-sub` | Estable (id) y frágil (clase) | `app.js:905-916` |
| Reportes: desplegable | `details.reportes` con `summary` «Sacar un reporte» | Frágil (clase); el `summary` por texto es estable | `index.html:95-96` |
| Reportes: formulario | `#formReporte` | Estable | `index.html:97` |
| Reportes: fechas | `#repDesde` y `#repHasta` (`type="date"`, con `label for`) | Estable | `index.html:98-101` |
| Reportes: botones | `button[data-formato="csv"]` («Descargar CSV») y `button[data-formato="json"]` («Ver JSON») | Estable | `index.html:103-104` |

### 2.7 Memoria del agente

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Lecciones | `#memoriaLecciones`. Títulos «Propuestas para revisar (N)» y «Lo que ya aprendió (N)» | Estable (id) | `index.html:115`, `app.js:963-967` |
| Tarjeta de una lección | `.leccion.leccion-propuesta` o `.leccion-aprobada`; texto en `.leccion-texto` | Frágil. No tiene id por lección | `app.js:950-960` |
| Aprobar / Rechazar lección | `button[data-accion="revisar-leccion"][data-leccion="LEC-…"][data-decision="aprobar"\|"rechazar"]` | Estable | `app.js:954-957` |
| Mensajes vacíos | «Ninguna. El agente propone una cuando…», «Todavía nada aprobado.», «La memoria del agente no está disponible.» | Frágil | `app.js:938-967` |
| Documentos | `#memoriaDocumentos`, lista `.memoria-docs li`; vacío «Ninguno cargado.» | Estable (id) | `index.html:116`, `app.js:968-972` |
| Desplegable «Enseñarle algo al agente» | `summary` por texto | Estable por texto | `index.html:121` |
| Formulario de lección | `#formLeccion`; campos `#leccionTexto` (máx. 400, requerido), `#leccionTipo`, `#leccionIp` (máx. 64); botón «Proponer lección» | Estable. `#leccionIp` sin `<label>`, solo placeholder | `index.html:122-136` |
| Desplegable «Cargar un documento» | `summary` por texto | Estable por texto | `index.html:139` |
| Formulario de documento | `#formDocumento`; `#docTitulo` (máx. 120, requerido), `#docArchivo` (.txt/.md), `#docContenido` (máx. 32768); botón «Cargar documento» | Estable | `index.html:140-148` |

### 2.8 Diálogo de confirmación y aviso

| Elemento | Selector recomendado | Estado | Dónde |
|---|---|---|---|
| Diálogo | `dialog#confirmacion` (`aria-labelledby`), título `#confirmacionTitulo`, cuerpo `#confirmacionCuerpo` | Estable | `index.html:161-164` |
| Títulos | «Vas a aprobar esta acción», «Vas a descartar esta sugerencia», «Vas a aprobar esta lección», «Vas a rechazar esta lección» | Estable (texto) | `app.js:1199`, `1242` |
| Confirmar | `#confirmacionSi` (valor `si`) | Estable | `index.html:167` |
| Cancelar | `button[value="no"]` o `get_by_role("button", name="Cancelar")` dentro del diálogo | Estable por rol. **Sin id propio** y hay otros botones «Cancelar» en el panel (el del motivo): acotar al diálogo | `index.html:166` |
| Advertencias | `.confirmacion-avisos li` (ver 3.4) | Frágil | `app.js:1142-1147` |
| Aviso (toast) | `#toast` (`role="status"`); clases `.visible.ok` o `.visible.error` | Estable | `index.html:157`, `app.js:1055-1062` |

## 3. Flujos de usuario

Cada flujo tiene el resultado visible esperado según el código. Los mensajes entre comillas son literales.

### 3.1 Login (P1)

| Flujo | Pasos | Resultado visible | Fuente |
|---|---|---|---|
| L1 Válido | Usuario y contraseña correctos, Iniciar sesión | El botón pasa a «Verificando…», luego redirige a `/` | `login.js:31-47` |
| L2 Contraseña incorrecta | Usuario válido, contraseña errónea | `#aviso` con «usuario o contraseña incorrectos» (HTTP 401, verificado), campo contraseña vacío, botón vuelve a «Iniciar sesión» | `login.js:55-57` |
| L3 Usuario inexistente | Usuario que no existe | El mismo mensaje y el mismo 401 (no revela si el usuario existe) | verificado con curl |
| L4 Bloqueo por intentos | 5 fallos en 15 min | `#aviso` con clase `espera` y el mensaje del servidor (HTTP 429), o «Demasiados intentos. Esperá unos minutos.» si no trae mensaje | `login.js:52-54` |
| L5 Servidor caído | Red cortada | «No se pudo contactar al servidor.» | `login.js:58-59` |
| L6 Campos vacíos | Enviar sin llenar | El navegador bloquea el envío (`required`), sin llamada | `login.html:22,26` |
| L7 Sesión abierta | Ir a `/login` con sesión | Redirige a `/` | `dashboard.py:350-351` |

### 3.2 Panel: acceso, sesión y refresco (P2)

| Flujo | Resultado visible | Fuente |
|---|---|---|
| A1 `/` sin sesión | Redirige a `/login` (302 verificado) | `dashboard.py:471-474` |
| A2 Carga con sesión | `#sesion` muestra usuario y rol; `#modeBadge` el modo; la tabla se dibuja | `app.js:206-225` |
| A3 Cerrar sesión | Redirige a `/login`; `/` vuelve a pedir login | `app.js:227-233` |
| A4 Sesión expirada o cerrada en otra pestaña | Cualquier llamada con 401 manda a `/login` | `app.js:208`, `256-258` |
| A5 Refresco cada 15 s | `#meta` se actualiza; no repinta si los datos no cambiaron ni mientras se escribe | `app.js:253-275`, `1303` |
| A6 Rol sin `decidir` | Sin botones Aprobar/Descartar ni formularios de memoria | `app.js:221-223`, `app.css:235` |
| A7 Expiración por inactividad (30 min) o por duración (8 h) | La siguiente llamada devuelve 401 y la interfaz redirige | `sesion_web.py:36-37`, `156-158` |

### 3.3 Triage: filtrar y abrir el detalle (P3, P4, P5)

| Flujo | Resultado visible |
|---|---|
| T1 Filtrar por severidad | La tabla muestra solo esa severidad |
| T2 Filtrar por tipo de ataque | Solo ese tipo; las opciones salen de los tipos presentes |
| T3 Buscar por IP | Filtra por `source_ip` o `attacker_ips` (subcadena, sin distinguir mayúsculas) |
| T4 Filtros combinados | Se aplican los tres a la vez |
| T5 Filtro sin resultados (inválido) | `.empty`: «No hay eventos que coincidan con el filtro.» |
| T6 Filtro tras el refresco | Se conserva (los controles están fuera de lo que se repinta) |
| T7 Abrir el detalle con clic | `.card` en `#detailWrap`, fila con clase `selected`, se desplaza hasta la tarjeta |
| T8 Abrir con teclado (Enter o Espacio sobre la fila) | Igual que el clic |
| T9 Cerrar el detalle | «cerrar ✕» o clic de nuevo en la misma fila |
| T10 Navegar por un enlace de campaña o de bloqueo vigente | Abre el incidente relacionado |
| T11 Desplegar la evidencia y las alternativas | Cambia `aria-expanded` y se muestra u oculta el cuerpo |
| T12 Sin incidentes | `.resumen-vacio` y `.empty` |

Fuente: `app.js:316-330`, `478-482`, `1246-1301`.

### 3.4 Decidir una acción (P5, P10, P11)

| Flujo | Pasos | Resultado visible |
|---|---|---|
| D1 Aprobar con confirmación | Aprobar, el diálogo «Vas a aprobar esta acción», Confirmar | Toast «✔ Acción aprobada» (clase `ok`); el estado de la acción pasa a «✔ aprobada»; la fila muestra «✔ resuelto»; el historial suma la decisión; el resumen baja los pendientes. Si el agente propone lecciones, el toast agrega «· el agente propuso N lección(es) para revisar» |
| D2 Cancelar la confirmación | Aprobar, Cancelar (o Escape) | No hay llamada ni cambio; la acción sigue «pendiente» |
| D3 Descartar con motivo | Descartar, escribir el motivo, Confirmar descarte, diálogo «Vas a descartar esta sugerencia», Confirmar | Toast «✘ Acción descartada»; estado «✘ descartada»; el motivo se guarda como nota y aparece en `.decided` |
| D4 Descartar sin motivo | Igual, con el textarea vacío | El diálogo agrega la advertencia «Descartás sin motivo: la próxima vez que aparezca esta IP, ni vos ni el agente van a saber por qué.»; se puede confirmar igual |
| D5 Cancelar el motivo | Descartar, Cancelar | El formulario se cierra; nada se registra |
| D6 Cancelar en el diálogo después de escribir el motivo | Confirmar descarte, Cancelar | No se registra; el motivo escrito se conserva (no se cierra `pidiendoMotivo`) |
| D7 Decisión sobre una acción ya decidida | Aprobar una acción ya descartada | Advertencia «Esta acción ya estaba … por …. Tu decisión la reemplaza; la anterior queda en el registro.» |
| D8 Advertencias de riesgo | Aprobar con falso positivo ALTO o impacto alto | «La probabilidad de falso positivo es ALTA: confirmá la evidencia antes de aprobar.» y «La acción tiene impacto ALTO sobre el servicio.» |
| D9 Falla del servidor | Respuesta de error de `POST /api/v1/decision` | Toast de clase `error` con el mensaje del servidor o «No se pudo registrar la decisión.»; la acción sigue pendiente |
| D10 Sin permiso | Un `viewer` o `auditor` fuerza la llamada | HTTP 403 con `permiso_requerido: decidir`. En la interfaz los botones no existen |
| D11 Sesión vencida al decidir | 401 | Redirige a `/login` |
| D12 Bloqueo vigente | IP ya bloqueada en otro incidente | Acción «✔ aplicada por regla», marca «✔ IP bloqueada» en la fila |

Fuente: `app.js:1064-1125`, `1149-1244`, `dashboard.py:514-646`.

### 3.5 Historial y reportes (P6, P7)

| Flujo | Resultado visible |
|---|---|
| H1 Historial vacío | «Todavía no se registraron decisiones.» |
| H2 Desplegar un incidente del historial | `aria-expanded="true"`; aparece `#dec-<id>` con cada decisión («✔ Aprobada» o «✘ Descartada», quién y hora) |
| H3 Historial con revisiones | Marca «(revisado N×)» |
| H4 Máximo 10 grupos | Solo se muestran los 10 incidentes más recientes (`app.js:895`) |
| R1 Descargar CSV sin fechas | Navega a `/api/v1/reportes?formato=csv`; el navegador descarga el archivo |
| R2 Descargar CSV con rango | Agrega `desde` y `hasta` a la URL |
| R3 Ver JSON | Abre una pestaña nueva con `formato=json` |
| R4 Fechas inválidas o rango invertido | No hay validación en el cliente; lo resuelve el servidor (no verificado) |
| R5 Neutralización de fórmulas en el CSV | Las celdas que empiezan con `=`, `+`, `-`, `@`, tabulación o retorno de carro llevan apóstrofo inicial (`reportes.py`, `_INICIO_DE_FORMULA`) |

Fuente: `app.js:1028-1039`, `851-934`.

### 3.6 Memoria del agente (P8)

| Flujo | Resultado visible |
|---|---|
| M1 Proponer una lección válida | Toast «Lección propuesta: falta que un analista la apruebe»; aparece en «Propuestas para revisar (N)» |
| M2 Lección vacía o de más de 400 caracteres | El navegador bloquea (`required`, `maxlength=400`) |
| M3 Lección con tipo y/o IP | Se guarda acotada |
| M4 Aprobar una lección | Diálogo «Vas a aprobar esta lección»; al confirmar, toast «✔ Lección aprobada: el agente la va a usar desde el próximo análisis…»; pasa a «Lo que ya aprendió» |
| M5 Rechazar una lección | Diálogo «Vas a rechazar esta lección»; la lección sale de las propuestas |
| M6 Cancelar la revisión | Sin cambios |
| M7 Aprobar la lección propia | El diálogo agrega una advertencia por `propuesta_por === usuario` |
| M8 Revisar una lección ya revisada | El servidor responde 400; toast `error` con el mensaje del servidor |
| M9 Cargar un documento por texto | Toast «Documento cargado: el agente lo consulta desde el próximo análisis»; aparece en «Documentos (N)» |
| M10 Cargar un archivo de más de 32 KB | Toast `error` «El archivo supera los 32 KB.»; no se envía |
| M11 Título vacío o de más de 120 caracteres | El navegador bloquea (`required`, `maxlength`) |
| M12 Servicio knowledge caído | «La memoria del agente no está disponible.»; el resto del panel sigue |
| M13 Rol sin `decidir` | Formularios y botones ocultos; las listas siguen visibles |

Fuente: `app.js:935-1026`, `1204-1244`.

### 3.7 Seguridad visible en la interfaz

| Flujo | Resultado visible |
|---|---|
| S1 Dato hostil de un log o del LLM | Se muestra como texto, no se ejecuta (`html` escapa por construcción: `app.js:142-164`) |
| S2 La interfaz no ejecuta comandos | Los comandos aparecen como texto en `.cmd`; aprobar solo registra |

## 4. Requisitos de la ERS

Los identificadores se tomaron de `Grupo4-ERS.docx`. Definiciones abreviadas.

| Requisito | Qué exige | Pantallas y flujos |
|---|---|---|
| RF-SUP-01 | Vista de triage con id, severidad, IP, tipo y resumen del análisis | P4, A2, T12 |
| RF-SUP-02 | Filtrar por severidad, tipo e IP, de forma combinable | T1 a T6 |
| RF-SUP-03 | Ficha de detalle con análisis, factores y acciones | P5, T7 a T11 |
| RF-SUP-04 | Aprobar o descartar cada acción, con nota | D1, D3, D4 |
| RF-SUP-05 | No ejecutar nunca los comandos; solo registrar | S2, D1 |
| RF-SUP-06 | Señalar campañas con enlaces a los incidentes relacionados | T10 |
| RF-SUP-07 | Actualizar cada 15 s reconstruyendo desde el registro | A5 |
| RF-SUP-08 | Indicar si el análisis fue del LLM o del respaldo | `#modeBadge`, fuente del análisis en P5 |
| RF-SUP-09 | Cuadro de confirmación antes de decidir una acción o una lección | P10, D1 a D8, M4 a M7 |
| RF-SUP-10 | Marcar como «aplicada automáticamente» el bloqueo de una IP ya aprobada | D12 |
| RF-AUT-01 | Autenticación para todo salvo login y salud | L1 a L7, A1, A4 |
| RF-AUT-02 | Tres roles; las vistas exigen un permiso, no un rol | Sección 1, A6, D10, M13 |
| RF-AUT-04 | Bloqueo tras 5 intentos fallidos en 15 minutos | L4 |
| RF-AUT-06 | Cada decisión se firma con el usuario y el rol de la sesión | D1 (el analista aparece en `.decided` y en el historial) |
| RF-MEM-01 | Cada decisión es un caso en la memoria | D1, D3 (efecto visible: toast con lecciones propuestas) |
| RF-MEM-02 | Un patrón repetido propone una lección | D1 (toast), M1 |
| RF-MEM-03 | Un analista propone una lección a mano (hasta 400 caracteres, tipo e IP opcionales) | M1 a M3 |
| RF-MEM-04 | Toda lección nace «propuesta» y no se aplica hasta aprobarse | M1, M4, M5, M8 |
| RF-MEM-05 | Cargar documentos de texto o Markdown (32 KB, 50 en total) | M9 a M11 |
| RF-MEM-06 | El agente recupera lecciones, casos y documentos antes de analizar | Bloque «Memoria del agente» del detalle (`renderAprendizaje`) |
| RF-MEM-07 | Una lección aprobada solo ajusta el falso positivo | Texto «ajustado por la lección…» en la ficha |
| RF-MEM-08 | Sin memoria el análisis continúa e indica que no se pudo consultar | M12 y «La memoria no estaba disponible cuando se analizó este incidente.» |
| RF-REP-01 | Reporte de decisiones y actividad, filtrable por fechas, CSV o JSON | R1 a R3 |
| RF-REP-02 | Resúmenes y verificación de cadena en el reporte | R3 (contenido del JSON) |
| RF-REP-03 | Neutralizar fórmulas en el CSV | R5 |
| RF-REP-04 | Registro encadenado de documentos y lecciones | M1, M4, M5, M9 (efecto interno; en la interfaz solo se ve en el reporte) |
| RQ-SEC-10 | Escapar todo contenido externo al renderizar | S1 |
| RQ-SEC-13 | Sesión: 30 min de inactividad o 8 h de duración | A7 |
| RNF-USA-01 | Resumen superior con totales y pendientes | P3 |
| RNF-USA-02 | Tipo y gravedad visibles sin abrir el detalle | P4: ícono, badge y extracto |
| RNF-USA-03 | Revisar y decidir en no más de tres interacciones | T7 y D1 (seleccionar fila, aprobar, confirmar) |
| RNF-USA-04 | Ayuda accesible desde la cabecera | P9 |
| RNF-USA-05 | Filtros combinables que se conservan tras el refresco | T4, T6 |
| RNF-USA-06 | Explicación y probabilidad de falso positivo junto a cada comando | `.cmd-explain` y «Falso pos.» en P5 |
| RNF-USA-07 | Color estable por severidad e ícono por tipo | `.badge.b-*`, `attackIcon` |
| RNF-USA-08 | Navegación completa por teclado y WCAG 2.1 AA | T8; **ver hallazgo H-2 de la sección 7** |
| RNF-USA-09 | Si falla el registro, informarlo y mantener la acción pendiente | D9 |
| RNF-RD-06 | Máximo 100 incidentes por vista | **Ver hallazgo H-3 de la sección 7** |

RF-AUT-03, RF-AUT-05 y RF-AUT-07 no tienen interfaz propia (contraseñas, alta por línea de comandos y auditoría del login); el formulario de login solo los toca de forma indirecta.

## 5. Pruebas existentes en `tests/interfaz`

Archivos: `conftest.py` (74 líneas), `test_panel.py` (212 líneas) y `__init__.py`. El documento `pruebas_de_interfaz.md`, que el código cita para instalar, **no existe** en el repositorio.

| # | Prueba (línea) | Qué cubre | Mapea a |
|---|---|---|---|
| 1 | `test_sin_sesion_el_panel_manda_al_login` (44) | `/` sin sesión redirige a `/login` | A1 |
| 2 | `test_contrasena_incorrecta_muestra_el_error_y_vacia_el_campo` (50) | Mensaje de error y campo vacío | L2 |
| 3 | `test_login_correcto_muestra_usuario_rol_e_incidentes` (62) | Usuario y rol en `#sesion`, tabla con filas, sin errores de consola | A2 |
| 4 | `test_cerrar_sesion_vuelve_al_login_y_corta_el_acceso` (70) | Cerrar sesión | A3 |
| 5 | `test_el_buscador_filtra_la_tabla` (80) | Filtro por IP | T3 |
| 6 | `test_clic_en_una_fila_abre_el_detalle_con_sus_acciones` (92) | Abrir el detalle | T7 |
| 7 | `test_una_fila_se_abre_con_el_teclado` (104) | Enter sobre la fila | T8 |
| 8 | `test_cancelar_la_confirmacion_no_registra_nada` (115) | Cancelar el diálogo | D2 |
| 9 | `test_aprobar_con_confirmacion_queda_en_pantalla_y_en_el_registro` (130) | Aprobar | D1 |
| 10 | `test_descartar_pide_motivo_y_lo_guarda` (147) | Descartar con motivo | D3 |
| 11 | `test_un_viewer_no_ve_los_botones_de_decision` (166) | Rol de solo lectura | A6 |
| 12 | `test_un_analisis_de_gemma_se_identifica_en_pantalla` (177) | Distintivo del modo de análisis | RF-SUP-08 |
| 13 | `test_un_texto_hostil_del_llm_se_muestra_como_texto_y_no_se_ejecuta` (197) | Escape de HTML | S1 |

Cómo corren: `pytest-playwright` 0.10.0 con Chromium; el panel se sirve con HTTP real en un puerto efímero sobre el `dashboard` del sandbox (con CSRF encendido) y una malla en proceso con usuarios de prueba (por ejemplo `ana`). No usan la malla del puerto 18080. Si falta Playwright o Chromium, se saltean (`conftest.py:26-33`). El proyecto las incluye en `scripts/pruebas_completas.sh`.

No hay pruebas de: filtros por severidad y por tipo, filtros combinados, estados vacíos, descartar sin motivo, advertencias del diálogo, alternativas, historial, reportes, memoria (lecciones y documentos), refresco de 15 s, bloqueo por intentos, expiración de sesión, rol auditor, accesibilidad ni diseño responsivo.

**Resultado de hoy (23-11-2026):**

| Corrida | Resultado |
|---|---|
| `python3 -m pytest tests/interfaz` tal como está | 13 saltadas: «falta Chromium: python3 -m playwright install chromium» |
| Con el Chrome del sistema (`--browser-channel chrome` y una carpeta de navegadores temporal, ver sección 6) | **12 pasan y 1 falla** |

La que falla es la 3 (`test_login_correcto_muestra_usuario_rol_e_incidentes`). Falla en `assert errores_de_consola == []` por `Failed to load resource: the server responded with a status of 404`. La traza del servidor lo identifica: `GET /favicon.ico 404`. Ninguna plantilla declara un `<link rel="icon">` y Chrome pide el favicon por su cuenta. Es un hallazgo de la interfaz y no un error de la prueba (ver H-1).

## 6. Entorno

### Qué hay instalado

| Componente | Estado |
|---|---|
| Playwright (Python) | En `.devtools/` (requiere `PYTHONPATH=.devtools`). `importlib.metadata` informa 1.64.1 y `python3 -m playwright --version` informa 1.65.2: hay dos versiones en la carpeta |
| `pytest-playwright` | 0.10.0, en `.devtools/` |
| Chromium de Playwright | **No instalado.** `~/.cache/ms-playwright` no existe. El ejecutable esperado, `~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`, no está |
| Navegadores del sistema | `/usr/bin/chromium` y `/usr/bin/google-chrome`, ambos 154.0.8037.57 |
| Instalar el de Playwright | `PYTHONPATH=.devtools python3 -m playwright install chromium` (no lo ejecuté: descarga cientos de MB) |

### Usuarios de la malla

La malla (`./entregables/2-servicios/postman/malla.sh iniciar`) sirve el gateway en `http://127.0.0.1:18080`.

| Rol | Usuario | Contraseña |
|---|---|---|
| analyst | `analista00` | `PruebaMalla#2026` |
| viewer | `observador00` | `PruebaMalla#2026` |
| auditor | `auditor00` | `PruebaMalla#2026` |

La malla trae 3 incidentes. Los datos son temporales y se descartan al detenerla (`malla.sh reiniciar` vuelve al estado inicial). Un usuario que falle 5 veces queda bloqueado (L4); reiniciar la malla lo limpia. Durante este inventario hice dos intentos de login fallidos con curl (uno con `analista00` y uno con un usuario inexistente).

Estado de la malla durante este trabajo: había procesos de la malla corriendo en los puertos 18001 a 18007 y 18080, propiedad de `root`, mientras `malla.sh estado` decía «Malla detenida» y `malla.sh detener` decía «La malla no está corriendo» (el archivo `.malla.pid` no coincide con el proceso). Hay que bajar ese proceso (con `sudo`) o `malla.sh iniciar` va a fallar por «El puerto … ya está en uso». No lo toqué.

### Cómo correr Playwright contra la malla

Los datos de la malla son efímeros, así que las pruebas contra el puerto 18080 deberían partir de `malla.sh reiniciar` y usar el login de cada rol por la pantalla.

```bash
cd Elastic-SIEM-Project
./entregables/2-servicios/postman/malla.sh reiniciar
export PYTHONPATH=$PWD/.devtools
# Con un script propio (sync_api):
#   p.chromium.launch(channel="chrome")   -> usa el Chrome del sistema
#   page.goto("http://127.0.0.1:18080/login")
```

### Cómo correr las pruebas existentes hoy

Las de `tests/interfaz` levantan su propio servidor; no necesitan la malla. Para correrlas sin instalar el Chromium de Playwright usé el Chrome del sistema:

```bash
export PYTHONPATH=$PWD/.devtools
mkdir -p /tmp/pw/chromium-1255/chrome-linux64
ln -sf /usr/bin/chromium /tmp/pw/chromium-1255/chrome-linux64/chrome
PLAYWRIGHT_BROWSERS_PATH=/tmp/pw python3 -m pytest tests/interfaz --browser-channel chrome
```

El enlace solo existe para que el `skip` de `conftest.py:29-33` encuentre un ejecutable; las pruebas usan Chrome por el canal. Resultado de esta forma: 12 pasan, 1 falla (sección 5).

### Grabar con codegen contra la malla

```bash
cd Elastic-SIEM-Project
./entregables/2-servicios/postman/malla.sh reiniciar
PYTHONPATH=$PWD/.devtools python3 -m playwright codegen \
  --channel chrome --target python \
  -o entregables/3-interfaces/grabacion.py.txt \
  http://127.0.0.1:18080/login
```

`--channel chrome` y `--target python` existen en este Playwright (verifiqué las opciones con `codegen --help`). **No lo ejecuté**: necesita pantalla. El archivo de salida lleva la extensión `.py.txt` para que ruff, bandit y `tests/test_no_autonomy.py` no lo tomen como código del producto; al pasarlo a prueba real se renombra a `.py` y se acomoda a las convenciones de `tests/interfaz`. Conviene grabar un rol por vez, iniciando sesión desde la pantalla.

## 7. Hallazgos para el plan

| # | Hallazgo | Evidencia | Relevancia |
|---|---|---|---|
| H-1 | `/favicon.ico` devuelve 404 y hace fallar la prueba que exige consola limpia | `curl` a `/favicon.ico` en la malla: 404. Prueba 3 de `tests/interfaz` | Hay que decidir si se agrega el icono o si las pruebas ignoran ese 404 |
| H-2 | «Cómo funciona este panel» es un `<span data-accion="about">` sin `role`, `tabindex` ni `aria-expanded`: no se abre con teclado | `index.html:16` | RNF-USA-08 (teclado) y RNF-USA-04 (ayuda) |
| H-3 | No encontré tope de 100 incidentes por vista: `renderEventsTable` pinta todos los filtrados. Los únicos recortes de la interfaz son 8 (ataques recientes) y 10 (historial) | `app.js:429-446`, `826`, `895`; sin coincidencias de un límite de 100 en `dashboard.py`. No revisé si un servicio interno lo aplica antes | RNF-RD-06. La prueba necesita datos con más de 100 incidentes |
| H-4 | No hay ningún `data-testid`. Resumen, badges, tarjetas de lección y de acción, y el historial solo se alcanzan por clase o texto | Búsqueda en `services/gateway`: 0 | Elegir entre selectores por clase y texto, o pedir atributos (cambio de código) |
| H-5 | `#fSearch` y `#leccionIp` no tienen `<label>`, solo placeholder | `index.html:78`, `134` | RNF-USA-08 (etiquetado) |
| H-6 | El botón «Cancelar» del diálogo no tiene id y comparte texto con el «Cancelar» del formulario del motivo | `index.html:166`, `app.js:805` | Los selectores tienen que acotarse al `dialog#confirmacion` |
| H-7 | La verificación de la cadena de auditoría (`/api/v1/audit/verify`, permiso `verificar_cadena`) no tiene elemento en la interfaz; el auditor ve lo mismo que el observador | 0 coincidencias en `app.js` | El rol auditor casi no se distingue en la interfaz; los flujos del auditor son de solo lectura |
| H-8 | `pruebas_de_interfaz.md` no existe pero el código lo cita | `conftest.py:14` | Documentación faltante |
| H-9 | El formulario de reportes no valida las fechas en el cliente: un rango invertido o inválido depende del servidor | `app.js:1028-1039` | R4 queda sin verificar |
| H-10 | Hay dos versiones de Playwright en `.devtools/` (1.64.1 por importación, 1.65.2 por la CLI) | `importlib.metadata` y `python3 -m playwright --version` | Fijar una versión antes de grabar y de correr la evidencia |
