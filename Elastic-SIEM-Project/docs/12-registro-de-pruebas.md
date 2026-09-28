# 12 · Registro de pruebas

> **Qué es.** El registro vivo de toda verificación que se corre sobre SIEM-IA:
> análisis estático (SAST) y pruebas de servicio. Se actualiza en cada fase, con
> los resultados reales de la corrida, no con los esperados.
>
> **Última actualización:** 25-09-2026, tareas **D1** y **D1.5**.
>
> Los otros dos documentos de pruebas cubren cosas distintas: el
> [reporte de la Fase 0](11-reporte-fase-0.md) explica **cómo se construyó** la
> red de seguridad, y el [plan de acción](10-plan-de-accion.md) §4 define la
> **estrategia**. Este registra **qué se ejecutó y qué dio**.

---

## 1. Estado actual, de un vistazo

| Indicador | Fase 0 | Fase 2 | P1 (auth) | P2 (R-05) | **P3 (reglas)** | Objetivo |
|-----------|:------:|:------:|:---------:|:---------:|:---------------:|----------|
| Pruebas que pasan | 119 | 418 | 548 | 571 | **724** | — |
| Tiempo de la suite | 1,3 s | 7,1 s | 41,8 s | 47,4 s | **75 s** | < 5 min ✅ |
| Puerta completa (SAST + pruebas) | 17 s | 27,9 s | 103,7 s | 119,5 s | **~150 s** | < 5 min ✅ |
| Cobertura (alcance §4.1) | 90 % | 95 % | 95 % | 95 % | **95 %** | ≥ 80 % ✅ |
| Bugs congelados pendientes | 24 | 2 | 0 | 0 | **0** | 0 ✅ |
| pylint + secure-coding-standard | 9,19 | 9,51 | 9,65 | 9,65 | **9,65** | ≥ 9,0 ✅ |
| bandit severidad alta | 2 | 0 | 0 | 0 | **0** | 0 ✅ |
| ruff en el código del proyecto | 12 | 0 | 0 | 0 | **0** | 0 ✅ |
| Líneas de JS analizadas por ESLint | 0 | 0 | 65 | 649 | **649** | > 0 ✅ |
| **Reglas de detección versionadas** | 0 | 0 | 0 | 0 | **13 / 13** | 13 ✅ |

> **`pytest -m bug` ya no colecta nada.** Los 24 bugs identificados en el
> [plan de acción](10-plan-de-accion.md) están cerrados, cada uno con su prueba
> de regresión. La deuda registrada quedó saldada.
>
> El salto de tiempo (7 → 42 s) es **Argon2id haciendo su trabajo**: cada login
> de prueba cuesta deliberadamente. Es el precio correcto y sigue muy por debajo
> del presupuesto de 5 minutos.

Cómo reproducir todo:

```bash
export PYTHONPATH="$PWD/.devtools"
./scripts/check.sh            # SAST + pruebas
./scripts/check.sh --sast     # solo análisis estático
./scripts/check.sh --tests    # solo pruebas
python3 audit_verify.py       # integridad del registro de auditoría
```

---

## 2. Inventario de pruebas

| Archivo | Pruebas | Qué verifica | Tipo |
|---------|--------:|--------------|------|
| `tests/unit/test_validators.py` | 91 | Validadores de entrada no confiable (S-01) | Unitaria |
| `tests/unit/test_s01_inyeccion_comandos.py` | 57 | Inyección de comando por copiar-pegar | Unitaria |
| `tests/integration/test_api_v1.py` | 38 | Contrato de `/api/v1/` (API-02…05) | **Servicio** |
| `tests/unit/test_b0x_robustez_y_formatos.py` | 37 | Robustez del acceso a datos (B-01…B-05) | Unitaria |
| `tests/test_no_autonomy.py` | 34 | Certificación de no-autonomía por AST | Estático |
| `tests/integration/test_a02_a04_integridad.py` | 35 | Cadena de hash, locking, `action_id`, tramo heredado | **Servicio** |
| `tests/unit/test_siem_lib_caracterizacion.py` | 26 | Módulo común: E/S, saneamiento | Unitaria |
| `tests/unit/test_classifier_caracterizacion.py` | 21 | Comportamiento del Agente 1 y forma del incidente | Unitaria |
| `tests/integration/test_api_caracterizacion.py` | 19 | Contrato histórico de la API | **Servicio** |
| `tests/unit/test_l01_l02_identidad_y_conteo.py` | 15 | Identidad del incidente y conteo | Unitaria |
| `tests/integration/test_a01_reset_preserva_auditoria.py` | 12 | `reset.sh` real contra un sandbox | **Servicio** |
| `tests/integration/test_auditoria_append_only.py` | 7 | Invariantes del registro append-only | **Servicio** |
| `tests/unit/test_gestion_usuarios.py` | 66 | Almacén de usuarios, validación, hashing, CLI | Unitaria |
| `tests/integration/test_api01_autenticacion.py` | 60 | Acceso, roles, sesión, CSRF, fuerza bruta | **Servicio** |
| `tests/unit/test_s02_xss_dashboard.py` | 51 | XSS, plantilla etiquetada `html`, accesibilidad | Unitaria + Node |
| `tests/unit/test_reglas_como_codigo.py` | 130 | Catálogo de reglas versionado: formato, MITRE, `.keyword` | Unitaria |
| `tests/unit/test_alertas_por_regla.py` | 17 | Una regla ruidosa no tapa a las demás (D-01) | Unitaria |
| `tests/unit/test_rol_del_valor_agrupado.py` | 28 | Atacante vs. víctima en las alertas (D-02) | Unitaria |
| `tests/integration/test_despliegue_de_reglas.py` | 23 | `deploy-rules.sh` contra un Kibana simulado | **Servicio** |

`tests/unit/test_classifier_bugs_congelados.py` se **eliminó** en esta fase: ya no
quedaba ningún bug del clasificador sin corregir.

Selección por marca:

```bash
pytest -m "not bug"   # 769 pruebas · deben estar SIEMPRE verdes
pytest -m bug         #   0 pruebas · no queda ningún bug congelado
```

---

## 3. Pruebas de código estático (SAST)

### 3.1 Resultado de la última corrida

| Herramienta | Configuración | Alcance | Resultado |
|-------------|---------------|---------|-----------|
| **pylint** + `pylint-secure-coding-standard` | `.pylintrc` | 9 módulos Python | **9,51/10** ✅ |
| **bandit** | `.bandit` | Código del proyecto | **0 HIGH** · 2 LOW justificados |
| **ruff** | `ruff.toml` | Todo el repo | **0** ✅ |
| **ESLint** + `security` + `no-unsanitized` | `eslint.config.js` | `static/**/*.js` | 0 errores ✅ |

### 3.2 Hallazgos cerrados en la Fase 2

| Herramienta | Hallazgo | Cómo se cerró |
|-------------|----------|---------------|
| bandit `B324` ×2 | SHA-1 en `_incident_id` y `_link_campaigns` | Pasaron a `sha256(..., usedforsecurity=False)`. **Efecto colateral: todos los `incident_id` cambiaron de sufijo** — un corte por única vez, consciente y documentado (§6) |
| pylint `R8005` ×2 | `open()` al escribir el registro append-only | `append_jsonl` y `write_json` usan `os.open` con modo explícito (`0600`), que era además la corrección de A-02 |
| pylint `W1510` | `subprocess.run` sin `check=` | `check=False` explícito en `siem_pipeline.py` |
| ruff ×12 | Imports desordenados, modos redundantes, import sin usar | Corregidos con los refactors R-01…R-04 |

> **Lo que el plugin de seguridad acertó por su cuenta.** `R8005` señalaba
> `siem_lib.py:180` y `:186` — exactamente `write_json` y `append_jsonl`, el
> escritor del registro de auditoría — sin que se lo hubiera configurado para
> eso. Confirmó de forma independiente que A-02 estaba bien priorizado.

### 3.3 Los 2 hallazgos que quedan, y por qué

```
[LOW] B404 ./siem_pipeline.py:18  import de subprocess
[LOW] B603 ./siem_pipeline.py:38  subprocess call
```

Son la allowlist de no-autonomía: la única ejecución de procesos del sistema,
con comandos literales, sin shell y sin datos de log de por medio. Están
justificados en `tests/test_no_autonomy.py` §4 y verificados por cuatro pruebas
específicas. La puerta cuenta solo severidad alta, así que no la bloquean.

### 3.4 Verificación de que el SAST realmente detecta

Una puerta que nunca falla no protege. Comprobado dos veces:

- **Fase 0** — se inyectó un `hashlib.md5()` en `siem_lib.py`:
  `ruff FALLA 13 (base 12)` · `bandit FALLA 3 (base 2)`. Verde al revertir.
- **Fase 1** — al escribir `test_s02_xss_dashboard.py` quedó una variable `l`
  ambigua: la puerta lo marcó como `13 hallazgos (línea de base: 12) — hay 1
  nuevo`, sobre código que acababa de escribirse.

Con las líneas de base ahora en **cero**, cualquier hallazgo nuevo rompe la
puerta de inmediato, sin margen.

ESLint se validó con un archivo que reproduce los patrones que importan:

```
static/__smoke.js
  2:3   error  Unsafe assignment to innerHTML                no-unsanitized/property
  3:3   error  eval with argument of type MemberExpression   security/detect-eval-with-expression
  3:3   error  eval can be harmful                           no-eval
  4:10  error  The Function constructor is eval              no-new-func
```

### 3.5 Análisis estático propio: certificación de no-autonomía

`tests/test_no_autonomy.py` (34 pruebas) recorre el **AST** de los 9 módulos del
sistema. No es un linter genérico: hace cumplir una propiedad del producto.

```
── Certificación de no-autonomía ──────────────────────────
Archivos .py analizados por AST : 9
Con import de subprocess        : ['siem_pipeline.py']
Allowlist                       : ['siem_pipeline.py']
Rutas HTTP que ejecutan algo    : ninguna
Herramientas del LLM            : ninguna
───────────────────────────────────────────────────────────
```

Se mantiene tras la Fase 2, que agregó dos módulos (`siem_validators.py`,
`audit_verify.py`) y **seis rutas HTTP nuevas**. El test enumera la lista
completa de rutas, así que agregar una obliga a actualizarlo a propósito.

**Verificación por mutación** (Fase 0, cuatro violaciones reales, una por vez,
revertidas después):

| Mutante | Detectado por |
|---------|---------------|
| `os.system()` en `api_decision` | `test_sin_llamadas_de_ejecucion[dashboard.py]` |
| `getattr(os, 'system')` disfrazado | `test_sin_llamadas_de_ejecucion[classifier.py]` |
| `import paramiko` en `siem_agent.py` | `test_sin_imports_de_ejecucion[siem_agent.py]` |
| Ruta `POST /api/execute` | `test_el_dashboard_no_define_rutas_de_ejecucion` |

---

## 4. Pruebas de servicio

### 4.1 API REST `/api/v1/` — 38 pruebas (nuevas en la Fase 2)

| Verificación | Resultado |
|--------------|-----------|
| `GET /api/v1/healthz` responde sin datos sensibles | 200 ✅ |
| `healthz` funciona aunque el pipeline no haya corrido | ✅ |
| `Cache-Control: no-store` en incidentes, decisiones y auditoría | ✅ |
| Las rutas sin versionar siguen funcionando (compatibilidad) | ✅ |
| Las dos rutas devuelven exactamente lo mismo | ✅ |
| `GET /api/v1/incidents/<id>` puntual · 404 en JSON si no existe | ✅ |
| **Cuerpo malformado ⇒ 400 en `application/json`** (antes HTML) | ✅ |
| Cuerpo que no es objeto (`[]`, `"x"`, `42`, `null`) ⇒ 400 | ✅ |
| `note` de 501 caracteres ⇒ 400 · de 500 ⇒ 201 | ✅ |
| Cuerpo de 200 KB ⇒ rechazado por `MAX_CONTENT_LENGTH` | ✅ |
| Tipos verificados en `note`, `incident_id`, `action_id` (8 casos) | ✅ |
| `decision` fuera del enum (9 casos, incluidos `execute` y `run`) ⇒ 400 | ✅ |
| **`action_id` inexistente ⇒ 404 y no se escribe nada** | ✅ |
| Acción válida pero de OTRO incidente ⇒ 404 | ✅ |
| Decisión válida ⇒ 201, con `prev_hash` en el registro | ✅ |
| `/api/v1/audit/verify` refleja el estado de la cadena | ✅ |
| Una línea corrupta no tumba el panel | ✅ |

> **Un hueco encontrado por estas pruebas.** La validación de `note` usaba
> `data.get("note") or ""`, y como `[]` y `{}` son *falsy* se convertían en
> cadena vacía antes de llegar al chequeo de tipo: entraban sin avisar. Se
> corrigió el código (chequear el tipo **antes** de cualquier coerción), no el
> test.

### 4.2 Integridad de la auditoría — 28 pruebas (nuevas en la Fase 2)

| Verificación | Resultado |
|--------------|-----------|
| El registro se crea con permisos `0600` | ✅ |
| `append_jsonl` usa `flock(LOCK_EX)`, `fsync` y `O_APPEND` | ✅ |
| **20 decisiones concurrentes ⇒ 20 líneas bien formadas** | ✅ |
| Las escrituras concurrentes mantienen la cadena íntegra | ✅ |
| Cada registro lleva el SHA-256 del anterior | ✅ |
| **Editar una línea del medio rompe la cadena** | ✅ |
| Borrar una línea rompe la cadena | ✅ |
| Una línea corrupta rompe la cadena | ✅ |
| Agregar al final legítimamente NO rompe nada | ✅ |
| Pegar un registro a mano al final tampoco pasa | ✅ |
| Cambiar cualquier campo (5 probados) rompe la cadena | ✅ |
| `audit_verify.py` sale con 0 si está intacta, 1 si está rota | ✅ |
| `audit_verify.py` **no modifica nada** | ✅ |
| `action_id` idéntico al reordenar el playbook | ✅ |
| Omitir una acción no reapunta las decisiones de las otras | ✅ |

> El `prev_hash` se calcula **con el lock tomado**. Si se leyera fuera del
> bloqueo, dos escrituras simultáneas encadenarían sobre el mismo eslabón y la
> cadena quedaría bifurcada. Lo cubre
> `test_escrituras_concurrentes_mantienen_la_cadena`.

#### El estado "heredado": no verificable ≠ manipulado

Al correr `audit_verify.py` **sobre los datos reales del proyecto** (27
decisiones y 12 corridas previas a la Fase 2), la primera versión informó:

```
❌ decisions.jsonl
   CADENA ROTA en la línea 1
   Qué significa: el registro de auditoría fue modificado después de escribirse.
```

Falso, y además contraproducente: esos registros son anteriores al encadenado,
no están manipulados. Una alerta que aparece siempre y siempre es un falso
positivo enseña a ignorar la herramienta — exactamente el problema de *alert
fatigue* que el proyecto entero intenta evitar.

`verificar_cadena()` distingue ahora **tres estados**:

| Estado | Significa | Salida de `audit_verify.py` |
|--------|-----------|------------------------------|
| `ok` | La cadena se verificó entera | ✅ · exit 0 |
| `heredado` | Anterior al encadenado; no verificable, sin indicio de manipulación | ⚠️ · exit 0 |
| `roto` | La cadena existe y no cierra: edición, borrado o inserción | ❌ · exit 1 |

**La distinción resiste el abuso**, que es lo que la hace útil: quitarle el
`prev_hash` a un registro para que pase por heredado se detecta igual, porque el
registro siguiente encadena sobre el hash del contenido original.

Al implementarlo apareció un segundo bug, esta vez en la lógica de migración: la
resincronización entre el tramo heredado y el encadenado aceptaba **cualquier**
`prev_hash` en el primer registro nuevo. Lo encontró
`test_quitar_prev_hash_al_primero_tampoco_alcanza`. Se corrigió calculando el
hash de cada registro leído, tenga o no `prev_hash`, de modo que el empalme entre
los dos tramos también se verifica. Siete pruebas nuevas cubren el caso.

### 4.3 `reset.sh` — 12 pruebas (Fase 1, sin cambios)

Ejecutan el **script real** en un sandbox con un `docker` de juguete. Verifican
que la auditoría se archiva (nunca se borra), que queda de solo lectura, que los
artefactos regenerables sí se borran, y que `--wipe-audit` exige escribir
`BORRAR AUDITORIA`.

### 4.4 Registro append-only — 7 pruebas (invariantes de comportamiento)

El archivo solo crece · revisar una decisión agrega y no edita · el estado es
replay del log · sobrevive al reinicio · cada registro conserva las IPs del
momento · cada línea es NDJSON válido · `siem_agent.py` **real** agrega al
historial sin reescribirlo.

### 4.5 Pipeline completo (verificación manual end-to-end)

Corrida del 16-09-2026 con la captura real, logs dentro de la ventana y **una
corrida vieja del mismo escaneo** para ejercitar B-05:

```
[Agente 1] Incidentes detectados: 3
   • INC-SCAN-172.18.0.7-5326f82e: port_scan [ALTA] — 26 eventos
   • INC-AUTH-172.18.0.3-1d106398: ssh_brute_force [ALTA] — 12 eventos
   • INC-PHISH-172.18.0.9-89b96289: credential_harvesting [ALTA] — 1 eventos
[OK] Análisis guardado (modo: fallback)

/api/v1/healthz        -> {'incidents_file': True, 'status': 'ok'}
/api/v1/incidents      -> 200 | Cache-Control: no-store
primer incidente       -> count=26   (B-05: no son 52 pese a la corrida vieja)
POST decision          -> 201 | prev_hash: 0000000000000000...
action_id inexistente  -> 404
nota de 501 chars      -> 400
cuerpo malformado      -> 400 | application/json
/api/v1/audit/verify   -> {'chain_ok': True, 'records': 1}

$ python3 audit_verify.py decisions.jsonl
  ✅ decisions.jsonl
     Cadena intacta · 1 registro(s)
     Analistas: analista-soc
     Decisiones: 1 aprobada(s), 0 descartada(s)
  exit=0
```

Y sobre el registro **real** del proyecto, que arrastra decisiones previas:

```
$ python3 audit_verify.py
  ⚠️  decisions.jsonl
     27 registro(s) SIN encadenar
     Motivo: 27 registro(s) anteriores al encadenado por hash (Fase 2); no se
             pueden verificar, pero no hay indicio de manipulación
  ⚠️  analysis_history.jsonl
     12 registro(s) SIN encadenar
  exit=0
```

---

## 4.6 Autenticación y control de acceso — 126 pruebas (tarea P1)

Cierra `API-01`, el último hallazgo abierto. Detalle completo en
[`15-autenticacion-y-roles.md`](15-autenticacion-y-roles.md).

| Verificación | Resultado |
|--------------|-----------|
| Las 11 rutas de datos responden 401 sin sesión (el panel redirige a `/login`) | ✅ |
| Solo `healthz` y `login` son públicas, y la lista está vigilada | ✅ |
| `healthz` no filtra nada del contenido del sistema | ✅ |
| El mensaje de error no distingue usuario inexistente de contraseña mala | ✅ |
| Un `viewer` que intenta decidir ⇒ **403 y no se escribe nada** en el registro | ✅ |
| Un `auditor` tampoco decide (separación de funciones) | ✅ |
| Solo el `auditor` verifica la cadena de hash | ✅ |
| **El registro firma con el usuario de la sesión**, no con el entorno | ✅ |
| `ANALYST_NAME` ya no existe en el camino de decisión | ✅ |
| Dos sesiones del mismo usuario ⇒ `session_id` distintos | ✅ |
| El `session_id` del registro no es la cookie | ✅ |
| Dar de baja a un usuario corta su sesión abierta | ✅ |
| Sesión expirada por inactividad (30 min) y por máximo absoluto (8 h) | ✅ |
| Sin token CSRF ⇒ 403 y no se escribe nada · con token válido ⇒ 201 | ✅ |
| 6 intentos fallidos ⇒ 429 con backoff creciente | ✅ |
| El bloqueo alcanza también a la contraseña correcta | ✅ |
| Cambiar `X-Forwarded-For` **no** esquiva el bloqueo | ✅ |
| El servidor no arranca sin `SECRET_KEY` ni con una corta | ✅ |
| Ningún rol declara permisos de ejecución | ✅ |
| `requiere_permiso("ejecutar")` lanza excepción | ✅ |

### Un artefacto de pruebas que costó entender

Un cliente autenticado como `cata` (auditor) empezaba a verse como `ana`
(analyst) y los permisos salían mal. Parecía una fuga de sesión —lo más grave
que le puede pasar a este sistema: decisiones firmadas por quien no las tomó—.

Resultó ser un **artefacto del cliente de prueba de Flask**:
`with app.test_client() as c:` preserva el contexto de petición, y Flask-Login
cachea el usuario en `g`; con ese contexto en la pila, la petición de otro
cliente resolvía `current_user` desde el `g` heredado.

Se comprobó explícitamente que **sin `with` el aislamiento es perfecto** antes
de tocar nada, las fixtures se corrigieron, y quedó
`test_las_sesiones_de_distintos_clientes_no_se_mezclan` vigilando la invariante
por si algún día fuera real.

---

## 4.7 Análisis estático del JavaScript — refactor R-05 (tarea P2)

Cierra el hallazgo **F-03**: `eslint-plugin-security` y
`eslint-plugin-no-unsanitized` estaban configurados y verificados, pero apuntaban
a `static/**/*.js` y ese directorio no existía. **De los dos linters de código
estático que el proyecto se propuso demostrar, el de JavaScript corría sobre cero
archivos.**

### Qué se movió

| | Antes | Después |
|---|---|---|
| `templates/index.html` | 784 líneas (HTML + CSS + JS) | **98 líneas**, solo marcado |
| `static/app.js` | — | **584 líneas** |
| `static/app.css` | — | **198 líneas** |
| JS que ESLint analiza | 65 líneas (solo `login.js`) | **649 líneas en 2 archivos** |
| HTML servido por petición | ~30 KB | **4,7 KB** + estáticos cacheables |

### Los 17 hallazgos de la primera corrida

Era la primera vez que ESLint veía este código. Encontró **8 errores y 9
avisos**, y **ninguno se silenció**:

| Hallazgo | Veredicto | Cómo se cerró |
|----------|-----------|---------------|
| `no-unsanitized/property` ×7 — `innerHTML` con contenido no literal | **Fragilidad real.** Todo pasaba por `esc()`, pero la seguridad dependía de no olvidarse nunca: un `${valor}` sin escapar en 500 líneas es un XSS | Plantilla etiquetada `html` que escapa **por construcción** |
| `security/detect-unsafe-regex` — `IP_RE` | **Falso positivo.** Se midió: 0,1 ms sobre 5 000 caracteres patológicos; todos los cuantificadores están acotados | Reescrita en forma desarrollada, equivalente y que `safe-regex` sí analiza |
| `security/detect-object-injection` ×4 — `ATTACK_LABELS[t]`, `ATTACK_ICONS[t]` | **Problema real, menor.** Un `attack_type` igual a `constructor` devolvía la función heredada del prototipo en vez del valor por defecto | Pasaron a `Map`, que es la estructura correcta para claves no confiables |
| `security/detect-object-injection` ×3 — `bySev[s]`, `collapsed[evId]` | Inofensivos, pero del mismo patrón | `Map` también |
| `security/detect-object-injection` ×2 — `ESC_MAP[c]`, `valores[i]` | Falsos positivos (clave de una clase de caracteres; índice de un bucle) | `Map` y `for…of entries()` |

### La plantilla etiquetada

```js
html`<td>${valorDeUnLog}</td>`     // se escapa siempre
html`<div>${html`<b>ok</b>`}</div>` // un fragmento propio NO se re-escapa
pintar(nodo, fragmento)             // rechaza cualquier cosa que no venga del tag
```

`eslint.config.js` declara `escape: { taggedTemplates: ["html"] }`. **No es una
excepción para silenciar la regla:** le dice al linter dónde está la frontera de
saneamiento, y esa afirmación está verificada por 10 pruebas que ejecutan el tag
real en Node contra la batería de payloads de XSS.

Resultado: **0 errores y 0 avisos sobre 649 líneas, sin una sola supresión.**

### Accesibilidad (RNF-USA-08)

Las filas de la tabla y el desplegable de evidencia eran `<tr>` y `<span>` con un
manejador: invisibles para quien navega con teclado o con lector de pantalla.
Ahora las filas llevan `role="button"`, `tabindex="0"` y `aria-label`, y el
desplegable es un `<button>` con `aria-expanded`/`aria-controls`. Hay una prueba
que lo vigila.

> **Completado en G1** (§4.14): faltaba la otra mitad del requisito, el contraste.
> Las insignias `CRITICAL` y `HIGH` daban 3.35:1 y 3.37:1, por debajo del 4.5:1 de
> WCAG AA. Corregido, con 35 pruebas que calculan los ratios sobre `app.css`.

---

## 4.8 Detección como código — 153 pruebas (tarea P3)

Cierra el hallazgo **F-02** y el requisito `RF-DIF-03`. `rules/rules.md`
documentaba 13 reglas, pero en el Kibana que corría había **4**, creadas a mano
en la consola: **quien clonaba el repositorio no obtenía el mismo sistema.**

### Qué se construyó

| Artefacto | Qué hace |
|-----------|----------|
| `rules/ndjson/` | Las 13 reglas versionadas, una por archivo, en formato de exportación de Elastic Security |
| `scripts/deploy-rules.sh` | Valida e importa las 13. Idempotente (`overwrite=true` + `rule_id` fijo) |
| `scripts/export-rules.sh` | El camino inverso, con `--check` para CI |
| `scripts/start.sh` | Las despliega al levantar el stack (`SIEM_SKIP_RULES=true` para saltearlo) |

Las 4 que ya existían se **exportaron** del Kibana real para no inventar el
formato; las 9 faltantes se escribieron desde `rules.md`.

### Verificación sobre el Kibana real

| Verificación | Resultado |
|--------------|-----------|
| Importación de las 13 | ✅ `13 regla(s) importada(s)` |
| **Las 13 ejecutan sin error** | ✅ `succeeded` en las 13, tras un ciclo de ejecución |
| Idempotencia (3 corridas) | ✅ siempre 13 reglas, nunca 26 |
| Ida y vuelta `deploy → export` | ✅ `--check` verde, sin diff espurio |
| **Desde cero: 0 reglas → `deploy-rules.sh`** | ✅ **13 activas, sin tocar la consola** |

### Pruebas automatizadas

**130 unitarias** sobre los archivos: NDJSON válido de una sola regla, campos
obligatorios, `rule_id` únicos y coincidentes con el nombre de archivo, mapeo
MITRE con formato `T####`, las tres técnicas del proyecto cubiertas, coherencia
severidad/riesgo, la ventana `from` cubre el `interval`, y **ningún campo de
instalación versionado** (`id`, `created_at`… atarían el repo a un Kibana).

**23 de servicio** contra un **Kibana simulado** (servidor HTTP mínimo que imita
los tres endpoints): desplegar dos veces no duplica · cinco corridas siguen dando
13 · reimportar aplica un cambio de umbral · `--dry-run` no contacta a Kibana ·
un archivo corrupto, un `rule_id` duplicado o una regla incompleta abortan **sin
desplegar nada** · las credenciales no aparecen en la salida pero sí llegan a
Kibana · `--check` detecta un ajuste hecho en la consola.

### Dos hallazgos que no estaban previstos

**1. El catálogo, tal como estaba escrito, producía reglas que no corren.**
`rules.md` nombra los campos de agrupación sin sufijo (`source_ip`, `tags`,
`user`…), que es como los muestra el asistente de Kibana. Pero en `filebeat-*`
todos están mapeados como `text`, y agregar sobre un campo `text` falla:

```
Fielddata is disabled on [source_ip]. Text fields are not optimised for
operations that require per-document field data like aggregations.
```

Se verificó ejecutando la agregación contra el índice real. Los archivos usan
`.keyword`, y `test_los_campos_de_agrupacion_usan_keyword` evita que una regla
nueva repita el error. Se documentó en `rules.md`.

**2. El flag `--disabled` no deshabilitaba nada.** Lo encontró
`test_con_disabled_quedan_apagadas`: los archivos versionados traen
`"enabled": true` (así salen de Kibana, donde están activas), así que el import
las dejaba andando igual y el flag solo saltaba el paso de habilitar. Se corrigió
apagándolas explícitamente con un PATCH.

### La no-autonomía, también en la capa del SIEM

El campo `actions` de una regla de Elastic es donde se conectan webhooks o
correos que **se ejecutan solos** al saltar una alerta. Las 13 lo tienen vacío:
una detección produce una alerta y nada más. Lo vigila
`test_ninguna_regla_dispara_acciones`, y otro test verifica que ningún script
contenga `ufw`, `iptables`, `ssh` ni `systemctl`.

> **Detectar no es actuar.** `deploy-rules.sh` sube reglas de detección al SIEM;
> no toca hosts, firewalls ni servicios. La cadena sigue terminando en un
> analista que decide.

---

## 4.9 D-01 · Una regla ruidosa tapaba a todas las demás

**Encontrado el 25-09-2026 verificando el script de demostración.** No estaba en
el plan y es el defecto de detección más serio hallado desde la auditoría.

`prepare-for-ia.py` pedía las **10 alertas más recientes** de la ventana:

```python
alerts = parse_alerts(es_search(ALERTS_INDEX, alerts_query(size=10, window=WINDOW)))
```

Con el stack real había **116 alertas de 8 reglas distintas**. Las 10 que
llegaban al clasificador eran **todas de la misma regla**:

```
  96  Port Scan – Rapid Sequential Probe     ← se llevaba las 10 plazas
   7  Sensitive Port Probe
   3  Phishing Page Visit + Submission
   3  SSH Successful Login After Brute Force ← CRÍTICA, riesgo 95
   2  Credential Submission to Suspicious Login
   2  Port Scan – Many Distinct Ports
   2  SSH Brute Force – Aggressive per Source IP
   1  SSH Brute Force – Basic Threshold
```

Entre las que quedaban afuera estaba **`SSH Successful Login After Brute Force`**:
significa que la fuerza bruta **funcionó** y hay una cuenta comprometida. La
detección más importante del sistema no llegaba al analista.

**El defecto empeora cuanto mejor configurado está el SIEM.** Apareció al
desplegar las 13 reglas del catálogo (tarea P3): con 4 reglas casi no se notaba,
con 13 una sola las silencia a todas.

### La corrección

`alerts_query_por_regla()` agrupa en Elasticsearch con `terms` + `top_hits`:
trae las N más recientes **de cada regla**, así ninguna puede desplazar a otra.

| | Antes | Después |
|---|---|---|
| Alertas que llegan al clasificador | 10 | 31 |
| Reglas representadas | **1 de 8** | **8 de 8** |
| `SSH Successful Login After Brute Force` | no llegaba | llega |

**17 pruebas** en `tests/unit/test_alertas_por_regla.py`, incluida una que
reproduce el escenario exacto (una regla con 96 alertas y otras siete con pocas)
y otra que falla si alguien vuelve a `alerts_query(size=…)` en el pipeline.

---

## 4.10 D-02 · La víctima aparecía como atacante en las alertas

**Encontrado el 25-09-2026**, al revisar la coherencia de los incidentes que
mostraba la demo. Es el mismo error que el hallazgo **L-02** —confundir atacante
con víctima— por la puerta de las alertas en vez de la de los logs.

Una alerta de tipo *threshold* trae el campo **y** el valor por los que agrupó:

```
SSH Brute Force – Aggressive per Source IP  →  source_ip.keyword = 172.18.0.7  (atacante)
SSH Brute Force – Basic Threshold           →  host.ip.keyword   = 172.18.0.3  (VÍCTIMA)
```

`prepare-for-ia.py` tomaba el valor y **tiraba el nombre del campo**:

```python
"source_ip": terms[0].get("value") if terms else s.get("source_ip"),
```

Resultado: la regla A1, que agrupa por la máquina **atacada**, producía un
incidente que acusaba a la víctima:

```
ssh_brute_force  alta  n=31   atacante=172.18.0.3   víctimas=[]   usuarios=[]
```

Una IP que nunca atacó nada, sin víctimas y sin usuarios, con severidad alta.

### La corrección no elige entre las dos lentes

"Esta IP está atacando" (A2) y "este host está siendo atacado" (A1) son dos
preguntas legítimas y distintas, y el catálogo las quiere a las dos. El defecto
no era tener ambas: era **descartar el dato que dice cuál es cuál**.

Ahora el valor se enruta según el campo:

| Agrupó por | El valor es | Va a |
|------------|-------------|------|
| `source_ip` | quien ataca | `source_ip` |
| `host.ip`, `host.name` | quien recibe | `victim_host` |
| `user` | a quién atacan | `target_user` |
| otro / sin threshold | no se interpreta | `source_ip` del evento |

Con los datos reales, el incidente pasó a decir la verdad:

```
ssh_brute_force  alta  n=55   atacante=desconocida   víctimas=['172.18.0.3']
```

Y su playbook ya no ofrece un `ufw deny` imposible: solo queda la mitigación
estructural (fail2ban), porque no hay IP que bloquear.

**La consecuencia que importa:** antes, un analista apurado podía ejecutar
`sudo ufw deny from 172.18.0.3` contra su propio host atacado. Es exactamente el
falso positivo con consecuencias reales —cortar un servicio legítimo— que el
proyecto entero está construido para evitar.

**28 pruebas** en `tests/unit/test_rol_del_valor_agrupado.py`, incluidas una que
verifica que las dos lentes conviven sin contaminarse y otra que falla si alguien
restaura la línea original.

---

## 4.11 Script de demostración (tarea D1)

`scripts/demo.sh` deja el sistema listo con un comando. Cierra el riesgo **F-06**
de la auditoría —*"el panel se ve vacío el día de la defensa"*— que era el más
probable de todos.

| Modo | Qué hace |
|------|----------|
| `./scripts/demo.sh` | Diagnóstico → usuarios → reglas → 3 ataques → espera alertas → pipeline → guion |
| `--rapido` | Sin la fuerza bruta real (no necesita Docker) |
| `--estado` | Solo diagnóstico: qué falta para poder demostrar |
| `--solo-guion` | Solo imprime el guion, no toca nada |

Verificado: corre dos veces sin romper nada, no duplica usuarios ni reglas, y
aborta con mensaje claro si falta algo imprescindible.

### Dos problemas de demostración que salieron al probarlo

**1. La fuerza bruta se clasificaba como "autenticación sospechosa".** El
diccionario de `run-brute-force.sh` tenía 4 contraseñas → 3 fallos, y el umbral
del clasificador es 20. El ataque solo se reconocía como fuerza bruta si Kibana
alcanzaba a disparar una alerta antes de que corriera el pipeline — una carrera
que se perdía casi siempre. Se amplió el diccionario a **25 intentos** (24 fallos
+ la real al final), así la detección se sostiene sola.

**2. El pipeline corría antes que las reglas.** `demo.sh` ahora espera a que
haya alertas en Elasticsearch antes de invocar el pipeline.

Resultado, con los tres ataques:

```
ssh_brute_force        alta       24 ev  🔗 campaña
port_scan              alta       26 ev  🔗 campaña
credential_harvesting  alta        1 ev
```

---

## 4.12 Ataque en vivo (tarea D2)

`scripts/demo.sh` (§4.11) muestra un **resultado**: el panel ya tiene incidentes
cuando empieza la defensa. Un panel con datos preexistentes, sin embargo, podría ser
cualquier archivo JSON. `scripts/demo-ataque.sh` muestra el **proceso**: lanza un
ataque mientras el panel está proyectado y el incidente aparece delante del público,
porque el panel se refresca solo cada 15 segundos.

| Modo | Ataque | MITRE | Necesita Docker |
|------|--------|-------|-----------------|
| `demo-ataque.sh` / `port-scan` | Sondeo de 26 puertos | T1046 | no |
| `demo-ataque.sh phishing` | Captura de credenciales | T1566 | no |
| `demo-ataque.sh fuerza-bruta` | Hydra por SSH real | T1110 | sí |
| `demo-ataque.sh campana` | Escaneo + phishing desde la misma IP | T1046 + T1566 | no |

`--rapido` saca las pausas narrativas (para probarlo, no para presentar) y `--ip X`
fija la IP del atacante.

### La IP nueva en cada corrida

Sin esto el script no sirve para demostrar. Las simulaciones usaban IP fijas
(`172.18.0.7` el escaneo, `172.18.0.8` el phishing), así que el ataque lanzado en
vivo se sumaba al incidente que ya estaba en el panel y quien presentaba no tenía
nada nuevo que señalar. Se agregó `--ip` a `run-port-scan.sh` y `run-phishing.sh`, y
`demo-ataque.sh` genera una IP distinta por corrida en **198.51.100.0/24** — el rango
que RFC 5737 reserva para documentación, para no proyectar la IP de un host real.

Sin `--ip`, ambas simulaciones generan exactamente lo de antes: `docs/05` y las
pruebas de clasificación dependen de esas IP fijas, y hay una prueba por script que
lo sostiene.

### El listado mostraba a la víctima como atacante

Salió al probar el modo `campana`. La campaña se formaba bien, pero el listado
imprimía `source_ip`, y en un incidente de phishing ese campo es **la víctima que
envió sus credenciales**, no el servidor de la página falsa. El guion decía "buscá la
IP 198.51.100.88 en el panel" y en pantalla figuraba `172.18.0.8`.

No es un defecto del clasificador —es la ambigüedad de `source_ip` entre detectores,
ya reportada como deuda arquitectónica en §7.2— sino del script. `listar_incidentes()`
ahora muestra `attacker_ips[0]`, agrega la columna `🔗` con el identificador de
campaña, y el cierre aclara la asimetría del phishing en voz alta.

### El guion imprimía una línea vacía

Al actualizar el paso 7 del guion de `demo.sh` —que mandaba a
`bash simulation/run-port-scan.sh --offline && python3 siem_pipeline.py`, con la IP
fija `172.18.0.7`, **la misma que `demo.sh` ya había usado al preparar el
laboratorio**, así que el ataque "en vivo" se habría fundido con un incidente
existente— apareció otra cosa.

El guion sale de un `cat <<GUION` **sin comillas**, y eso es deliberado: expande
`$USUARIO_DEMO` y `$PASSWORD_DEMO` para que quien presenta lea las credenciales del
laboratorio. El precio es que backticks y `$(...)` dentro del texto se **ejecutan**.
Escribir `` `campana` `` en la prosa —la sintaxis de código de Markdown, lo natural—
produjo una línea vacía en pantalla, en silencio.

Quedan tres pruebas: el cuerpo del heredoc no puede contener backticks ni `$(`, solo
expande variables de una lista cerrada, y el paso 7 tiene que apuntar a
`demo-ataque.sh` y no volver a los comandos a mano.

### Verificación ejecutada

Todo contra el stack real levantado (4 servicios, 13 reglas activas):

| Corrida | Resultado |
|---------|-----------|
| `campana --rapido` sobre estado limpio | 2 incidentes nuevos, misma IP `198.51.100.216`, mismo `CAMP-fcfeab8d` |
| `port-scan --rapido` | 1 incidente nuevo, IP `198.51.100.49` distinguible a simple vista |
| `phishing --rapido` | Se sumó al incidente existente (agrupa por víctima): el cierre lo dice y sugiere correr `demo.sh` antes |
| `demo-ataque.sh --borrar-todo` | Aborta, salida 2 |
| `demo-ataque.sh contener` | Aborta, salida 2 — un tipo mal escrito **no** cae al de por defecto |
| `demo-ataque.sh --help` | Salida 0, no lanza nada |

El caso `phishing` merece una nota: `detect_phishing` agrupa por la IP de la víctima,
que en la simulación es fija (`172.18.0.9`), así que dos corridas de phishing caen en
el mismo incidente. No es un error —el incidente *es* la agrupación— y el script lo
explica en pantalla en lugar de dejar a quien presenta buscando un incidente que no
va a aparecer.

### Pruebas automatizadas

`tests/integration/test_scripts_de_demostracion.py` — **31 pruebas**:

| Grupo | Qué fija |
|-------|----------|
| Sintaxis | `bash -n` sobre los 5 scripts: un error de sintaxis se descubriría en vivo |
| Argumentos | Opción y tipo desconocidos abortan con salida 2; `--help` no ataca |
| Cabecera | Los tipos documentados son exactamente los que acepta el `case` |
| RFC 5737 | La IP generada está en el rango reservado y el último octeto no desborda |
| `--ip` | Llega al evento generado, en el campo correcto de cada simulación |
| Compatibilidad | Sin `--ip`, las IP por defecto son las de siempre |
| Sin pérdida | Una corrida nueva no trunca los eventos de la anterior |
| Formato | Lo generado es NDJSON válido línea por línea |
| No-autonomía | Ningún script de demostración contiene verbos de contención |
| Guion | Sin backticks ni `$(...)`, y manda al script de ataque en vivo |

Los scripts resuelven su salida desde su propia ubicación (`ROOT="$(dirname "$0")/.."`),
así que las pruebas **copian el árbol a `tmp_path`** y lo corren ahí: `network_logs/`
del proyecto son datos del equipo.

`test_scripts_de_demostracion.py` usa `subprocess`, así que se sumó al allowlist
exacto de `tests/test_no_autonomy.py` con su justificación escrita. Ese aserto es de
lista cerrada: agregar un archivo que lance procesos obliga a declararlo.

### Dos correcciones de prueba, no de código

Ambas pruebas fallaron primero y en las dos el equivocado era el test:

1. **`escaneo` no es un tipo de ataque.** La expresión que leía la cabecera capturó
   la palabra de la línea *sin* argumento, que describe el tipo por defecto. Se ajustó
   la expresión.
2. **"Un archivo por corrida" era más fuerte que la garantía real.** El nombre lleva
   marca de tiempo en segundos, así que dos corridas del mismo tipo en el mismo
   segundo comparten archivo — pero lo abren con `>>`. Lo que Filebeat necesita es que
   no se trunque, y eso es lo que la prueba verifica ahora.

### Mutación del control de no-autonomía

Se inyectaron dos acciones de contención reales en `demo-ataque.sh` y el control las
detectó en ambos casos; el script quedó restaurado byte a byte:

| Inyectado | Detectado |
|-----------|-----------|
| `ufw deny from "$IP_ATAQUE"` | `['\bufw\b']` |
| `ssh admin@172.18.0.5 "systemctl stop sshd"` | `['\bsystemctl\b', '\bssh\s+[\w.@]']` |

También se reinyectaron los backticks en el guion de `demo.sh`: la prueba se puso en
rojo y el script quedó restaurado idéntico.

`ssh` se busca como comando seguido de destino, para que el nombre de contenedor
`ssh-target` —que sí aparece, legítimamente— no dé un falso positivo.

### Los comandos de la defensa, verificados contra el servidor real

El documento de evidencia (`docs/auditoria/03-evidencia-para-la-catedra.md`) traía un
bloque de `curl` escrito **antes de P1**: sin autenticación, tres de los cuatro
comandos devolvían lo documentado. Hoy devuelven 401 o 403. Quien los copiara en la
defensa vería fallar la demostración de su propia API.

Se ejecutaron todos contra el servidor corriendo y se reescribió el bloque con las
salidas reales. La versión corregida demuestra **más** que la anterior, porque los
rechazos son el control funcionando:

| Petición | Código | Cuerpo |
|----------|--------|--------|
| `GET /api/v1/healthz` (público) | 200 | `{"incidents_file":true,"status":"ok"}` |
| `GET /api/v1/incidents` sin sesión | 401 | — |
| `POST /api/v1/login` analista | 200 | rol, permisos, token CSRF, política de expiración |
| `POST /api/v1/decision` con sesión, **sin** CSRF | 403 | `token CSRF inválido o ausente` |
| `POST /api/v1/decision` con CSRF, acción inexistente | 404 | `no existe la acción 'x' en el incidente 'INC-INVENTADO'` |
| `POST /api/v1/decision` con CSRF, JSON roto | 400 | `se esperaba un cuerpo JSON` (JSON, no HTML de Werkzeug) |
| `GET /api/v1/audit/verify` como **analyst** | 403 | `el rol 'analyst' no tiene permiso para 'verificar_cadena'` |
| `GET /api/v1/audit/verify` como **auditor** | 200 | `chain_ok:true, records:28, "27 heredados al inicio; los 1 siguientes verifican bien"` |
| `POST /api/v1/decision` como **auditor** | 403 | `el rol 'auditor' no tiene permiso para 'decidir'` |

Las dos últimas filas son el par que conviene mostrar en voz alta: el analista decide
y no audita, el auditor audita y no decide. Y ninguno de los tres roles puede ejecutar
una acción de contención — no es un permiso ausente de la tabla, es una capacidad que
no existe en el sistema.

Queda registrado como **D-04** en la auditoría. La lección es de proceso: la
documentación de demostración envejece con el código, y solo se detecta ejecutándola.

### Estado

`800 pruebas, 2 omitidas, ~100 s` y `./scripts/check.sh` **todo en verde** (ruff,
pylint + secure-coding-standard, bandit, eslint + security, no-autonomía, cobertura
≥ 80 %). Las 99 s siguen dentro del límite de 5 minutos del objetivo de cátedra.

---

## 4.13 Romper la auditoría en vivo (tarea D3)

"El registro es inmutable" es una afirmación, y nadie tiene por qué creerla.
`scripts/demo-auditoria.sh` la convierte en una demostración: altera una decisión ya
registrada y el verificador del proyecto —el mismo que corre en la puerta de
calidad— señala la línea exacta y termina con **código 1**.

| Modo | Qué hace |
|------|----------|
| `./scripts/demo-auditoria.sh` | Narrado, con pausas, en 5 pasos |
| `--rapido` | Sin pausas (para probarlo) |
| `--json` | Solo el antes/después de la cadena, parseable |

### El registro real no se toca

`decisions.jsonl` son datos del equipo. El script copia el registro a un directorio
temporal, trabaja ahí, y en el paso 5 imprime el **SHA-256 del archivo real antes y
después**: si no coinciden, aborta con código 1 y lo declara un defecto propio. La
copia temporal se borra con un `trap` en `EXIT INT TERM`, así una interrupción a mitad
de camino no deja nada.

### Por qué el script agrega dos decisiones antes de alterar una

Es la parte que enseña algo. Un encadenado protege cada registro **a través del
siguiente**: el último eslabón queda expuesto hasta que otro lo cubre, porque no hay
ningún `prev_hash` que lo apunte. En el estado actual del proyecto hay 27 registros
`heredado` (anteriores al encadenado) y los que siguen; alterar el último no rompe
nada.

No es un defecto de esta implementación, es una propiedad del mecanismo. Cerrarla
requiere un **ancla externa** —publicar el hash de cierre en otro sistema—, que hoy no
existe. El script siembra dos decisiones con el `append_jsonl` real del proyecto para
que el registro alterado tenga sucesores, y la demostración lo dice en voz alta antes
de que lo pregunten.

Queda una prueba que lo deja escrito: `test_alterar_el_ultimo_registro_no_es_detectable`
verifica **las dos mitades** —que alterar el último no se detecta y que alterar el
primero sí—, y falla si algún día el encadenado empieza a proteger también el último.
Ese fallo sería la señal de que el script puede dejar de sembrar.

### Verificación ejecutada

| Corrida | Resultado |
|---------|-----------|
| `demo-auditoria.sh --rapido` | 30 registros ✅ → altera el 28 → **CADENA ROTA en la línea 29**, exit 1 → restaura → 30 ✅ |
| SHA-256 de `decisions.jsonl` antes/después | `73c4407c…` = `73c4407c…`, verificado además por fuera del script |
| `python3 audit_verify.py` sobre el registro real, después | exit 0, cadena intacta, 28 registros |
| `--json` | `{"antes":{"estado":"ok","records":30},"despues":{"estado":"roto","first_broken":29}}` |
| `--json \| python3 -m json.tool` | Parseable (hubo que sacar una línea narrada que lo ensuciaba) |
| Sin `decisions.jsonl` | exit 1, con la instrucción de qué correr primero |
| `--romper-de-verdad` | exit 2 |

### Pruebas automatizadas

12 pruebas más en `tests/integration/test_scripts_de_demostracion.py` (total **40**):

| Qué fija |
|----------|
| La ruptura se detecta: `antes.estado == ok`, `despues.estado == roto`, con línea señalada |
| El registro no se modifica (comparación de bytes, no del mensaje del script) |
| `--json` es parseable, sin narración filtrada |
| Sin registro: exit 1 y el mensaje dice cómo salir del paso |
| Alterar el último registro **no** es detectable; alterar el primero **sí** |
| Todo `./scripts/*.sh` que nombra el guion de `demo.sh` existe |
| Sintaxis y ausencia de verbos de contención (se sumó a las listas de §4.12) |

La prueba corre contra un **árbol mínimo en `tmp_path`** con un `decisions.jsonl`
encadenado de juguete, hecho con el `append_jsonl` real: el registro del equipo no
entra en la prueba ni para leerlo.

### Mutación

| Inyectado | Detectado por |
|-----------|---------------|
| Se quita la siembra (se altera el último registro) | La autocomprobación del paso 3 del script: exigía código 1 y recibió 0 |
| El script escribe en el registro real | La comparación de SHA-256 del paso 5 |

Las dos capas respondieron, y **la del script disparó primero**. Eso es lo que se
quería: en una defensa, el script falla en voz alta en lugar de mostrar un resultado
falso.

### Un hallazgo del documento de evidencia

`03-evidencia-para-la-catedra.md` instruía, para esta misma demostración, **editar a
mano** una decisión de `decisions.jsonl` — sin copia y sin decir cómo volver atrás.
Seguir esa instrucción en la defensa habría dejado la auditoría del equipo con la
cadena rota de forma permanente: restaurarla exige los bytes originales exactos.
Reemplazado por el script. Registrado como **D-05**.

### Estado

`809 pruebas, 2 omitidas, ~113 s` y `./scripts/check.sh` **todo en verde**.

---

## 4.14 Contraste de la interfaz (tarea G1)

Completa `RNF-USA-08`, que hasta acá cubría solo navegación por teclado (§4.7). El
panel es la herramienta con la que un analista mira severidades durante horas: una
insignia ilegible no es un detalle estético, es la diferencia entre ver y no ver que
un incidente es crítico.

### Lo que fallaba

Las insignias usaban `color: #fff` sobre sus propios rellenos:

| Insignia | Fondo | Texto | Contraste | WCAG AA (4.5:1) |
|----------|-------|-------|-----------|-----------------|
| `CRITICAL` | `#f85149` | `#fff` | **3.35:1** | ❌ |
| `HIGH` | `#db6d28` | `#fff` | **3.37:1** | ❌ |
| `MEDIUM` | `#d29922` | `#1c1300` | 7.28:1 | ✅ |
| `LOW` | `#3fb950` | `#04130a` | 7.50:1 | ✅ |

La incoherencia era la pista: `MEDIUM` y `LOW` ya usaban texto oscuro porque con
blanco se veían mal, pero nadie volvió sobre las dos primeras. Y el umbral que
aplica es el de **texto normal**: la insignia es de 11px bold y el nivel relajado de
3:1 ("texto grande") empieza en 18.66px bold.

### La corrección

Texto oscuro en las cuatro, cada uno teñido de su propio color y no negro puro, para
que la insignia no se vea sucia. La urgencia la comunica el **relleno**, que sigue
siendo rojo; el color del texto solo tiene que ser legible.

| Insignia | Texto nuevo | Contraste |
|----------|-------------|-----------|
| `CRITICAL` | `#1a0603` | 5.85:1 ✅ |
| `HIGH` | `#240d00` | 5.50:1 ✅ |

### Una insignia que podía quedar invisible

Salió al auditar la hoja completa. El panel arma la clase como
`"b-" + sev.toUpperCase()`, y `.badge` fijaba `color:#fff` **sin fondo**. Con una
severidad fuera de las cuatro —`"alta"` produce `.b-ALTA`, que no existe— la insignia
quedaba con letras blancas sobre el fondo del panel: prácticamente invisible.

Dos correcciones, una por capa:

1. **`.badge` trae relleno neutro propio** (`--border` con `--text`, 7.91:1), así
   cualquier valor inesperado sigue siendo legible.
2. **`siem_agent.analyze_incident` normaliza la severidad.** El prompt le *pide* al
   LLM `LOW|MEDIUM|HIGH|CRITICAL`, pero pedirlo no es garantizarlo, y su respuesta se
   pasaba tal cual. El respaldo determinístico ya normalizaba con `_SEV_MAP`; el
   camino del LLM no.

Lo que importa del diseño de (2): **ante un valor irreconocible no se cae a
`MEDIUM`.** Eso degradaría en silencio un incidente que el Agente 1 marcó como
crítico, y un analista que filtra por severidad dejaría de verlo — mucho peor que una
insignia rara. Se usa la severidad determinística del Agente 1, que es el mismo
criterio que el resto del proyecto: cuando el LLM no sirve, manda lo determinístico.
Si hubo corrección, queda `severidad_ajustada_sin_normalizar` con lo que dijo el LLM:
el histórico no pierde el dato.

### Auditoría completa de la paleta

Se calcularon los 30 pares de la hoja, no solo las insignias:

| Grupo | Resultado |
|-------|-----------|
| `--text`, `--muted`, `--accent` sobre los 3 fondos | 5.62:1 a 12.45:1 ✅ |
| `--crit`, `--high`, `--med`, `--low` como texto sobre los 3 fondos | 5.13:1 a 7.61:1 ✅ |
| `#fff` sobre `--ok` (botón aprobar, chip aprobado) | 4.63:1 ✅ (justo) |
| `#fff` sobre `--no` (descartar) | 10.97:1 ✅ |
| `--ok` **como texto** sobre los fondos | 3.74:1 a 4.15:1 — **no se usa así**, verificado |

`--ok` sobre el panel da 3.74:1, que solo alcanzaría para texto grande. Se verificó
que el token se usa únicamente como relleno con texto blanco, nunca como color de
texto, así que no hay incumplimiento. Queda anotado por si alguien lo reutiliza.

### Pruebas automatizadas

**`tests/unit/test_contraste_de_la_interfaz.py` — 35 pruebas.** Leen `static/app.css`
y calculan los ratios con la fórmula de WCAG 2.1 §1.4.3. Es análisis estático de la
hoja de estilos: sin navegador ni capturas.

| Qué fija |
|----------|
| La fórmula, contra referencias conocidas (21:1, 1:1, 4.48:1) — si esto falla, el resto miente |
| Cada una de las cuatro insignias cumple 4.5:1 |
| El ratio **anotado en el comentario** del CSS coincide con el real (±0.05) |
| Una severidad desconocida sigue siendo legible (`.badge` tiene fondo y color) |
| Los 7 colores de texto cumplen AA sobre los 3 fondos (21 combinaciones) |
| Los chips de estado (`.s-approved`, `.s-dismissed`) cumplen AA |
| Barrido general: ninguna regla con fondo y texto baja de 3:1 — atrapa estilos nuevos |

**`tests/unit/test_severidad_del_agente.py` — 35 pruebas.** El Agente 2 no tenía
archivo de pruebas propio (hallazgo **F-07**, 31 % de cobertura); este es el primero.

| Qué fija |
|----------|
| Los cuatro valores válidos pasan intactos, tolerando caja y espacios |
| Las cuatro traducciones del español (`critica`→`CRITICAL`, etc.) |
| 10 valores irreconocibles (incluidos `None`, `42`, `[]`, `""`) caen a la severidad determinística |
| **El respaldo nunca degrada un incidente crítico** |
| Sin clasificación usable, queda `MEDIUM` |
| **Toda severidad posible tiene su clase `.b-*` en el CSS** — cierra el círculo con G1 |
| `analyze_incident` normaliza lo del LLM y registra el original; no agrega ruido si acierta |

La última fila de la primera tabla y la sexta de la segunda son las que se cruzan: si
alguien agrega un valor válido al Agente 2 sin agregar su regla CSS, o cambia una
clase CSS sin avisar al Agente 2, una de las dos falla.

### Mutación

| Inyectado | Detectado |
|-----------|-----------|
| `.b-CRITICAL` vuelve a `color:#fff` | `3.35:1, por debajo de 4.5:1` — y además el comentario quedó desfasado |
| Se anota `9.99:1` en un comentario | `el comentario dice 9.99:1 y el real es 5.50:1` |
| `.badge` pierde su relleno neutro | `.badge no define fondo y color propios` |
| `_normalizar_severidad` defaultea a `MEDIUM` | 15 pruebas en rojo, entre ellas `se degradó un incidente crítico` |
| `analyze_incident` deja de normalizar | 2 pruebas en rojo |

### Verificación en el servidor

`curl http://127.0.0.1:5000/static/app.css` devuelve las cuatro reglas corregidas: el
panel corriendo sirve el CSS nuevo, no una versión en caché.

### Estado

`879 pruebas, 2 omitidas, ~111 s` y `./scripts/check.sh` **todo en verde**. Hubo un
hallazgo de ruff en mi propia prueba (`C402`, generador innecesario); se corrigió
extrayendo un ayudante que además saca la duplicación del parseo de declaraciones.

---

## 4.15 Tokens de diseño y escala tipográfica (tarea G2)

### Lo que había

| Propiedad | Antes |
|-----------|-------|
| Tamaños de fuente | **10 distintos** para 53 usos, incluidos `12.5px` y `13.5px` |
| Radios | **7 distintos** (4, 6, 8, 10, 20px y dos compuestos) |
| Combinaciones de padding | **29 distintas** para 39 usos |
| Valores numéricos de espaciado | 20 distintos para 119 usos, con 1, 3, 5, 7 y 9px sueltos |
| Pantalla de login | 37 líneas de CSS **embebido** en la plantilla, con su propio `:root` |

El problema de fondo no era la cantidad de valores: era que **la intención no estaba
escrita en ningún lado**. Nadie podía saber si `13.5px` era un paso de la escala o el
apuro de alguien, así que la regla siguiente inventaba el valor 11.º.

Y ya había costado algo concreto: `--ok` valía `#238636` en el panel y `#3fb950` en
el login. **El mismo nombre con dos colores.** El del login, además, no se usaba en
ninguna regla.

### Lo que se leyó antes de decidir

`12.5px` no era descuido: aparece **siempre en texto monoespaciado** (IP, comandos,
marcas de tiempo). Una monoespaciada se ve más grande que una proporcional al mismo
tamaño, así que 12.5px monoespaciado se lee como 13px sans al lado. Es una corrección
óptica deliberada, y redondearla habría empeorado el panel. Quedó como `--fs-mono`,
con el porqué escrito y una prueba que lo sostiene.

El espaciado tampoco era caótico: el archivo ya seguía casi entero una **grilla de
2px**, con 10px y 14px como los dos valores más usados (25 y 20 veces). Los impares
eran 14 usos de 119.

### Las decisiones

**Grilla de 2px, no de 4px.** Llevar 6, 10, 14, 18, 22 y 26 a múltiplos de 4 habría
movido 72 usos, y 10 y 14 son claramente el ritmo buscado. Se ajustaron los 14 usos
impares al paso más cercano: cambios de **1px**.

**Los tokens de espaciado se llaman por su valor** (`--sp-10: 10px`) y no por una
talla. Con 17 pasos, una escala de tallas sería adivinanza; así la hoja se sigue
leyendo y el conjunto igual queda cerrado por la prueba.

**Un solo archivo declara.** `static/tokens.css` tiene la paleta y las tres escalas;
`app.css` y `login.css` solo consumen. Es lo que impide que vuelva a haber dos `--ok`.

**Los alias se escriben como alias.** `--err: var(--crit)`, no `--err: #f85149`. Si se
repitiera el hex, nada impediría que uno cambie y el otro no.

### Cambios reales de valor

Se resolvió cada declaración a píxeles antes y después. **167 declaraciones, 167
después**, y exactamente **14 cambios**, todos de ≤1px:

| Cambio | Dónde | Cuánto |
|--------|-------|--------|
| `13.5px` → `14px` | 4 tamaños de fuente de texto de lectura | +0.5px |
| `3px 9px` → `4px 10px` | insignias | +1px |
| `2px 7px` → `2px 8px`, `1px 5px` → `2px 6px`, `1px 7px` → `2px 8px` | chips | +1px |
| `2px 9px` → `2px 10px`, `7px 0` → `8px 0`, `3px 0` → `4px 0` | listas y celdas | +1px |
| `8px 10px 9px` → `8px 10px 10px` | pie del bloque de comando | +1px |

### El login, que había quedado fuera de R-05

El refactor R-05 extrajo el CSS del panel y dejó la pantalla de login con su `<style>`
embebido: sin caché, sin análisis estático y sin los tokens compartidos. Se extrajo a
`static/login.css`, sobre la misma escala. También salió el único `style=` en línea
que quedaba (`font-size:22px` en el escudo).

Cambios de valor al pasarlo a la escala, todos de ≤2px: radio de la tarjeta 12→10px,
padding 32×34→32×32px, título 19→18px, botón 11→12px, escudo 22→20px.

> **Por qué el login no carga `app.css`:** las dos hojas definen `body`, `button` y
> `*`. Cargarlas juntas haría que los estilos de los botones del panel pisaran los del
> formulario. Por eso los tokens viven aparte y cada pantalla enlaza los suyos.

### Un defecto de contraste que apareció al hacerlo

Al calcular los pares de color del login salió que **el hover del botón bajaba el
contraste**: `#fff` sobre `--ok-claro` (#2ea043) da **3.37:1**, contra 4.63:1 en
reposo. El botón se volvía menos legible justo cuando el usuario estaba por apretarlo.

La causa es que el hover **aclaraba** el fondo. Oscurecerlo da la misma señal de
interacción y sube a **5.41:1** (`--ok-oscuro: #1f7a30`) — y es además la convención
de "presionado". `--ok-claro` quedó solo para bordes, con el aviso escrito al lado.

El panel no tenía el problema: su `button:hover` cambia el borde, no el fondo.

### Lo que NO se tokenizó, y por qué

Quedan 10 colores crudos en `app.css`: superficies de hover y selección de 1–2 usos
(`#11161d`, `#1b2330`, `#152436`, `#13242f`, `#101820`) y los cuatro textos oscuros de
las insignias, que llevan su ratio anotado al lado. Tokenizarlos daría 10 tokens de un
solo uso, que es ruido, no vocabulario. Sí se tokenizaron los que lo merecían:
`#0d1117` ×2 (era `--bg` duplicado literal), `#7ee787` ×5, `#21262d` ×2 y el grupo
morado de campaña, que es un conjunto semántico.

### Pruebas automatizadas

**`tests/unit/test_tokens_de_diseno.py` — 17 pruebas.**

| Qué fija |
|----------|
| **Solo `tokens.css` declara un `:root`** — es lo que evita que vuelva a haber dos `--ok` |
| Ninguna plantilla trae `<style>` embebido ni `style=` en línea |
| Las dos pantallas enlazan `tokens.css`, y **antes** que su hoja propia |
| **Ninguna propiedad de ritmo usa un px suelto**, con archivo y línea — evita el valor 11.º |
| Todo token usado existe; todo token definido se usa (mirando las dos hojas juntas) |
| El espaciado es una grilla de 2px y cada token se llama por su valor |
| La escala tipográfica no pasa de 9 pasos |
| Los radios mantienen su jerarquía xs < sm < md < lg < píldora |
| `--fs-mono` es medio píxel menor que `--fs-md`, y es el único fraccionario |
| Cada grupo de tokens tiene su comentario explicando para qué es |
| Los alias se escriben como `var(--otro)` y apuntan a algo que existe |
| `tokens.css` no define reglas además de `:root` |

**`tests/unit/test_contraste_de_la_interfaz.py` — pasó de 35 a 52 pruebas**, ahora
sobre las tres hojas: suma los avisos del login, su botón, el chip pendiente y
—lo nuevo— **los estados `:hover`**, resolviendo el color de texto que heredan de su
regla base. Esa es la que encontró el defecto del hover.

El andamiaje compartido vive en `tests/unit/hojas_de_estilo.py`, que no es un archivo
de pruebas: lo importan las dos, que verifican cosas distintas sobre el mismo material
y necesitaban el mismo parseo (incluida la resolución de alias).

### Mutación

| Inyectado | Detectado |
|-----------|-----------|
| Un `padding: 9px 13px` escrito a mano | `app.css:44  padding: 9px 13px` |
| Un token de espaciado impar (`--sp-9: 9px`) | `espaciado fuera de la grilla de 2px` |
| Redondear `--fs-mono` a 13px | Dos pruebas, con el aviso sobre las IP |
| `var(--sp-21)`, que nadie definió | `tokens usados y no definidos: {'sp-21'}` |
| El hover del login vuelve a aclarar | `button:hover:not(:disabled) → 3.37:1 (base: button)` |

### Verificación en el servidor

Jinja cachea las plantillas cuando el modo depuración está apagado, así que el panel
que estaba corriendo seguía sirviendo el `<style>` embebido: **hubo que reiniciarlo**.
Es comportamiento normal de Flask, no un defecto, pero conviene tenerlo presente el
día de la defensa si se toca una plantilla.

Tras reiniciar, las dos pantallas sirven `tokens.css` antes que su hoja propia, y el
login devuelve **0 bloques `<style>`**.

### Estado

`913 pruebas, 2 omitidas, ~105 s` y `./scripts/check.sh` **todo en verde**. Hubo un
hallazgo de ruff en mi propia prueba (`SIM300`, condición Yoda); corregido.

---

## 4.16 Iconos SVG monocromos (tarea G3)

### Por qué los emoji eran un problema

Un emoji no es un icono: es un **mapa de bits multicolor** que aporta cada sistema
operativo. 🛰️ no se parece en Windows, macOS y Linux; su tamaño y línea base no se
controlan; y —lo que más pesa acá— **no hereda el color del texto**.

En este panel el color *significa* algo: severidad, estado del análisis, decisión. Un
glifo que trae su propia paleta compite con esa información en lugar de acompañarla.

Dos casos lo mostraban con claridad:

* El 🟥 del panel de eventos activos **ni era un icono**: era un cuadrado rojo. Rojo
  es el color de `CRITICAL` en este sistema, así que un cuadrado rojo permanente en el
  encabezado del panel decía algo que no era cierto.
* El 🟢 / 🟡 de la insignia de modo ponía el verde y el ámbar **desde el sistema
  operativo**, no desde el significado: la clase CSS ya definía el color y el emoji lo
  ignoraba.

### Lo que se hizo

Un sprite de **14 símbolos** en `templates/_iconos.html`, con `currentColor` y
`viewBox` de 24×24. Se usan como `<svg class="ico"><use href="#i-candado"></use></svg>`
y se dimensionan en `em`, así que crecen con el texto que acompañan y no hace falta un
tamaño por cada lugar donde aparecen.

| Símbolo | Reemplaza | Dónde |
|---------|-----------|-------|
| `i-escudo` | 🛡️ | marca del panel y del login |
| `i-info` | ℹ️ | «Cómo funciona este panel» |
| `i-actividad` | 🟥 | «Eventos de Seguridad Activos» |
| `i-registro` | 📜 | «Registro de Eventos del Sistema» |
| `i-reloj` | 🕒 / 🕘 | «Ataques Recientes», antecedentes de una IP |
| `i-archivo` | 🗂️ | «Historial de Decisiones» |
| `i-candado` | 🔐 | `ssh_brute_force` |
| `i-radar` | 🛰️ | `port_scan` |
| `i-anzuelo` | 🎣 | `credential_harvesting` |
| `i-interrogacion` | ❓ | `suspicious_auth` |
| `i-advertencia` | ⚠️ | tipo de ataque desconocido |
| `i-enlace` | 🔗 | campaña (icono y banner) |
| `i-idea` | 💡 | «Por qué esta severidad» |
| `i-lupa` | 🔍 | «Evidencia» |

El punto de estado del modo pasó a ser un círculo CSS con `background: currentColor`,
así que lo pinta la clase del modo (`--ok-texto` o `--med`) y **siempre** coincide con
el texto de al lado.

### Lo que se dejó como texto, a propósito

`→ ▸ ▾ ✕ ✔ ✘ ↻` son glifos **tipográficos**: ya son monocromos y ya heredan el color.
Pasarlos a SVG sería más marcado sin ninguna ganancia. La prueba que barre emoji los
tiene en una lista explícita, para que la decisión quede escrita y no parezca un olvido.

### Decisiones de implementación

**El sprite va embebido, no en un archivo aparte.** `<use>` apuntando a un SVG externo
no funciona en todos los navegadores. Lo incluyen las dos plantillas con
`{% include '_iconos.html' %}`.

**`ico()` valida el identificador.** Devuelve un `FragmentoSeguro` —el marcado es SVG,
no texto— y el identificador sale **siempre** de un mapa cerrado de `app.js`, nunca de
datos del servidor. La validación `^i-[a-z]+$` deja escrito que eso es una condición y
no una casualidad: si alguien mañana lo alimenta con datos del servidor, revienta en
lugar de inyectar marcado.

**Los iconos llevan `aria-hidden="true"`.** Cada uno va al lado de su texto; sin eso,
un lector de pantalla anunciaría el nombre del SVG **además** de la etiqueta.

**Salió también el último `style=` en línea.** El colapso de evidencia se generaba con
`style="display:none"` desde JavaScript — la misma clase de problema que acabábamos de
sacar de las plantillas, en un lugar que ninguna herramienta miraba. Ahora es la clase
`.oculto`.

### Costo, con honestidad

El sprite son **2 257 bytes** de marcado. La página de login lo incluye entero y usa un
solo símbolo, así que el 61 % de sus 3 714 bytes es sprite que no dibuja. Se podría
filtrar por pantalla, pero un `include` compartido es más simple de mantener que dos
sprites que se desincronizan, y el absoluto es despreciable.

### Pruebas automatizadas

`tests/unit/test_iconos.py` — **67 pruebas**:

| Qué fija |
|----------|
| El sprite es **XML bien formado** y cada `path` usa solo comandos SVG válidos |
| **Cada `<use href="#…">` apunta a un símbolo que existe** — un id mal escrito no falla, dibuja nada |
| No quedan símbolos sin usar (peso muerto en cada carga) |
| Cada id respeta el patrón `^i-[a-z]+$` que `ico()` valida |
| Cada símbolo declara `viewBox` — sin él no escala y se ignora el tamaño en `em` |
| Las dos pantallas incluyen el sprite y enlazan `iconos.css` |
| **No quedan emoji de color** en plantillas ni en JavaScript |
| `.ico` y `.punto` usan `currentColor` y no fijan un color |
| Los iconos generados desde JS llevan `aria-hidden` |
| `app.js` no construye ningún `style=` en línea |
| **Cada tipo de ataque del clasificador tiene su icono** (cruce con `classifier.py`) |
| Hay un icono de reserva para un tipo desconocido |
| `ico()` ejecutado **en Node**: produce el marcado esperado, devuelve `FragmentoSeguro`, y **rechaza 7 identificadores inválidos** |

La fila del cruce es la que sostiene `RNF-USA-07` ("icono estable por tipo de ataque"):
si alguien agrega un detector al clasificador sin agregar su icono, el incidente
aparecería con el de advertencia genérico y esa estabilidad se perdería en silencio.
La prueba lee la tabla de `_classification` en `classifier.py`, no una lista copiada.

`test_iconos.py` usa `subprocess` para ejecutar el `ico()` **real** en Node, por la
misma razón que `test_s02`: reimplementarlo en Python probaría el test y no el código
que se despliega. Se sumó al allowlist exacto de `tests/test_no_autonomy.py`.

### Dos correcciones de prueba, no de código

1. **El emoji del comentario.** El barrido marcó el 🟥 del comentario del sprite, que
   explica *qué reemplaza* `i-actividad`. Un comentario no es interfaz: ahora se quitan
   comentarios de Jinja, HTML y JavaScript antes de barrer (los `//` solo cuando abren
   la línea, para no romper un `https://`).
2. **El corte del sprite para parsearlo.** Empezaba en el primer `<svg` del archivo, y
   ese está **dentro del comentario de cabecera**, que muestra cómo usarlo: se parseaban
   0 símbolos y la prueba pasaba por vacío. Se quitan los comentarios primero, y
   `test_hay_simbolos_en_el_sprite` exige al menos 10 para que no vuelva a pasar
   desapercibido.

### Dos hallazgos de configuración

**`S314` eximido para `tests/**`.** Parsear el sprite con `xml.etree` disparó el aviso
de ruff sobre XML no confiable. Acá la entrada es un archivo versionado del propio
repositorio, así que no justifica sumar `defusedxml`. Se eximió **en `ruff.toml`, con
su razón escrita**, y no con un `# noqa` en línea: el proyecto no tiene supresiones
inline por hallazgos de seguridad y no era el momento de empezar.

**Un `# noqa` que no era un `noqa`.** Ruff avisaba en cada corrida:
`Invalid # noqa directive on tests/unit/test_b0x_robustez_y_formatos.py:311`. Alguien
había escrito el marcador propio del proyecto (`MARCA_EXCEPCION = "ventana-ok"`) con el
prefijo `# noqa:`, que ruff intenta interpretar como lista de códigos. Los otros cuatro
usos del marcador son comentarios simples. Corregido — y de paso desaparece un aviso
que estaba ahí desde la Fase 2.

### Verificación en el servidor

Tras reiniciar el panel (Jinja cachea plantillas, ver §4.15):

| Página | Símbolos servidos | `<use>` en el HTML | Emoji |
|--------|-------------------|--------------------|-------|
| `/login` | 14 | 1 | **0** |
| `/` (autenticado) | 14 | 7 | **0** |

Los `<use>` restantes del panel los genera `app.js` al renderizar cada incidente.

### Estado

`982 pruebas, 2 omitidas, ~121 s` y `./scripts/check.sh` **todo en verde**.

---

## 4.17 Un estado no se pinta como una acción (tarea G4)

### El problema

En la fila de cada acción recomendada convivían dos pastillas:

```
[ approved ]   1. Bloquear la IP en el firewall        [ Aprobar ] [ Descartar ]
  ↑ estado                                              ↑ acción
```

Las dos eran **relleno verde saturado con texto blanco** (`var(--ok)` + `#fff`). Una
informa qué pasó; la otra ofrece hacer algo.

Un relleno saturado dice "apretame". El chip invitaba a un clic que no existe — y
peor: el analista podía leer «aprobada» como si todavía tuviera que aprobar. En el
panel donde la decisión humana es el único mecanismo de contención, esa ambigüedad no
es cosmética.

### La corrección

Se separan los dos lenguajes:

| | Tratamiento | Qué comunica |
|---|---|---|
| **Estado** | Tinte + borde | «esto ya pasó» — se lee como etiqueta |
| **Acción** | Relleno sólido | «se puede hacer algo» — se lee como control |

| Chip | Fondo | Texto | Contraste |
|------|-------|-------|-----------|
| `pendiente` | `--panel3` | `--muted` | 4.95:1 ✅ |
| `✔ aprobada` | `--tenue-ok` `#10261a` | `--ok-texto` | 10.40:1 ✅ |
| `✘ descartada` | `--tenue-no` `#2d1113` | `--tenue-no-texto` | 8.99:1 ✅ |

Los botones **no** se tocaron: conservar su relleno sólido es la otra mitad de la
separación. Si también se atenuaran, se perdería la señal de «acá se puede hacer algo».

### La marca, que no es decoración

El chip lleva `✔` / `✘`. Verde y rojo no alcanzan: alrededor del **8 % de los varones**
tiene alguna deficiencia en la visión del rojo y el verde, y para esa persona los dos
chips atenuados se parecen. La marca resuelve la distinción sin ocupar espacio, y es
`RNF-USA-08` — el mismo requisito que el contraste de §4.14 y la navegación por teclado
de §4.7.

### El chip mostraba el valor crudo de la API

Salió al reescribirlo: `<span class="state s-${a.status}">${a.status}</span>` ponía
`approved`, `pending`, `dismissed` —en inglés— en un panel en español. Y el **historial
de decisiones**, unas líneas más abajo en el mismo archivo, ya traducía con marca
(`"✔ Aprobada" : "✘ Descartada"`).

Dos vocabularios para lo mismo, en la misma pantalla. Se unificó en un mapa
`ESTADO_TEXTO`, y hay una prueba que verifica que el chip y el historial no se
desincronicen. La **clase** sigue usando el valor crudo: es lo que elige el color, y
hay otra prueba que lo exige.

### Los tokens se renombraron

`--err-fondo` / `--err-texto` / `--aviso-fondo` / `--aviso-texto` eran los avisos del
login (§4.15). El nombre era demasiado estrecho: el mismo lenguaje visual —fondo teñido
+ texto legible— sirve ahora también a los chips del panel de decisión. Pasaron a
`--tenue-ok`, `--tenue-no` y `--tenue-aviso`, con el porqué escrito.

`--tenue-ok-texto` se declara como **alias** (`var(--ok-texto)`) y no repitiendo el hex,
por la misma razón que `--err`: si se repitiera, nada impediría que uno cambie y el otro
no.

De paso se consolidó `#ff9492`, un rojo suelto a tres unidades del token, que usaba
`.decision-item .dec-dismissed`. El contraste **sube** de 8.16:1 a 8.90:1.

### Pruebas automatizadas

`tests/unit/test_estado_y_accion.py` — **18 pruebas**:

| Qué fija |
|----------|
| **Ningún `.s-*` comparte su fondo con un `button.*.on`** — el defecto, en una prueba |
| Los chips tienen borde y no usan texto blanco (el del relleno sólido) |
| Los botones activos **conservan** su relleno sólido con texto blanco |
| Cada estado posible tiene su regla CSS y su etiqueta en español |
| El chip interpola la etiqueta, no el valor de la API; la **clase** sí usa el valor crudo |
| Los estados decididos se distinguen sin color (llevan `✔` / `✘`) |
| El chip y el historial de decisiones usan el mismo vocabulario |
| El modo solo lectura esconde los **controles** y no los **estados** |

Los estados salen de `dashboard.DECISIONES_VALIDAS` más `pending`, importando el módulo:
no es una lista copiada. Si alguien agrega una decisión válida sin su regla CSS y su
etiqueta, tres pruebas fallan.

La última fila cruza con los roles: para un `viewer` el panel es lectura pura, y con los
estados atenuados eso se refuerza — no quedan rellenos sólidos invitando a un clic que
el rol no tiene. La no-autonomía va por otro lado (ningún rol ejecuta contención, §4.6),
pero que la interfaz no ofrezca lo que no se puede hacer es parte de lo mismo.

### Mutación

| Inyectado | Detectado |
|-----------|-----------|
| `.s-approved` vuelve a `var(--ok)` + `#fff` | `usa #238636, el mismo fondo que button.approve.on` (y el texto blanco, por separado) |
| El chip vuelve a interpolar `${a.status}` | `el chip interpola «a.status» como texto: es el valor de la API` |
| Se saca la marca `✔` de la etiqueta | `«approved» se distingue solo por el color` |

### Estado

`1000 pruebas, 2 omitidas, ~109 s` y `./scripts/check.sh` **todo en verde**. Los
archivos estáticos no se cachean como las plantillas, así que el panel corriendo ya
sirve los cambios sin reiniciar; verificado con `curl`.

---

## 4.18 La fila de resumen destaca lo que pide una decisión (tarea G5)

### El problema

Siete recuadros del mismo tamaño y el mismo peso:

```
[ 5 ]        [ 12 ]     [ 7 ]        [ 0 ]      [ 5 ]    [ 0 ]     [ 0 ]
Incidentes   Acciones   Pendientes   Críticos   Altos    Medios    Bajos
```

Nada estaba destacado, así que nada guiaba la mirada. Y como las severidades suelen
concentrarse en una o dos, **tres de los siete mostraban 0** con la misma prominencia
que el número que importa.

Ese número es uno: **cuántas acciones esperan una decisión humana**. Es lo que este
panel existe para resolver — «la IA sugiere, el humano decide». El resto es contexto.

### Lo que se hizo

```
  4                  5 incidentes            ▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇        ↻ auto cada 15s
  acciones esperan   6 acciones sugeridas    ● 1 críticos  ● 3 altos
  tu decisión                                ● 1 medios    ● 0 bajos
```

| Antes | Ahora |
|-------|-------|
| 7 recuadros iguales | 1 número principal + 2 líneas de contexto + barra con leyenda |
| Nada destacado | El número principal se **enciende** (`--accent`) solo si hay pendientes |
| 4 recuadros de severidad | Barra apilada proporcional + leyenda compacta |
| Siete ceros si no hay incidentes | Estado vacío que dice qué correr |

**La jerarquía sale de degradar el contexto, no de inflar el número.** El principal
sigue en `--fs-2xl` (20px, el mismo que tenían los siete) y el contexto baja a
`--fs-sm`. Un dígito de 32px habría pedido un décimo token tipográfico y habría quedado
ajeno a un tablero denso de 13px — se decidió respetar la escala de §4.15 en lugar de
subirle el tope a la prueba que la vigila.

### Los ceros no se esconden

Esconder las severidades en cero habría dejado un resumen más limpio y **menos
informativo**: un cero dice «miramos y no hay críticos», que en un panel de seguridad
no es lo mismo que no decir nada. La leyenda lista las cuatro siempre; lo que cambia es
que el conteo en cero no toma el color del texto, así que deja de competir.

**No se usó `opacity` para atenuarlos.** Sobre un texto que ya es `--muted`, una
opacidad del 45 % hunde el contraste por debajo de AA — y el barrido de contraste de
§4.14 **no modela la opacidad**, así que no lo habría detectado. Hay una prueba que
prohíbe `opacity` en la leyenda por ese motivo.

### La proporción es un dato, no un estilo

El ancho de cada segmento depende de cuántos incidentes hay: no puede vivir en una hoja
estática. Viaja como propiedad personalizada `--dato-n`, y `.seg { flex: var(--dato-n) 1 0 }`
la consume.

Eso choca con la prueba de §4.16 que prohíbe `style=` en el JavaScript, así que se
**refinó la regla** en lugar de esquivarla: se permite `style="--dato-…: valor"` y sigue
prohibida cualquier declaración CSS (`display`, `color`, `width`). El prefijo `--dato-`
distingue un dato de un token de diseño, y habilitó dos pruebas nuevas:

* un `var(--dato-…)` que el CSS consume **tiene que definirlo** algún JavaScript;
* un `var(--…)` sin ese prefijo tiene que estar en `tokens.css`.

Verificado por mutación: `style="display:flex"` se rechaza, `style="--dato-n:3"` pasa.

### Verificación: el resumen renderizado de verdad

Se ejecutó `renderSummary` en **Node con un DOM simulado** (`innerHTML` como setter que
convierte a texto, igual que el DOM real) y se leyó el HTML de cuatro casos:

| Caso | Salida |
|------|--------|
| Sin incidentes | «Sin incidentes en la ventana de 24 horas. Generá uno con `./scripts/demo-ataque.sh`.» |
| 1 incidente, 1 pendiente | «**1** acción espera tu decisión» · 1 incidente · 1 acción sugerida · 1 segmento |
| Todo decidido | «**0** sin decisiones pendientes», sin la clase `hay-pendientes` |
| 5 incidentes, 4 pendientes | «**4** acciones esperan tu decisión» · 3 segmentos con `--dato-n` 1/3/1 · `bajos` marcado como `cero` |

**Y encontró algo.** Con cero pendientes el rótulo decía «0 acciones esperan tu
decisión», que bajo un cero grande se lee raro. Ahora dice «sin decisiones pendientes».
Leyendo el código eso pasaba bien; leyendo la salida, no.

### Pruebas automatizadas

`tests/unit/test_resumen.py` — **19 pruebas**:

| Qué fija |
|----------|
| **El número grande es el de pendientes**, no el total de incidentes |
| Se enciende con `--accent` solo si hay pendientes; sin ellos queda atenuado |
| El contexto está degradado (`--fs-sm` contra `--fs-2xl`) |
| No reaparecen las siete cajas `.stat` |
| Cada severidad tiene color en la barra y en la leyenda |
| **Las severidades del resumen son las que puede emitir el Agente 2** (cruce con `_SEV_VALIDAS`) |
| La barra solo dibuja segmentos con conteo (un segmento de 0 es una astilla de 1px) |
| La proporción viaja como `--dato-n` y la hoja la consume |
| La barra va `aria-hidden` y la leyenda es el contenido accesible |
| **La leyenda lista las cuatro severidades, incluidas las de cero** |
| El cero se lista pero no se resalta, y **no se atenúa con `opacity`** |
| Hay estado vacío, menciona la ventana de 24 h y dice qué correr |
| El estado vacío conserva el aviso de refresco |
| Los conteos concuerdan en singular y plural, en los tres casos |

### Mutación

| Inyectado | Detectado |
|-----------|-----------|
| El número grande vuelve a `incs.length` | `el número destacado es «incs.length» y tiene que ser el de acciones pendientes` |
| La leyenda filtra los ceros | `la leyenda esconde las severidades en cero` |
| Se atenúa la leyenda con `opacity: .45` | `la leyenda usa opacity: atenuar así rompe el contraste sin que se note` |
| `style="display:flex"` en la barra | `app.js construye declaraciones CSS en línea: ['display:flex']` |

La primera mutación falló primero con un mensaje pobre (`no encontré el número
principal`), porque la expresión capturaba `\w+` y `incs.length` tiene un punto. Se
corrigió para que el fallo **diga qué encontró**: una prueba que no diagnostica cuesta
más de lo que ahorra.

### Estado

`1020 pruebas, 2 omitidas, ~111 s` y `./scripts/check.sh` **todo en verde**.

---

## 4.19 D-11 · El panel atribuía a Elastic detecciones que no pasaron por Elastic

Salió al preparar la demostración desde cero (`docs/16`), cuando había que responder
con precisión qué aparece por las reglas desplegadas y qué no.

### Lo que hacía

`detect_port_scans` y `detect_phishing` fijaban a mano:

```python
rule_name="Network port scan detection",  severity_siem="high", risk_score=47
rule_name="Credential submission to suspicious login page", severity_siem="high", risk_score=68
```

**Ninguno de esos nombres existe en Kibana.** El catálogo llama a esas reglas «Port
Scan – Many Distinct Ports» y «Credential Submission to Suspicious Login». El campo se
llama `severity_siem` —severidad *del SIEM*— y el panel lo mostraba bajo la etiqueta
«Regla SIEM».

Y esos dos detectores **ni siquiera consultan Elasticsearch**: leen `network_logs/`
directamente, porque en este laboratorio no hay Suricata. Aparecen aunque no haya una
sola regla desplegada.

Un evaluador que abriera un incidente de escaneo, leyera el nombre y lo buscara en
Kibana no lo encontraría — en el peor momento posible.

### Por qué era peor que una imprecisión

El proyecto **sí** tiene algo bueno que decir acá: hay dos caminos de detección y el
sistema funciona aunque el SIEM no dispare. El nombre inventado tapaba ese argumento
con otro que no era cierto.

### La corrección

Cada incidente declara su procedencia en `detection_source`:

| Valor | Cuándo | Qué trae |
|-------|--------|----------|
| `"elastic"` | Se construyó desde una alerta real | `rule_name`, `severity_siem` y `risk_score` son los de esa alerta |
| `"clasificador"` | Lo detectó el Agente 1 por su cuenta | Nada que citar: los tres campos quedan en `None` |

El panel pasó de «Regla SIEM: …» a «Detección: …», y lo dice en positivo —«Agente 1 ·
detección determinística»— en vez de solo negar que haya regla.

### El riesgo del arreglo, y cómo se cubrió

Vaciar `severity_siem` podía hacer que el panel cayera a `MEDIUM` y **degradara en
silencio** un incidente — exactamente lo que se evitó en G1 (§4.14) con el Agente 2.

La cadena de respaldos del panel estaba además **repetida en seis lugares**, así que
cualquiera de los seis podía quedar atrás. Se unificó en `severidadDe()` con el orden
correcto:

1. lo que ajustó el Agente 2
2. la severidad que trajo la alerta, si la hubo
3. **la del Agente 1, que siempre existe** ← el respaldo que faltaba
4. `MEDIUM`, que a esta altura significa «algo se rompió»

Verificado sobre los incidentes reales: ninguna severidad se degradó.

### Pruebas

`tests/unit/test_procedencia_de_la_deteccion.py` — **17 pruebas**:

| Qué fija |
|----------|
| El escaneo y el phishing no inventan regla ni severidad del SIEM |
| Con alerta, la procedencia es `elastic`; sin alerta, `clasificador` |
| **`classifier.py` no asigna ningún `rule_name` literal** — se recorre el AST, así que un comentario que *cite* el nombre viejo no cuenta |
| Los nombres que inventaba no existen en el catálogo (por qué era engañoso) |
| Solo hay dos procedencias posibles: el panel decide con `=== "elastic"` |
| **Sin severidad del SIEM queda la determinística**, no `MEDIUM` — los cuatro tipos |
| El panel decide la severidad en un solo lugar y la cadena incluye la determinística |
| El panel muestra la procedencia y ya no la etiqueta «Regla SIEM» |

Mutación: reintroducir el nombre inventado dispara dos pruebas; quitar el respaldo
determinístico dispara la de la cadena.

---

## 4.20 D-12 · Una agregación sin `.keyword` rompía toda la captura del SIEM

Este solo aparece **arrancando de cero**, y por eso había sobrevivido.

### El síntoma

Con los índices de Filebeat recién creados, el pipeline imprimía:

```
[ERROR] HTTP 400 desde Elasticsearch: 400 Client Error: Bad Request
        for url: http://localhost:9200/filebeat-*/_search
[INFO] No se sobreescribe 'siem_clean.json' para preservar la última captura.
```

y clasificaba **solo desde `network_logs/`**: ningún incidente de autenticación,
ninguna procedencia «Elastic SIEM». La demostración perdía justo la fila que la
justifica.

### La causa

```
Fielddata is disabled on [source_ip] in [filebeat-8.12.2-2026.09.26].
Text fields are not optimised for operations that require per-document field data
like aggregations and sorting…
```

No hay **plantilla de índice** para `filebeat-*` (verificado:
`GET _index_template/filebeat*` devuelve ninguna), así que el mapeo es dinámico y
`source_ip` queda como `text` con subcampo `keyword`. `siem_lib.source_ip_aggregation`
agregaba sobre el `text`.

**El catálogo de reglas ya documentaba esta trampa** y se corrigió en P3, donde las
reglas pasaron a agrupar por `source_ip.keyword`. `siem_lib` quedó afuera: las reglas
son datos y esto es código, y la corrección no cruzó la frontera.

### Por qué no se había notado

`prepare-for-ia.py` es una etapa **tolerable** del orquestador: si falla, el pipeline
sigue con los datos que haya y termina con **código 0**. Eso está bien para el modo
offline —el sistema funciona sin stack— pero significa que el error se veía solo
leyendo el log, y el `siem_clean.json` de una captura anterior mantenía la ilusión de
que todo andaba.

### La corrección

Una línea: `"field": "source_ip.keyword"`. Las claves del bucket siguen siendo las IP,
así que `build_summary` no cambia.

Verificado después del arreglo: la captura pasó de fallar a traer **4 alertas y 20
logs de autenticación**, y aparecieron los incidentes de fuerza bruta con el nombre de
la regla que los disparó.

### La guarda que faltaba en la demostración

El script de la demostración redirigía la salida del pipeline a un log y solo imprimía
«pipeline completo»: el aviso quedaba invisible. Ahora `demo-desde-cero.sh` **exige que
la captura sea nueva** (menos de 10 minutos) y aborta con un mensaje explícito si no lo
es:

```
✗ LA CAPTURA DE ELASTICSEARCH NO SE RENOVÓ (VIEJA 2026-09-20T10:00:00+00:00)
  El pipeline siguió con los datos que había —es una etapa tolerable— y terminó
  bien, pero lo que vas a ver NO sale de esta corrida.
  No presentes así: la demostración afirma justamente lo contrario.
```

Verificado en sus tres rutas: captura fresca (`OK 22 20`), vieja (`VIEJA …`) y ausente
(`FALTA`).

### Pruebas

`tests/unit/test_agregaciones_keyword.py` — **6 pruebas**:

| Qué fija |
|----------|
| **La agregación por IP origen usa `.keyword`** |
| Sigue devolviendo el mismo bucket (`by_source_ip`), así que el consumidor no cambia |
| Barrido: ninguna consulta de `siem_lib` agrega sobre un campo de texto sin sufijo |
| Barrido sobre el **código fuente**, para atrapar una agregación nueva en una función que estas pruebas no llaman |
| Las reglas del catálogo también agrupan por `.keyword` — el mismo defecto a los dos lados de la frontera código/datos |

`kibana.alert.rule.name` está en una lista explícita de campos que **ya** son keyword
por mapeo del motor de detección, con su razón escrita.

---

## 4.21 La demostración desde cero (`scripts/demo-desde-cero.sh`)

Responde la pregunta que `demo.sh` y `demo-ataque.sh` dejan abierta: *«¿cómo sé que el
panel no está mostrando un archivo preparado?»*. Pone los cuatro números en cero
delante del público y construye el resultado en siete pasos.

| Modo | Qué hace |
|------|----------|
| `./scripts/demo-desde-cero.sh` | Limpia y guía la demostración entera, con pausas |
| `--limpiar` | Solo deja todo en cero y sale |
| `--estado` | Los cuatro números, sin tocar nada |
| `--rapido` | Sin pausas (para ensayar) |
| `--sin-docker` | Omite la fuerza bruta con Hydra |
| `--si` | No pregunta antes de borrar |

**No baja Docker.** Borra índices, alertas, reglas y artefactos del pipeline por API:
la limpieza tarda segundos en vez de los minutos que lleva reiniciar Elasticsearch. El
registro de auditoría se **archiva** en `audit/archive/`, nunca se borra (A-01).

### Corrida verificada, 26-09-2026

| Momento | Reglas | Alertas | Documentos | Incidentes |
|---------|--------|---------|------------|------------|
| Al empezar | 13 | 777 | 61 142 | 5 |
| Tras limpiar | **0** | **0** | **0** | **0** |
| Al terminar | 13 | 4 | 140 | 3 |

Resultado final, con la procedencia a la vista:

```
port_scan              alta      26  Agente 1 · determinística (sin pasar por Kibana)
ssh_brute_force        alta      20  Elastic SIEM · SSH Brute Force – Aggressive per Source IP
credential_harvesting  alta       1  Agente 1 · determinística (sin pasar por Kibana)
```

### Las llamadas de borrado, verificadas en aislamiento

Antes de escribirlas en el script se probaron sueltas, para que no fallen en medio de
una defensa:

| Llamada | Resultado |
|---------|-----------|
| `POST /api/detection_engine/rules/_bulk_action {"action":"delete"}` | `{"succeeded": 13, "failed": 0}` |
| `POST .alerts-security.alerts-default/_delete_by_query` | `{"deleted": 777, "failures": []}` |
| `DELETE /filebeat-*` | **falla**: `Wildcard expressions or all indices are not allowed` |
| `DELETE /<lista de 12 índices por nombre>` | `{"acknowledged": true}` |

La tercera fila es la que obligó a enumerar: Elasticsearch trae
`action.destructive_requires_name` activo y rechaza el comodín. Queda escrito en el
script para que nadie lo vuelva a intentar.

### El guion completo

`docs/16-demostracion-desde-cero.md`: qué correr, en qué orden, **qué decir mientras
corre** y qué contestar si preguntan. Incluye la tabla de fallos posibles y lo que
**no** hay que afirmar.

### Estado

`1043 pruebas, 2 omitidas, ~91 s` y `./scripts/check.sh` **todo en verde**.

---

## 4.22 La evidencia, en una carpeta (`scripts/evidencia.sh`)

Los dos primeros objetivos de la materia son **pruebas de código estático** y
**pruebas de servicios**. El proyecto las corría —`check.sh` hace las dos cosas— pero
la salida se iba por pantalla: no quedaba nada que adjuntar a un informe ni que
mostrar si la demostración en vivo fallaba.

`./scripts/evidencia.sh` deja `evidencia/<fecha>/` con las salidas **crudas** de cada
herramienta, sin editar ni resumir, más un `00-resumen.md` que explica qué prueba cada
archivo.

| Archivo | Objetivo | Qué prueba |
|---------|----------|------------|
| `01-analisis-estatico.txt` | 1 | ruff, pylint + secure-coding-standard, bandit y ESLint + security corriendo sobre el código |
| `02-la-puerta-atrapa.txt` | 1 | **Se inyecta una vulnerabilidad real y se muestra que la puerta la encuentra** |
| `03-pruebas-de-servicio.txt` | 2 | Nueve peticiones HTTP reales contra el panel corriendo, con su respuesta textual |
| `04-suite-y-cobertura.txt` | 2 | La suite completa con medición de cobertura |
| `05-no-autonomia.txt` | transversal | La certificación por AST de que nada puede ejecutar contención |

### La pieza que convierte esto en prueba

Un informe que dice «el análisis estático pasa» no prueba nada: podría estar mal
configurado y pasar siempre. El archivo `02` inyecta `hashlib.md5()` en `siem_lib.py`,
corre las herramientas y guarda lo que devuelven:

```
── ruff DESPUÉS de inyectar ──
S324 Probable use of insecure hash functions in `hashlib`: `md5`
   --> siem_lib.py:620:12

── bandit DESPUÉS de inyectar ──
>> Issue: [B324:hashlib] Use of weak MD5 hash for security.
   Severity: High   Confidence: High
```

y revierte con un `trap EXIT`, dejando el SHA-256 del archivo en el propio informe
para que se vea que quedó idéntico. Verificado: tras la corrida, `ruff check .`
devuelve `All checks passed!` y el archivo no conserva rastro de la inyección.

### Los rechazos son el control funcionando

Las nueve peticiones de servicio, con lo que devolvió el servidor:

| # | Petición | Código |
|---|----------|--------|
| 1 | `GET /api/v1/healthz` (público) | 200 |
| 2 | `GET /api/v1/incidents` sin sesión | **401** |
| 3 | `POST /api/v1/login` analista | 200 |
| 4 | `POST /api/v1/decision` con sesión, sin CSRF | **403** |
| 5 | `POST /api/v1/decision` con CSRF, acción inexistente | **404** |
| 6 | `POST /api/v1/decision` con CSRF, JSON roto | **400** |
| 7 | `GET /api/v1/audit/verify` como **analyst** | **403** |
| 8 | `GET /api/v1/audit/verify` como **auditor** | 200 |
| 9 | `POST /api/v1/decision` como **auditor** | **403** |

Las filas 7 y 9 son el par que conviene mostrar junto: el analista decide y no audita;
el auditor audita y no decide. Ninguno de los tres roles puede ejecutar contención —
no es un permiso ausente de la tabla, es una capacidad que no existe.

### Corrida verificada, 26-09-2026

`1053 pruebas, cobertura 95 %, 36 verificaciones de no-autonomía`, 0 hallazgos nuevos
de análisis estático (líneas de base en cero).

La carpeta `evidencia/` está en `.gitignore`: es un artefacto de cada corrida, no algo
que se versione.

---

## 4.23 D-13 · Siete de las trece reglas no llegan al panel

Salió al responder qué pasa si alguien escribe sus propias reglas en Kibana.

`detect_auth_incidents` filtra las alertas por una lista blanca de **una sola
técnica**:

```python
_AUTH_MITRE_TECHNIQUES = {"T1110"}
if technique_id and technique_id not in _AUTH_MITRE_TECHNIQUES:
    continue
```

El filtro es correcto en lo suyo —sin él, una alerta de port scan se procesaría como
un incidente SSH con 0 eventos reales y una IP que nunca hizo fuerza bruta— pero deja
un hueco: **ninguna otra ruta convierte una alerta en incidente.**

Probado sobre el clasificador, con alertas sintéticas:

| Regla mapeada a | ¿Produce incidente? |
|-----------------|---------------------|
| `T1110` (fuerza bruta) | **Sí** |
| `T1046` (escaneo) | No, se descarta |
| `T1566` (phishing) | No, se descarta |
| `T1059` (ejecución) | No, se descarta |
| **Sin mapeo MITRE** | **Sí**, pero se procesa como incidente de autenticación |

Y medido sobre el catálogo desplegado: **6 de 13 reglas** producen incidentes. Las
otras 7 (B1–B4 de escaneo, C1–C3 de phishing) disparan en Kibana y su alerta se
descarta. Los incidentes de escaneo y phishing que sí aparecen los produce el Agente 1
leyendo `network_logs/` — ver §4.19.

La última fila de la tabla es la más engañosa: una regla **sin** mapeo MITRE pasa el
filtro y se trata como autenticación aunque detecte otra cosa.

**Queda abierto.** Cerrarlo pide un detector que convierta en incidente cualquier
alerta que los detectores específicos no reclamen, con un playbook genérico sin
comando sugerido. Eso cambia el modelo de incidentes y es una decisión de diseño del
equipo, no una corrección puntual. Registrado como **D-13** en la auditoría.

---

## 4.24 El umbral de A2 no coincidía con su catálogo

`rules/rules.md` documentaba «≥10 fallos por source_ip en 1 min» y el archivo
desplegaba **3**. Cuando la tabla y el archivo se separan, gana el archivo y la
documentación miente en silencio.

Peor: **invertía la escalera de severidad.**

| Regla | Severidad | Umbral desplegado |
|-------|-----------|-------------------|
| A1 | medium | 5 |
| A2 | **high** | **3** ← disparaba antes que A1 |
| A5 | critical | 50 |

Tres contraseñas mal tipeadas producían una alerta de severidad **alta** antes de que
la regla *medium* llegara a su umbral. Corregido a 10 y redesplegado (versión 2).

### Pruebas

Se agregaron 4 pruebas a `tests/unit/test_reglas_como_codigo.py`:

| Qué fija |
|----------|
| Se leen al menos 8 umbrales de `rules.md` (blindaje del andamiaje) |
| **Cada regla con un `≥N` documentado despliega ese número** — B1 y B2 comparan contra `threshold.cardinality`, que es donde vive su umbral |
| La escalera medium → high → critical exige umbrales crecientes |
| Las reglas sin umbral numérico (A4 EQL, B3 consulta, B4/C1/C3 secuencia) se omiten explícitamente |

Mutación: devolver A2 a 3 dispara las dos, con el mensaje
`la escalera se invirtió: medium=5, high=3, critical=50`.

---

## 5. Cobertura

| Módulo | Fase 1 | Fase 2 | **P1** | Sin cubrir |
|--------|:------:|:------:|:------:|------------|
| `siem_validators.py` | 100 % | 100 % | **100 %** | — |
| `siem_auth.py` | — | — | **99 %** | dos ramas de error del almacén |
| `siem_lib.py` | 88 % | 95 % | **96 %** | ramas de error sin ES real |
| `classifier.py` | 94 % | 95 % | **95 %** | `main()` y una rama de severidad |
| `manage_users.py` | — | — | **94 %** | entrada interactiva de contraseña |
| `dashboard.py` | 95 % | 95 % | **90 %** | `__main__` y el resumen de arranque |
| **Total (alcance §4.1)** | 93 % | 95 % | **95 %** | objetivo ≥ 80 % |

`audit_verify.py` se ejercita como proceso (5 pruebas), que es como lo va a usar
CI y una persona en una terminal; por eso no aparece en el informe de cobertura.

`siem_agent.py` sigue fuera del umbral a propósito: su camino principal depende
de la API de Gemini.

---

## 6. Cambios de comportamiento verificados en la Fase 2

Cada corrección produjo fallos en las pruebas de caracterización. **Ningún
cambio de comportamiento pasó inadvertido.**

| Corrección | Pruebas que fallaron | Cómo se resolvió |
|------------|---------------------|------------------|
| R-01 + B-01 + B-02 (`siem_lib`) | 2 | Stub del 404 ajustado a cómo se comporta `requests` de verdad |
| B-03 + B-05 + B324 + A-03 (`classifier`) | 16 | 6 congelados retirados · 10 de caracterización actualizados |
| A-02 + A-04 (auditoría) | 4 | Congelados retirados, reemplazados por 28 pruebas nuevas |
| Dashboard (R-03 + API-02…05) | 15 | 5 congelados retirados · rutas y códigos actualizados |
| R-02 (dataclass `Incident`) | 0 | Sin cambio de comportamiento observable |
| R-04 + W1510 | 0 | Sin cambio de comportamiento observable |
| Estado "heredado" del verificador | 3 | 2 eran bugs reales de la lógica de migración; 1, la forma del dict de respuesta |

**Diferencias medidas en la salida, con los datos reales:**

| | Antes de la Fase 2 | Después |
|---|---|---|
| `ReadTimeout` de Elasticsearch | traceback sin contexto | `ESUnavailable` con mensaje accionable |
| Basic Auth hacia un host remoto por HTTP | permitido en silencio | bloqueado (`ES_ALLOW_INSECURE_HTTP` para optar) |
| Dos corridas del mismo port scan | `event_count` 52 | **26** (ventana de 24 h) |
| `action_id` | posicional (`-a1`, `-a2`) | **derivado del contenido** |
| Editar una decisión ya registrada | indetectable | **rompe la cadena de hash** |
| 20 decisiones concurrentes | escrituras posiblemente entrelazadas | 20 líneas íntegras |
| Permisos del registro | según el umask | **`0600`** |
| Cuerpo JSON malformado | HTML de Werkzeug | **JSON con 400** |
| `note` sin tope | 100 000 caracteres al registro inmutable | **400 si supera 500** |
| `action_id` inexistente | se auditaba | **404, sin escribir** |
| Rutas de la API | 4, sin versionar | 10, con `/api/v1/` y `/healthz` |
| Forma del incidente | distinta según el detector | **idéntica**, con `extras` para lo específico |

### El corte de identificadores

Pasar de SHA-1 a SHA-256 (hallazgo `B324`) cambió el sufijo de **todos** los
`incident_id`, y A-03 cambió la forma de todos los `action_id`. Las decisiones
registradas antes de la Fase 2 quedan huérfanas.

Fue una decisión consciente y de una sola vez: es el momento adecuado, porque
después de la Fase 3 habrá decisiones firmadas por usuarios reales y el costo de
un corte así sería mucho mayor. El plan (§9, tabla de riesgos) lo anticipaba y
la recomendación sigue siendo archivar el `decisions.jsonl` previo con
`scripts/reset.sh` — que ahora lo conserva en `audit/archive/` en vez de
borrarlo.

---

## 7. Deuda de pruebas y próximos pasos

### 7.1 No queda ningún bug congelado

Los 24 hallazgos del plan están cerrados. `pytest -m bug` no colecta nada.

Los dos últimos, ambos de `API-01`, se cerraron en la tarea P1: el campo
`analyst` del registro inmutable sale ahora de la sesión autenticada. La cadena
de hash ya garantizaba que el registro no se alteró después de escribirse;
ahora también se sabe **quién lo escribió**.

### 7.2 Lo que todavía no se prueba

- **Navegador.** No hay pruebas de UI: el E2E con Playwright depende del refactor
  R-05 (extraer el JS de `index.html`) y corresponde a la Fase 3. Hoy el panel se
  verifica por su HTML servido y ejecutando su `esc()` en Node.
- **Elasticsearch real.** Todo corre con fixtures y dobles de prueba.
- **Agente 2 con LLM.** Solo se prueba el fallback y un cliente hostil simulado.
- **Durabilidad ante corte de energía.** `fsync` se verifica de forma
  estructural (que el código lo pida), no provocando un corte real.

### 7.3 Criterio para agregar una prueba

Cada hallazgo corregido deja una prueba de regresión que **falla si el bug
vuelve**, en un archivo nombrado por el hallazgo. Las de caracterización se
actualizan en el mismo commit que cambia el comportamiento, para que el diff del
test muestre exactamente qué cambió y por qué.

Cuando `pytest -m bug` no colecte nada, la deuda registrada estará saldada.
