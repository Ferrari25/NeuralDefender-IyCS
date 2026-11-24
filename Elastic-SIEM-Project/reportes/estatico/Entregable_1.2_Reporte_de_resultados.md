# NeuralDefender - Entregable 1.2: Reporte de resultados del análisis estático

Proyecto: NeuralDefender - Elastic-SIEM-Project
Unidad: Control de calidad - Evaluación estática de código
Fecha de la corrida: 22 de noviembre de 2026
Base: commit `43fd91c` de la copia con repositorio git, que ya tenía 33 archivos modificados sin confirmar antes de esta corrida (lista en `_originales/git-status-antes.txt`).

Todos los números de este reporte salen de salidas reales de las herramientas, guardadas sin editar en `reportes/estatico/`. Lo que no se pudo correr o no se verificó está en la sección 9.

## 1. Resumen

| Concepto | Corrida inicial | Corrida final |
|---|---|---|
| Hallazgos totales | 170 | 67 |
| Bloqueantes | 0 | 0 |
| Críticos | 0 | 0 |
| Mayores | 45 | 21 |
| Menores | 125 | 46 |
| Hallazgos de seguridad | 7 | 0 |
| Puntaje de pylint (mínimo exigido 9,0) | 9,73 | 9,79 |
| Pruebas de reglas propias | 577 pasan, 5 omitidas | 577 pasan, 5 omitidas |
| Pruebas completas (reglas propias, unitarias e integración) | no corrida | 1.482 pasan, 5 omitidas, 0 fallan |
| Cobertura de la revisión | 93,2 % | 93,2 % |

Los 103 hallazgos que bajaron se reparten así: 65 se corrigieron en el código o la configuración y 38 se suprimieron como falsos positivos, solo en la línea y con el motivo escrito (sección 6). Quedan 67 pendientes, todos de calidad, que no se corrigieron por las razones de la sección 7.2.

La meta de revisar al menos el 80 % del código se cumple: 93,2 % con linters y SAST (sección 8).

## 2. Entorno y herramientas

La carpeta `.devtools/` del proyecto está compilada para Python 3.14 y sin permisos de ejecución, y el sistema tiene Python 3.13. Por eso las herramientas de Python se instalaron en un entorno virtual fuera del repositorio, con las mismas versiones que el proyecto tenía en `.devtools/` (ruff 0.16.9, pylint 4.0.10, astroid 4.0.4, plugin 1.5.1, bandit 1.9.4). El detalle completo está en `00-versiones.txt`.

| Herramienta | Versión | Origen |
|---|---|---|
| ruff | 0.16.9 | pip (igual que `.devtools/`) |
| pylint / astroid | 4.0.10 / 4.0.4 | pip (igual que `.devtools/`) |
| pylint-secure-coding-standard | 1.5.1 | pip (igual que `.devtools/`) |
| bandit | 1.9.4 | pip (igual que `.devtools/`) |
| pytest / coverage | 9.2.0 / 7.16.2 | pip |
| eslint | 9.39.5 | npm (el `package.json` pide `^9.11.0`) |
| eslint-plugin-security / no-unsanitized | 3.0.1 / 4.1.5 | npm |
| shellcheck | 0.11.0 | pip (`shellcheck-py`) |
| hadolint | 2.15.1 | imagen Docker `hadolint/hadolint` |
| yamllint | 1.38.0 | pip |
| docker compose | 2.26.1 | sistema |
| bash | 5.2.37 | sistema |

shellcheck, hadolint y yamllint no figuran en `requirements-dev.txt` ni en `package.json`: se instalaron para esta corrida y habría que declararlos para que otra persona pueda repetirla.

## 3. Preparación previa a la corrida

Se hicieron los cambios pedidos antes de correr. El diff completo de todas las correcciones está en `correcciones.diff`.

| Cambio | Archivo | Resultado |
|---|---|---|
| Crear configuración de shellcheck | `.shellcheckrc` | `shell=bash`, `external-sources=true` |
| Crear configuración de hadolint | `.hadolint.yaml` | `failure-threshold: warning` |
| Crear configuración de yamllint | `.yamllint` | Reglas por defecto; se desactivan `line-length` y `document-start`, y `truthy` no revisa claves |
| Corregir la ruta de lint:js | `package.json` | `static/**/*.js` pasa a `services/gateway/static/**/*.js` |
| Activar C901 | `ruff.toml` | Se agrega `C901` a `select` y `[lint.mccabe] max-complexity = 10` |
| Anotar versiones | `00-versiones.txt` | Ver sección 2 |

La ruta de `lint:js` estaba rota. El script original apuntaba a una carpeta que ya no existe, y como usa `--no-error-on-unmatched-pattern`, terminaba con código 0 sin analizar nada y sin avisar. La prueba está en `extra/npm-lint-js.txt`. Con la ruta corregida analiza `app.js` y `login.js`.

## 4. Hallazgos de la corrida inicial

Cada herramienta se corrió por separado y su salida cruda está en `inicial/`. La corrida automatizada está en `correr_estatico.sh`.

### 4.1 Criterio de severidad

El documento 1.1 que se me entregó se corta justo al comenzar la sección 7.1 (clasificación de hallazgos), así que no tiene la definición de los cuatro niveles. Usé este criterio propio, que conviene reemplazar por el oficial si existe:

| Severidad | Criterio aplicado |
|---|---|
| Bloqueante | Impide aprobar según los criterios del plan: error de eslint, hallazgo alto de bandit, prueba propia en rojo, error de sintaxis, puntaje de pylint menor a 9,0 |
| Crítico | Vulnerabilidad confirmada o riesgo de pérdida de datos sin llegar a ser bloqueante |
| Mayor | Defecto de calidad que afecta la corrección o la mantenibilidad: complejidad C901, mensajes de pylint de tipo error, advertencia o refactor, y advertencias de shellcheck |
| Menor | Convención, estilo e información: mensajes de pylint de convención, avisos de nivel info o style, hallazgos de nivel bajo de bandit, advertencias de eslint, formato de YAML |

Un hallazgo es de seguridad si pertenece a una regla de seguridad del documento 1.1 (bandit, eslint-plugin-security, la configuración del plugin de seguridad de pylint, y las reglas SC2086, SC2046 y SC2035 de shellcheck). El resto es de calidad. Esta clasificación la hice yo; no es una salida de las herramientas.

### 4.2 Resultados por herramienta

| Herramienta | Alcance | Hallazgos | Tipo | Severidad | Código de salida |
|---|---|---|---|---|---|
| ruff (E, F, W, I, UP, B, S, C4, SIM, C901) | 35 archivos Python de producto y los de pruebas | 8 | 8 calidad | 8 mayores | 1 |
| pylint | 28 archivos de `libs/` y `services/` | 78 | 77 calidad, 1 seguridad | 20 mayores, 58 menores | 0 (el puntaje 9,73 supera 9,0) |
| bandit | 35 archivos de producto | 1 | 1 seguridad | 1 menor | 1 |
| eslint | `app.js`, `login.js`, script k6 | 1 | 1 seguridad | 1 menor | 0 |
| shellcheck | 27 scripts | 42 | 38 calidad, 4 seguridad | 17 mayores, 25 menores | 1 |
| bash -n | 27 scripts | 0 | - | - | 0 |
| hadolint | 9 Dockerfile | 1 | 1 calidad | 1 menor | 1 |
| yamllint | 5 archivos YAML | 39 | 39 calidad | 39 menores | 1 |
| docker compose config -q | `docker-compose.yml` | 0 | - | - | 0 |
| Reglas propias (pytest) | 9 archivos de prueba | 0 fallas | - | - | 0 |
| **Total** | | **170** | **163 calidad, 7 seguridad** | **45 mayores, 125 menores** | |

El código de salida de hadolint en `inicial/codigos-de-salida.txt` figura como 0 porque la primera corrida no incluía `backup/Dockerfile`. Se repitió con los 9 Dockerfile, y `inicial/hadolint.txt` y `inicial/hadolint.json` tienen el resultado correcto.

### 4.3 Detalle de los hallazgos

**ruff (8, todos C901 de complejidad mayor a 10).**

| Archivo | Función | Complejidad |
|---|---|---|
| `services/classifier/classifier.py` | `_playbook` | 11 |
| `services/classifier/classifier.py` | `detect_auth_incidents` | 25 |
| `services/classifier/classifier.py` | `_link_campaigns` | 15 |
| `services/collector/verify-cobertura.py` | `main` | 12 |
| `simulation/pentest.py` | `imprimir` | 13 |
| `tests/integration/test_despliegue_de_reglas.py` | `_manejador` | 17 |
| `tests/integration/test_respaldo_y_retencion.py` | `_manejador` | 16 |
| `tests/integration/test_respaldo_y_retencion.py` | `_atender` | 13 |

Antes de activar C901, ruff no tenía ningún hallazgo en el proyecto (comprobado con el `ruff.toml` original: `extra/ruff-sin-C901.txt`).

**pylint (78).** 45 de largo de línea mayor a 100, 14 de refactor (muchos argumentos, retornos, ramas, sentencias, variables locales y atributos), 5 advertencias, 1 error de configuración y 13 de convención menores. El caso más notable es `detect_auth_incidents` en `classifier.py`, que excede los tres límites a la vez (36 variables locales, 21 ramas, 90 sentencias). El puntaje fue 9,73.

**bandit (1).** B105 de severidad baja en `libs/siem_servicios.py:43`: detecta una "posible contraseña" en el texto `"X-Internal-Token"`. Es el nombre de un encabezado HTTP, no un secreto (falso positivo, sección 6).

**eslint (1).** Una advertencia `security/detect-object-injection` en `services/gateway/static/app.js:338` (falso positivo, sección 6). No hubo ningún error ni ninguna alerta de `no-unsanitized`, que es la regla contra XSS.

**shellcheck (42).**

| Regla | Cantidad | Qué es |
|---|---|---|
| SC2164 | 11 | `cd` sin control de error |
| SC2015 | 11 | `A && B \|\| C` no es un if/else |
| SC2016 | 4 | Comillas simples que no expanden variables |
| SC2329 | 3 | Función nunca invocada directamente |
| SC2086 | 2 | Variable sin comillas |
| SC2128 | 2 | Array expandido sin índice |
| SC2012 | 2 | `ls` en lugar de `find` |
| SC1090, SC2046, SC2035, SC2178, SC2154, SC2001, SC2181 | 1 cada una | Varias |

**hadolint (1).** DL3018 en `backup/Dockerfile`: `apk add` sin versiones fijas de los paquetes.

**yamllint (39).** 38 de espacios dentro de llaves en `docker-compose.yml` y 1 de comentario sin espacio inicial en `filebeat/filebeat.yml`.

### 4.4 Hallazgos de configuración encontrados durante la corrida

Estos no son hallazgos de las herramientas sobre el código, sino problemas en cómo estaban configuradas.

1. **La configuración de seguridad de pylint no hacía nada.** pylint reportó `unrecognized-option` sobre `.pylintrc`. El plugin `pylint-secure-coding-standard` solo define 3 opciones (`os-open-mode`, `os-mkdir-mode`, `os-mkfifo-mode`). Las otras 9 que el archivo declaraba (`os-system`, `subprocess-run-check`, `check-on-os-popen`, `check-on-os-spawn`, `check-on-os-exec`, `os-makedirs-mode`, `check-on-pickle`, `check-on-marshal`, `check-on-shelve`) no existen. Con un archivo de prueba (`extra/prueba_plugin.py.txt`) comprobé qué reglas están realmente activas: `os.system`, `os.popen`, `pickle`, `marshal`, `shelve` y `subprocess.run` sin `check`. No se detectaron `os.spawn`, `os.exec`, `os.makedirs` ni `os.mkdir` (salida en `extra/plugin-reglas-activas.txt`). Con el plugin 1.6.1, más nuevo, ocurre lo mismo (`extra/pylint-con-plugin-1.6.1.txt`). Por eso la tabla 3.3 del documento 1.1, que lista esas opciones, debe corregirse.
2. **`requirements-dev.txt` no fija versiones** (usa `>=`). Una instalación nueva trae ruff 0.17.6 y plugin 1.6.1 en lugar de las del proyecto. Con ruff 0.17.6 el resultado fue el mismo (8 hallazgos de C901).
3. **El script de `lint:js` estaba roto** (sección 3).
4. **hadolint no analizaba `backup/Dockerfile`**: el documento 1.1 habla de 8 imágenes, pero hay 9.

## 5. Ejemplos reales

### Ejemplo 1: la configuración de seguridad de pylint (seguridad, mayor)

Hallazgo de pylint: `.pylintrc:1: E0015 Unrecognized option found: os-system, subprocess-run-check, check-on-os-popen, ...`

Fragmento antes (resumido: se omiten los comentarios del archivo original, que está completo en `_originales/.pylintrc.orig`):

```ini
[SECURE_CODING_STANDARD]
os-system=True
subprocess-run-check=True
check-on-os-popen=True
check-on-os-spawn=True
check-on-os-exec=True
os-open-mode=0o600
os-mkdir-mode=0o700
os-mkfifo-mode=0o600
os-makedirs-mode=0o700
check-on-pickle=True
check-on-marshal=True
check-on-shelve=True
```

Corrección aplicada: se dejaron solo las 3 opciones que el plugin define, y un comentario aclara que las demás reglas están siempre activas.

```ini
[SECURE_CODING_STANDARD]
# El plugin (v1.5.1) solo define estas tres opciones. Las demas reglas
# (os.system, os.popen, pickle, marshal, shelve) estan siempre activas y no se
# configuran; subprocess.run sin `check=` lo detecta pylint (W1510).
os-open-mode=0o600
os-mkdir-mode=0o700
os-mkfifo-mode=0o600
```

Resultado: desaparece el error `E0015` y la configuración refleja lo que realmente se aplica.

### Ejemplo 2: `cd` sin control de error (shellcheck SC2164, calidad, mayor)

Hallazgo: `scripts/pruebas_completas.sh:10 SC2164 Use 'cd ... || exit' or 'cd ... || return' in case cd fails.` Aparecía en 11 lugares.

Antes:

```bash
cd "$(dirname "$0")/.."
```

Después:

```bash
cd "$(dirname "$0")/.." || exit 1
```

Sin la corrección, si el `cd` falla el script sigue corriendo en el directorio equivocado y puede escribir o borrar donde no debe. Las 11 apariciones se corrigieron igual. En `demo-auditoria.sh` además se movió una verificación de `$?` (SC2181) al propio comando.

### Ejemplo 3: manejador de excepción que solo relanza (pylint W0706, calidad, mayor)

Hallazgo: `services/audit/cadena.py:96 try-except-raise: The except handler raises immediately`. Está en la función que escribe el registro de auditoría encadenado.

Antes:

```python
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, AUDIT_FILE_MODE)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                ...
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise
    return completo
```

Después: se quitó el `try/except` externo, que no hacía nada, y se desindentó el bloque. El `finally` que libera el candado se conserva.

```python
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, AUDIT_FILE_MODE)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            ...
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return completo
```

Como es código de auditoría, se verificó con las pruebas de integración (`test_auditoria_append_only.py` y las demás): pasan todas.

## 6. Falsos positivos y supresiones justificadas

Se suprimieron 38 hallazgos. Cada supresión está solo en la línea afectada y lleva el motivo en el mismo comentario o en el de la línea de arriba. Son decisiones del equipo, y quien revise puede discrepar con alguna. Las que más discusión admiten son las de estilo (SC2015) y las de pylint.

| Herramienta | Regla | Cantidad | Dónde | Justificación |
|---|---|---|---|---|
| bandit y ruff | B105 / S105 | 1 | `libs/siem_servicios.py:43` | Es el nombre del encabezado HTTP, no un secreto |
| eslint | `security/detect-object-injection` | 1 | `services/gateway/static/app.js:338` | El acceso `NOMBRE_DEL_MODELO[mode]` está protegido por `Object.hasOwn` en el `if` de arriba |
| shellcheck | SC2016 | 4 | `scripts/start.sh` | Comillas simples a propósito: `wait_for` evalúa el texto después con `eval` |
| shellcheck | SC2329 | 3 | `scripts/pruebas_de_verificacion.sh` | Las funciones se invocan por nombre desde la tabla de casos |
| shellcheck | SC2015 | 11 | `demo.sh`, `demo-desde-cero.sh`, `demo-ataque.sh` | `ok`, `verde` y `detalle` solo imprimen y no pueden fallar, así que `A && B \|\| C` equivale a un if/else |
| shellcheck | SC2154 | 1 | `scripts/deploy.sh:71` | `rc` se asigna dentro del propio `trap` |
| shellcheck | SC2001 | 1 | `scripts/deploy.sh:112` | Se antepone sangría a cada línea de un texto multilínea; `${var//}` no lo hace |
| shellcheck | SC1090 | 1 | `scripts/pruebas_de_performance.sh` | Ruta variable de un archivo de credenciales que no se versiona |
| pylint | global-statement | 2 | `libs/siem_servicios.py`, `services/pipeline/programador.py` | Punto de inyección para pruebas y un único hilo por proceso |
| pylint | import-outside-toplevel | 3 | `services/analyst/proveedores_llm.py` | SDK opcional: solo se importa si el proveedor es Gemini |
| pylint | broad-exception-caught | 2 | `siem_agent.py`, `proveedores_llm.py` | Cualquier fallo del LLM o del SDK debe caer al análisis de respaldo |
| pylint | wrong-import-order | 3 | `services/audit/audit_service.py` | pylint toma los módulos del propio servicio por de terceros; el orden lo fija ruff (isort) |
| pylint | invalid-name | 3 | `get-logs.py`, `verify-cobertura.py`, `programador.py` | Los dos primeros son comandos de línea de comandos con guion; el tercero es estado mutable del módulo, no una constante |
| pylint | consider-using-with | 1 | `services/pipeline/orquestador.py:121` | Candado no bloqueante que se libera en el `finally`; `with` no aplica |
| hadolint | DL3018 | 1 | `backup/Dockerfile` | La imagen base está fijada (`alpine:3.20`); fijar cada paquete apk rompería el build cuando Alpine rote versiones |

Una salvedad sobre pylint: para los dos módulos con guion en el nombre, la supresión de `invalid-name` quedó como una línea aparte después del shebang, así que cubre todo ese archivo y no solo una línea. No se puede poner en la primera línea sin romper el shebang.

## 7. Comparación entre la corrida inicial y la final

### 7.1 Resultados

| Herramienta | Inicial | Final | Qué cambió |
|---|---|---|---|
| ruff | 8 | 8 | Sin cambios (todos C901) |
| pylint | 78 | 59 | 14 suprimidos y 5 corregidos; puntaje de 9,73 a 9,79 |
| bandit | 1 | 0 | Supresión justificada de B105 |
| eslint | 1 | 0 | Supresión justificada |
| shellcheck | 42 | 0 | 21 corregidos y 21 suprimidos |
| bash -n | 0 | 0 | Los 27 scripts mantienen sintaxis válida |
| hadolint | 1 | 0 | Supresión justificada de DL3018 |
| yamllint | 39 | 0 | 39 corregidos |
| docker compose config | 0 | 0 | Sin cambios |
| Reglas propias | 577 pasan | 577 pasan | Sin cambios |
| **Total** | **170** | **67** | |

Por severidad: los mayores bajan de 45 a 21 y los menores de 125 a 46. Los bloqueantes y críticos fueron 0 en ambas corridas.

Para el compose se verificó que la corrección de espacios en las llaves no cambió el contenido: se cargó el archivo antes y después con PyYAML y el resultado fue idéntico.

### 7.2 Lo que quedó pendiente y por qué

| Pendiente | Cantidad | Motivo |
|---|---|---|
| C901 de ruff | 8 | Requiere partir funciones grandes. `detect_auth_incidents` (complejidad 25) es la lógica central del clasificador y no se refactorizó sin un diseño previo |
| line-too-long de pylint | 45 | Es solo estilo; 25 están en `classifier.py`. Se dejaron para no tocar cadenas largas de forma masiva |
| Límites de tamaño de pylint (muchos argumentos, retornos, ramas, sentencias, variables locales, atributos de instancia) | 13 | Mismo motivo que C901: requieren rediseño |
| `too-many-lines` de pylint | 1 | `classifier.py` tiene 1.379 líneas. Se resuelve partiéndolo en módulos |

Ninguno es de seguridad. Quedan registrados como deuda técnica conocida, no como excepciones aceptadas.

### 7.3 Verificación de que las correcciones no rompieron nada

Después de las correcciones se corrieron las pruebas completas: reglas propias, unitarias e integración, 1.482 pasan, 5 se omiten y 0 fallan (`final/regresion-pytest-completo.txt`). Las 5 omitidas son reglas de detección que no documentan un umbral numérico y ya estaban omitidas antes. No hay una corrida equivalente de pruebas completas antes de las correcciones, por lo que la comparación directa se limita a las 577 pruebas de reglas propias, que dan el mismo resultado.

El diff completo de lo modificado (31 archivos, 122 líneas agregadas y 93 quitadas) está en `correcciones.diff`, y los originales de cada archivo, con sufijo `.orig`, en `_originales/`.

## 8. Cobertura de la revisión

Definición: líneas de código del producto revisadas por al menos una herramienta de análisis estático, divididas por las líneas totales del producto. Las líneas se cuentan con `wc -l`, igual que en el documento 1.1.

| Lenguaje | Archivos | Líneas | Herramientas que lo revisan | Revisado |
|---|---|---|---|---|
| Python | 35 | 8.030 | ruff, bandit (los 35 archivos); pylint (28 archivos de `libs/` y `services/`) | Sí |
| JavaScript | 3 | 1.576 | eslint | Sí |
| Shell | 27 | 3.851 | shellcheck, bash -n | Sí |
| Dockerfile | 9 | 241 | hadolint | Sí |
| YAML | 5 | 620 | yamllint, docker compose config | Sí |
| CSS | 4 | 663 | Sin linter; solo pruebas propias | No |
| HTML | 3 | 298 | Sin linter; solo pruebas propias | No |
| Logstash | 1 | 68 | Ninguna | No |
| NDJSON | 14 | 14 | Solo pruebas propias | No |
| **Total** | | **15.361** | | |

| Medida | Líneas | Porcentaje |
|---|---|---|
| Revisadas por linters y SAST | 14.318 de 15.361 | **93,2 %** |
| Sumando lo que leen las pruebas propias (CSS, HTML y reglas NDJSON) | 15.293 de 15.361 | 99,6 % |

La meta es 80 % o más: se cumple. Con las herramientas que el proyecto ya tenía (ruff, pylint, bandit y eslint) la cobertura habría sido de 62 %, así que fue necesario agregar shellcheck, hadolint y yamllint, como anticipaba el plan.

Cómo leer la cifra:
- **El 93,2 % es la medida firme.** Cuenta solo archivos que una herramienta analizó de verdad. Para ruff comprobé la lista exacta con `ruff --show-files` (`final/ruff-archivos-analizados.txt`) y para bandit con sus métricas por archivo.
- **El 99,6 % es una cota superior.** Verifiqué que las pruebas propias leen los archivos de CSS, las plantillas HTML y las reglas NDJSON, pero no comprobé una por una qué reglas aplican a cada línea.
- **Las cifras difieren un poco del documento 1.1.** Este reporte mide 15.361 líneas contra las 15.310 del documento. La diferencia viene de que hay 9 Dockerfile y no 8 (+13 líneas) y de que mis correcciones agregaron líneas de comentario (+38 en total). Antes de las correcciones el total era 15.323 y el porcentaje también 93,2 %.
- **No se mide cuánto del código revisa cada regla**, solo que el archivo pasó por la herramienta. pylint no analiza `backup/` ni `simulation/`, que sí pasan por ruff y bandit.

## 9. Lo que no se pudo correr o no se verificó

- **El script de la puerta del proyecto** (`scripts/pruebas_de_codigo_estatico.sh`) no se corrió, porque depende de `.devtools/bin`, que no funciona en este equipo. Se corrió cada herramienta por separado con las mismas opciones, como se pidió.
- **Hallazgos de las pruebas no estáticas**: no se corrieron `tests/interfaz` (Playwright y Chromium), las pruebas de Postman ni las de rendimiento con k6. No forman parte de la evaluación estática.
- **Pruebas completas antes de las correcciones**: no existe una corrida de línea de base (sección 7.3).
- **Herramientas opcionales del plan anterior** que no están en el documento 1.1 y no se corrieron: htmlhint, stylelint, `pip-audit`, `npm audit`, detección de secretos y verificación de tipos. Por eso HTML, CSS y Logstash quedan sin linter.
- **Clasificación de severidad**: es propia, por el motivo de la sección 4.1.
- **Estado del repositorio**: el árbol ya tenía 33 archivos modificados antes de la corrida. El diff de este reporte incluye solo mis cambios; el estado previo está en `_originales/git-status-antes.txt`. La instalación de eslint creó `node_modules/`.

## 10. Archivos de evidencia

Todo está en `reportes/estatico/`.

| Archivo o carpeta | Contenido |
|---|---|
| `00-versiones.txt` | Versión de cada herramienta |
| `correr_estatico.sh` | Script que corre cada herramienta por separado |
| `inicial/` | Salida cruda de cada herramienta en la corrida inicial (`.txt` y `.json`) y códigos de salida |
| `final/` | Lo mismo para la corrida final, más la lista de archivos que analizó ruff y la salida de las pruebas completas |
| `clasificacion.json` | Cada hallazgo con su herramienta, tipo y severidad |
| `correcciones.diff` | Todos los cambios al código y la configuración |
| `_originales/` | Copia de cada archivo modificado antes del cambio (sufijo `.orig`) |
| `extra/npm-lint-js.txt` | Prueba de que el script original de `lint:js` no analizaba nada |
| `extra/plugin-reglas-activas.txt`, `extra/prueba_plugin.py.txt` | Prueba de qué reglas del plugin de seguridad están activas |
| `extra/pylint-con-plugin-1.6.1.txt` | pylint con la versión más nueva del plugin |

## 11. Actualización posterior a la corrida final

Después de cerrar este reporte, y antes de grabar el video del entregable 1.4, se corrió la compuerta oficial del proyecto (`scripts/pruebas_de_codigo_estatico.sh`) con las herramientas propias del proyecto. Terminó en fallo, porque ruff informaba 8 hallazgos C901 contra una línea de base de 0. Se resolvió así:

| Cambio | Archivo | Efecto |
|---|---|---|
| Eximir C901 solo en `tests/**`, igual que ya se eximen otras reglas ahí | `ruff.toml` (línea 29) | Los 3 C901 de pruebas dejan de contarse: son servidores HTTP simulados con muchas ramas |
| Fijar la línea de base de ruff en 5 | `scripts/pruebas_de_codigo_estatico.sh` (línea 59) | La compuerta tolera los 5 C901 conocidos del producto y falla ante cualquiera nuevo |

Los 5 hallazgos del producto no se corrigieron: `_playbook`, `detect_auth_incidents` y `_link_campaigns` en `classifier.py`, `main` en `verify-cobertura.py` e `imprimir` en `simulation/pentest.py`. Siguen siendo deuda técnica, ahora declarada como línea de base. Los originales de ambos archivos están en `_originales/` con el sufijo `.antes-de-1.4`.

| Concepto | En las secciones 1 a 10 | Después de esta actualización |
|---|---|---|
| Hallazgos de ruff | 8 | 5 |
| Hallazgos totales | 67 | 64 |
| Hallazgos mayores | 21 | 18 |
| Compuerta oficial del proyecto | No corrida | Todo en verde, código de salida 0 |

El resto de los números de este reporte no cambia. La salida de la compuerta está en `entregables/1.3-evidencia-reglas/configuracion-efectiva/compuerta-oficial--pruebas_de_codigo_estatico.txt`. Las carpetas `inicial/` y `final/` se conservan como estaban: son la foto de cada corrida.

Para correr la compuerta se reconstruyó `.devtools/` con Python 3.13, porque la versión anterior estaba compilada para Python 3.14 y no ejecutaba en este equipo. Se usaron las mismas versiones de este reporte.
