# NeuralDefender - Entregable 1.3: Evidencia de las reglas de análisis estático

Esta carpeta demuestra que las reglas descritas en el documento 1.1 existen en el repositorio y que cada herramienta las aplica. Todo sale de comandos reales: las salidas están guardadas sin editar y los números de línea de la columna de pruebas se leyeron de esas salidas.

Ubicación: `Elastic-SIEM-Project/entregables/1.3-evidencia-reglas/`.

## 1. Qué contiene la carpeta

| Carpeta o archivo | Contenido |
|---|---|
| `configuracion/` | Copia, en su versión final, de cada archivo de reglas: `ruff.toml`, `.pylintrc`, `bandit.ini` (copia de `.bandit`), `eslint.config.js`, `.shellcheckrc`, `.hadolint.yaml`, `.yamllint`, `package.json`, `requirements-dev.txt` y `.vscode/` (`settings.json`, `extensions.json`, `tasks.json`). Se agregaron `.vscode/pylint.sh` (el envoltorio que usa `settings.json`) y `pruebas_de_codigo_estatico.sh` (donde están el puntaje mínimo de pylint y las exclusiones de bandit). `SHA256SUMS.txt` guarda la suma de cada copia |
| `configuracion-efectiva/` | Lo que cada herramienta dice que aplica de verdad, salida de sus propios comandos (sección 2) |
| `prueba-de-reglas/` | Un archivo de ejemplo por lenguaje con violaciones intencionales, la salida de cada herramienta, y la demostración de las reglas propias (sección 3) |
| `README.md` | Este documento |

## 2. Configuración efectiva

Cada archivo es la salida de un comando que se corrió desde `Elastic-SIEM-Project/` con las herramientas de `00-versiones.txt`.

| Herramienta | Comando | Archivo |
|---|---|---|
| ruff | `ruff check --show-settings <archivo>` (producto y pruebas) | `ruff--show-settings--producto.txt`, `ruff--show-settings--tests.txt` |
| ruff | el mismo código con `--stdin-filename libs/...` y `tests/...` | `ruff--excepciones-solo-en-tests.txt` |
| pylint | `pylint --list-msgs-enabled` con `.pylintrc` y el plugin cargado | `pylint--list-msgs-enabled.txt` |
| pylint | `pylint --generate-rcfile` (valores efectivos) | `pylint--generate-rcfile.txt` |
| bandit | `bandit -v` y la lista de pruebas de su propia librería | `bandit--verbose-perfil.txt`, `bandit--pruebas-activas.txt` |
| eslint | `eslint --print-config` sobre `app.js`, `login.js` y el script de k6 | `eslint--print-config--*.json` |
| shellcheck | `--version`, `--list-optional`, y una corrida con y sin `.shellcheckrc` | `shellcheck--*.txt` |
| hadolint | una corrida con el umbral del proyecto y con `--failure-threshold info` | `hadolint--efecto-de-hadolint-yaml.txt` |
| yamllint | su librería (`YamlLintConfig`), porque esta versión no tiene `--print-config` | `yamllint--configuracion-resuelta.txt` |
| pytest | `pytest --collect-only -q` sobre los 9 archivos de reglas propias | `pytest--coleccion-reglas-propias.txt`, `pytest--casos-por-archivo.txt` |
| npm y compose | `npm pkg get scripts devDependencies`, `docker compose config -q` | `npm--scripts-y-versiones.txt`, `docker-compose--config-q.txt` |

Los archivos `muestra_sin_shebang.sh` y `muestra_hadolint_solo_info.Dockerfile` son los insumos mínimos de las corridas de shellcheck y hadolint.

Cuatro herramientas no ofrecen un volcado directo de su configuración y se resolvió así: shellcheck y hadolint no tienen un comando que la imprima, por eso se demuestra su efecto comparando una corrida con y sin el archivo de reglas; yamllint no tiene `--print-config` en esta versión y se usó su propia librería; y bandit muestra su perfil con `-v`.

## 3. Prueba de reglas

Cada archivo de ejemplo tiene una violación por línea, con la regla anotada al lado.

| Lenguaje | Archivo de ejemplo | Salidas |
|---|---|---|
| Python | `python/ejemplo_violaciones_python.py.txt` | `python/salidas/` (ruff, pylint, bandit) |
| JavaScript | `javascript/ejemplo_violaciones_js.js` y `ejemplo_solo_advertencias.js` | `javascript/salidas/` (eslint) |
| Shell | `shell/ejemplo_violaciones_shell.sh` y `ejemplo_sintaxis_invalida.sh` | `shell/salidas/` (shellcheck, bash -n) |
| Dockerfile | `dockerfile/Dockerfile.violaciones` | `dockerfile/salidas/` (hadolint) |
| YAML | `yaml/ejemplo_violaciones.yml`, `ejemplo_sintaxis_invalida.yml`, `ejemplo_compose_invalido.yml` | `yaml/salidas/` (yamllint, compose) |
| Reglas propias | `reglas-propias/ejecutar_mutaciones.sh` | `reglas-propias/salidas/` (una por propiedad) |

Cómo repetirlo, desde cualquier carpeta (`VENV` es la carpeta `bin` del entorno con las herramientas de Python):

```
VENV=/ruta/al/venv/bin bash prueba-de-reglas/ejecutar_pruebas.sh
VENV=/ruta/al/venv/bin bash prueba-de-reglas/reglas-propias/ejecutar_mutaciones.sh
```

Cómo se prueban las reglas propias: `ejecutar_mutaciones.sh` copia el proyecto a una carpeta temporal y, para cada propiedad, corre la prueba con el código sano (debe pasar), inyecta un defecto en la copia y corre la misma prueba (debe fallar). El producto no se modifica.

## 4. Reglas del documento 1.1 y su prueba

Cómo leer las tablas:

- **Configurada en** indica el archivo y la línea dentro de `configuracion/`. Cuando dice "activa por defecto", la regla no se configura: la herramienta la trae encendida y `.shellcheckrc` o `.hadolint.yaml` no la modifican.
- **Prueba** indica el archivo de ejemplo (python, javascript, shell, dockerfile, yaml) y la línea donde saltó la regla, tomada de la salida de la herramienta.
- **Estado**: Demostrada si la herramienta detectó la violación; Parcial si solo se cumple en parte; No demostrable si no se pudo provocar o no existe.


### Sección 2 del documento 1.1: Herramientas y archivos de configuración

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| Cada lenguaje tiene su archivo de configuración (ruff.toml, .pylintrc, .bandit, eslint.config.js, .shellcheckrc, .hadolint.yaml, .yamllint) | Carpeta `configuracion/` (copias idénticas, verificadas con `SHA256SUMS.txt`) | `configuracion/SHA256SUMS.txt`; el archivo `.bandit` se guarda como `bandit.ini` (sección 5) | Demostrada |
| Las versiones se toman de requirements-dev.txt y package.json | `configuracion/requirements-dev.txt:15` a `:18` y `configuracion/package.json:12` a `:14` | Esos archivos declaran rangos (`pylint>=3.2`, `bandit>=1.7`, `ruff>=0.5`, `^9.11.0`), no versiones exactas. Las versiones realmente usadas están en `configuracion-efectiva/00-versiones.txt` | Parcial |
| Las mismas reglas en el editor (VS Code) | `configuracion/.vscode/settings.json:10`, `:14`, `:25`; `configuracion/.vscode/tasks.json:5`, `:13`, `:27`, `:41`; `configuracion/.vscode/extensions.json:4` a `:6` | Los comandos de `tasks.json` son los mismos que se corrieron desde la terminal. La ejecución dentro del IDE no se puede demostrar por línea de comandos (corresponde al entregable 1.4) | Parcial |

### Sección 3.1 del documento 1.1: Python: ruff

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| E, W: estilo y errores de sintaxis | `configuracion/ruff.toml:10` | python: W291 línea 65, E711 línea 63 (`python/salidas/ruff.txt`) | Demostrada |
| F: imports y variables sin uso | `configuracion/ruff.toml:10` | python: F401 líneas 11, 13, F841 línea 70 y otras 25 | Demostrada |
| I: orden de imports | `configuracion/ruff.toml:10` | python: I001 línea 4 | Demostrada |
| UP: sintaxis obsoleta | `configuracion/ruff.toml:10` | python: UP035 línea 13 | Demostrada |
| B: patrones propensos a errores | `configuracion/ruff.toml:10` | python: B006 línea 20 | Demostrada |
| C4 y SIM: expresiones y flujos innecesarios | `configuracion/ruff.toml:10` | python: C411 línea 55, C416 línea 55, SIM103 línea 48 | Demostrada |
| C901: complejidad ciclomática mayor a 10 | `configuracion/ruff.toml:10` y `:15` | python: C901 línea 68; el valor 10 figura en `configuracion-efectiva/ruff--show-settings--producto.txt:738` | Demostrada |
| S: eval, exec, subprocess, contraseñas, XML, hashes | `configuracion/ruff.toml:10` | python: S105 línea 17, S605 líneas 21, 22, S602 línea 24, S307 línea 25, S102 línea 26, S301 líneas 27, 29, S324 líneas 30, 31, S506 línea 32, S113 línea 33, S314 línea 34, S101 línea 35, S108 líneas 36, 38, 39, 40, 43, S608 línea 37 | Demostrada |
| E501 ignorada (el largo lo controla pylint) | `configuracion/ruff.toml:11` | python: la línea 132 supera los 100 caracteres: ruff no emite E501 y pylint sí emite C0301 | Demostrada |
| Excepciones solo en `tests/` (C901, S101, S105, S106, S314, S404, S603, S607, SIM117) | `configuracion/ruff.toml:29` | `configuracion-efectiva/ruff--excepciones-solo-en-tests.txt`: el mismo código (assert, contraseña literal y una función con 11 ramas) da S101, S105 y C901 con ruta `libs/` y pasa limpio con ruta `tests/` | Demostrada |
| Criterio de aprobación de ruff: sin hallazgos nuevos respecto de la línea de base (5 C901 conocidos del producto) | `configuracion/pruebas_de_codigo_estatico.sh:59` (`BASE_RUFF=5`) | `configuracion-efectiva/compuerta-oficial--pruebas_de_codigo_estatico.txt`: `ruff · proyecto BASE 5 hallazgo(s) conocido(s), sin regresiones`, resumen en verde y código de salida 0 | Demostrada |
| Largo de línea 100 y versión py310 | `configuracion/ruff.toml:2` y `:3` | `{EF}:{ln('ruff--show-settings--producto.txt','^linter.line_length')}` (line_length = 100) y `:{ln('ruff--show-settings--producto.txt','unresolved_target_version')}` (target_version 3.10) | Demostrada |

### Sección 3.2 del documento 1.1: Python: pylint

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| Familias activas C, R, W, E, F | Sin opción: valor por defecto de pylint (`.pylintrc` no la restringe) | python: C0114 línea 1, R0913 línea 58, W0611 líneas 11, 13, E8002 línea 21. La familia F (fatal) no se pudo provocar con un archivo válido | Parcial |
| Largo máximo de línea 100 | `configuracion/.pylintrc:30` | python: C0301 línea 132 (`python/salidas/pylint.txt`) | Demostrada |
| Variables locales 25, ramas 15, sentencias 60, argumentos 6 | `configuracion/.pylintrc:35` a `:38` | python: R0914 y R0912 y R0915 línea 68 (función `funcion_enorme`), R0913 línea 58 | Demostrada |
| Docstring obligatorio en módulos y funciones públicas | `configuracion/.pylintrc:24` y `:25` (desactivan los mensajes de funciones y clases) | python: falta de docstring de módulo C0114 línea 1 sí se detecta; las funciones públicas sin docstring (`seguridad`, `sim`, ...) NO generan C0116 porque está desactivado (`configuracion-efectiva/pylint--list-msgs-enabled.txt`) | Parcial |
| Puntaje mínimo 9,0 sobre 10 | `configuracion/pruebas_de_codigo_estatico.sh:108` (`--fail-under=9.0`). No está en `.pylintrc` | `python/salidas/pylint.txt`: puntaje 0,00 y código de salida 30 con `--fail-under=9.0`. En el producto, `reportes/estatico/final/pylint.txt`: puntaje 9,79 y código 0 | Demostrada |
| Mensajes desactivados: missing-class-docstring, missing-function-docstring, too-few-public-methods, duplicate-code | `configuracion/.pylintrc:24` a `:27` | `configuracion-efectiva/pylint--list-msgs-enabled.txt`: los cuatro figuran en la sección de mensajes desactivados | Demostrada |

### Sección 3.3 del documento 1.1: Python: pylint-secure-coding-standard

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| os-system: prohíbe `os.system` | `configuracion/.pylintrc:8` carga el plugin. La opción `os-system` NO existe: la regla está siempre activa | python: E8002 línea 21 | Demostrada |
| subprocess-run-check: exige `check=` en `subprocess.run` | Opción inexistente. La regla es de pylint, no del plugin | python: W1510 línea 23 | Demostrada |
| check-on-os-popen: prohíbe `os.popen` | Opción inexistente. Regla siempre activa | python: E8010 línea 22 | Demostrada |
| check-on-os-spawn y check-on-os-exec | Opciones inexistentes | python: `os.spawnl` y `os.execl` (líneas 41 y 42) NO generan ningún mensaje de pylint. bandit sí los detecta (B606 líneas 41, 42) | No demostrable |
| os-open-mode y os-mkfifo-mode = 0o600 | `configuracion/.pylintrc:16` y `:18` | python: W8012 línea 38 (os.open con 0o777), W8017 línea 43 (os.mkfifo con 0o666) | Demostrada |
| os-mkdir-mode = 0o700 | `configuracion/.pylintrc:17` | python: W8016 línea 39 (os.mkdir con 0o777) | Demostrada |
| os-makedirs-mode = 0o700 | Opción inexistente | python: `os.makedirs` sin modo (línea 40) NO genera ningún mensaje de pylint | No demostrable |
| check-on-pickle, check-on-marshal, check-on-shelve | Opciones inexistentes. Reglas siempre activas | python: E8013 línea 27, E8014 línea 28, E8015 línea 29 | Demostrada |

### Sección 3.4 del documento 1.1: Python: bandit

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| Alcance: todo el proyecto salvo `tests/`, `elasticsearch/` y dependencias | `configuracion/pruebas_de_codigo_estatico.sh:22` (variable `EXCLUIR`) y `:112`. El `exclude_dirs` de `.bandit` no aplica a `-r` | `reportes/estatico/final/bandit.json`: bandit analizó 35 archivos, 0 de `tests/` y 0 de `elasticsearch/` | Demostrada |
| B101: uso de assert | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B101 línea 35 (`python/salidas/bandit.txt`) | Demostrada |
| B113: requests sin timeout | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B113 línea 33 | Demostrada |
| B301: deserialización con pickle | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B301 líneas 27, 29 (pickle y shelve) | Demostrada |
| B324: hashes débiles | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B324 líneas 30, 31 | Demostrada |
| B404, B603, B602, B605: procesos y shell | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B404 línea 9, B603 línea 23, B602 línea 24, B605 líneas 21, 22 | Demostrada |
| B506: yaml.load inseguro | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B506 línea 32 | Demostrada |
| B608: SQL armado por concatenación | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B608 línea 37 | Demostrada |
| B108: archivos temporales inseguros | `configuracion/bandit.ini:11` y `:12` (copia de `.bandit`); sin lista de pruebas, se ejecutan todas (`configuracion-efectiva/bandit--verbose-perfil.txt`) | python: B108 líneas 36, 38, 39, 40, 43 | Demostrada |

### Sección 4 del documento 1.1: JavaScript: eslint

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| no-unsanitized/property (error): XSS por innerHTML | `configuracion/eslint.config.js:66` | javascript: no-unsanitized/property, línea 9, nivel error (`javascript/salidas/eslint.txt`) | Demostrada |
| no-unsanitized/method (error) | `configuracion/eslint.config.js:67` | javascript: no-unsanitized/method, línea 10, nivel error | Demostrada |
| no-eval (error) | `configuracion/eslint.config.js:73` | javascript: no-eval, línea 11, nivel error | Demostrada |
| no-implied-eval (error) | `configuracion/eslint.config.js:74` | javascript: no-implied-eval, línea 12, nivel error | Demostrada |
| no-new-func (error) | `configuracion/eslint.config.js:75` | javascript: no-new-func, línea 13, nivel error | Demostrada |
| security/detect-eval-with-expression (error) | `configuracion/eslint.config.js:70` | javascript: security/detect-eval-with-expression, línea 11, nivel error | Demostrada |
| security/detect-child-process (error) | `configuracion/eslint.config.js:72` | javascript: security/detect-child-process, línea 15, nivel error (la regla exige la llamada `cp.exec(dato)`; el `require` solo no la dispara) | Demostrada |
| security/detect-non-literal-require (error) | `configuracion/eslint.config.js:71` | javascript: security/detect-non-literal-require, línea 16, nivel error | Demostrada |
| security/detect-unsafe-regex (error) | `configuracion/eslint.config.js:80` | javascript: security/detect-unsafe-regex, línea 17, nivel error | Demostrada |
| security/detect-object-injection (warn) | `configuracion/eslint.config.js:78` | javascript: security/detect-object-injection, línea 19, nivel warning. `javascript/salidas/eslint-solo-advertencias.txt`: un archivo con solo advertencias termina con código 0 | Demostrada |
| security/detect-non-literal-regexp (warn) | `configuracion/eslint.config.js:79` | javascript: security/detect-non-literal-regexp, línea 18, nivel warning | Demostrada |
| eqeqeq con opción smart (error) | `configuracion/eslint.config.js:84` | javascript: eqeqeq, línea 20, nivel error | Demostrada |
| no-unused-vars (warn) | `configuracion/eslint.config.js:83` | javascript: no-unused-vars, línea 23, nivel warning | Demostrada |
| Las reglas de nivel error bloquean la aprobación | Niveles definidos en `eslint.config.js:66` a `:84` | `javascript/salidas/eslint.txt`: 11 errores y 3 advertencias, código de salida 1. Con solo advertencias, código 0 | Demostrada |
| Alcance: `services/gateway/static/` y `tests/performance/` | `configuracion/eslint.config.js:26` y `:34`; `configuracion/package.json:8` y `:9` | `configuracion-efectiva/eslint--print-config--app.js.json`, `--login.js.json` y `--k6.json` muestran las reglas efectivas de cada archivo | Demostrada |

### Sección 5.1 del documento 1.1: Shell: shellcheck y bash -n

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| bash -n: sintaxis sin ejecutar | Sin archivo de configuración: es un comando de bash | `shell/salidas/bash-n.txt`: `line 5: syntax error: unexpected end of file`, código de salida 2 | Demostrada |
| SC2086: variable sin comillas | `configuracion/.shellcheckrc:4` (shell=bash). La regla viene activa por defecto | shell: SC2086 líneas 5, 8, 10 (`shell/salidas/shellcheck.txt`) | Demostrada |
| SC2035: globbing interpretado como opción | `configuracion/.shellcheckrc`. Activa por defecto | shell: SC2035 línea 7 | Demostrada |
| SC2164: cd sin control de error | `configuracion/.shellcheckrc`. Activa por defecto | shell: SC2164 línea 6 | Demostrada |
| `set -euo pipefail` (corte ante errores) | Ninguna: es una convención de los scripts, no una regla de herramienta | `shell/salidas/set-e-en-el-producto.txt`: un `grep` lista 11 scripts del producto que no declaran `set -e` (los de pruebas y demos lo omiten a propósito, y `generate_certs.sh` no declara ningún `set`). shellcheck no la verifica | No demostrable |
| shell=bash en `.shellcheckrc` | `configuracion/.shellcheckrc:4` | `configuracion-efectiva/shellcheck--efecto-de-shellcheckrc.txt`: sin `.shellcheckrc` aparece SC2148, con él no | Demostrada |

### Sección 5.2 del documento 1.1: Dockerfile: hadolint

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| DL3006: imagen base sin etiqueta | `configuracion/.hadolint.yaml:4` (`failure-threshold: warning`). Las reglas DL vienen activas por defecto | dockerfile: DL3006 línea 2 (`dockerfile/salidas/hadolint.txt`) | Demostrada |
| DL3007: etiqueta latest | `configuracion/.hadolint.yaml:4` (`failure-threshold: warning`). Las reglas DL vienen activas por defecto | dockerfile: DL3007 línea 3 | Demostrada |
| DL3002: contenedor con usuario root | `configuracion/.hadolint.yaml:4` (`failure-threshold: warning`). Las reglas DL vienen activas por defecto | dockerfile: DL3002 línea 6 | Demostrada |
| DL3020: ADD en lugar de COPY | `configuracion/.hadolint.yaml:4` (`failure-threshold: warning`). Las reglas DL vienen activas por defecto | dockerfile: DL3020 línea 4 | Demostrada |
| DL3042: pip sin --no-cache-dir | `configuracion/.hadolint.yaml:4` (`failure-threshold: warning`). Las reglas DL vienen activas por defecto | dockerfile: DL3042 línea 5 | Demostrada |
| Umbral de falla de hadolint | `configuracion/.hadolint.yaml:4` | `configuracion-efectiva/hadolint--efecto-de-hadolint-yaml.txt`: una observación de nivel info da código 0 con el umbral del proyecto y código 1 con `--failure-threshold info` | Demostrada |

### Sección 5.3 del documento 1.1: YAML: yamllint y docker compose config

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| syntax: sintaxis | `configuracion/.yamllint:2` (`extends: default`). Reglas resueltas en `configuracion-efectiva/yamllint--configuracion-resuelta.txt` | yaml: syntax línea 3 (`yaml/salidas/yamllint-sintaxis.txt`) | Demostrada |
| indentation: sangría | `configuracion/.yamllint:2` (`extends: default`). Reglas resueltas en `configuracion-efectiva/yamllint--configuracion-resuelta.txt` | yaml: indentation línea 9 (`yaml/salidas/yamllint-estilo.txt`) | Demostrada |
| key-duplicates: claves repetidas | `configuracion/.yamllint:2` (`extends: default`). Reglas resueltas en `configuracion-efectiva/yamllint--configuracion-resuelta.txt` | yaml: key-duplicates línea 4 | Demostrada |
| docker compose config -q: validez del compose | Sin archivo de configuración: es un comando de Docker Compose | `yaml/salidas/compose-config.txt`: `service "web" has neither an image nor a build context specified`, código de salida 15 | Demostrada |

### Sección 6 del documento 1.1: Reglas específicas del sistema (pruebas que leen el código)

| Regla del documento 1.1 | Configurada en | Prueba que demuestra que se aplica | Estado |
|---|---|---|---|
| Ningún componente ejecuta procesos ni se conecta a hosts remotos | `tests/test_no_autonomy.py:135` y `:158` | `prueba-de-reglas/reglas-propias/salidas/M1-no-autonomia.txt`: con el código sano pasan (88 passed); con el defecto inyectado falla `test_sin_imports_de_ejecucion[siem_lib.py]` | Demostrada |
| Validación de IP y usuario por lista blanca | `tests/unit/test_validators.py`, `tests/unit/test_s01_inyeccion_comandos.py` | `prueba-de-reglas/reglas-propias/salidas/M2-lista-blanca.txt`: con el código sano pasan (148 passed); con el defecto inyectado falla `test_safe_token_detecta_los_payloads_de_shell[victima;` | Demostrada |
| Ausencia de XSS en el panel | `tests/unit/test_s02_xss_dashboard.py:75` | `prueba-de-reglas/reglas-propias/salidas/M3-xss-panel.txt`: con el código sano pasan (52 passed); con el defecto inyectado falla `test_no_quedan_handlers_inline` | Demostrada |
| Reglas de detección válidas y sin acciones | `tests/unit/test_reglas_como_codigo.py:238` | `prueba-de-reglas/reglas-propias/salidas/M4-reglas-sin-acciones.txt`: con el código sano pasan (150 passed, 5 skipped); con el defecto inyectado falla `test_ninguna_regla_dispara_acciones` | Demostrada |
| Red aislada, límites de memoria y healthchecks | `tests/unit/test_despliegue_compose.py:58` | `prueba-de-reglas/reglas-propias/salidas/M5-compose-limites.txt`: con el código sano pasan (61 passed); con el defecto inyectado falla `test_todo_servicio_tiene_tope_de_memoria[filebeat]` | Demostrada |
| Consultas sobre campos .keyword | `tests/unit/test_agregaciones_keyword.py:61` | `prueba-de-reglas/reglas-propias/salidas/M6-keyword.txt`: con el código sano pasan (6 passed); con el defecto inyectado falla `test_la_agregacion_por_ip_origen_usa_keyword` | Demostrada |
| Uso de tokens de diseño en CSS | `tests/unit/test_tokens_de_diseno.py:85` | `prueba-de-reglas/reglas-propias/salidas/M7-tokens-css.txt`: con el código sano pasan (19 passed); con el defecto inyectado falla `test_ninguna_propiedad_de_ritmo_usa_un_valor_en_px_suelto[app.css]` | Demostrada |
| Contraste WCAG AA | `tests/unit/test_contraste_de_la_interfaz.py:137` | `prueba-de-reglas/reglas-propias/salidas/M8-contraste.txt`: con el código sano pasan (53 passed); con el defecto inyectado falla `test_una_severidad_desconocida_sigue_siendo_legible` | Demostrada |

## 5. Reglas que no se pueden demostrar o solo en parte, y correcciones al documento 1.1

| Tema | Qué se encontró | Qué hay que corregir |
|---|---|---|
| Opciones del plugin de seguridad de pylint | De las 12 opciones que declara `.pylintrc`, 9 no existen en el plugin (`pylint` las informa como `unrecognized-option`). Solo existen `os-open-mode`, `os-mkdir-mode` y `os-mkfifo-mode`. Las reglas de `os.system`, `os.popen`, `pickle`, `marshal` y `shelve` están activas por defecto | La tabla 3.3 del documento 1.1 debe listar solo las 3 opciones reales y aclarar cuáles reglas son siempre activas |
| `os.spawn`, `os.exec` y `os.makedirs` | El plugin no los detecta (líneas 40 a 42 del ejemplo de Python). bandit detecta `spawn` y `exec` con B606 | No afirmar esas reglas para pylint |
| Docstring obligatorio | Solo se exige en módulos. Las funciones y clases tienen el mensaje desactivado en `.pylintrc:24` y `:25` | Cambiar la tabla 3.2 a "docstring de módulo" o reactivar `missing-function-docstring` |
| Puntaje mínimo de pylint | Está en el script `pruebas_de_codigo_estatico.sh:108`, no en `.pylintrc` | Indicar dónde se configura |
| Alcance de bandit | `exclude_dirs` de `.bandit` no se aplica a `-r`. Las exclusiones reales están en `pruebas_de_codigo_estatico.sh:22` | Indicar dónde se configura |
| `set -euo pipefail` | Ninguna herramienta lo verifica. 11 scripts del producto no declaran `set -e` | Presentarlo como convención verificada con `grep`, no como regla de shellcheck |
| Versiones | `requirements-dev.txt` y `package.json` declaran rangos, no versiones exactas | Fijar versiones o citar `00-versiones.txt` |
| Familia F de pylint | No se pudo provocar con un archivo válido | Dejarla como "aplica por defecto" |
| Reglas del editor (VS Code) | Solo se puede demostrar que los archivos existen y que sus comandos son los de la terminal | Se demuestra en el video del entregable 1.4 |

## 6. Estos archivos no ensucian la corrida normal

Los archivos con violaciones están fuera del alcance de las herramientas por cómo se nombran y dónde están, sin tocar ninguna configuración del producto:

- El ejemplo de Python termina en `.py.txt`, por lo que ni `ruff check .`, ni `bandit -r .`, ni la prueba de no-autonomía (que recorre `*.py`) lo ven. El runner crea una copia `.py` temporal solo mientras corren las herramientas y la borra.
- Los scripts de shell, los Dockerfile y los YAML del producto se analizan con listas explícitas de archivos (`scripts/`, `simulation/`, `backup/`, `services/*/Dockerfile`, los cinco YAML), y el JavaScript con `services/gateway/static/**` y `tests/performance/**`. Esta carpeta queda fuera de todas.
- La copia de `.bandit` se guarda como `bandit.ini`. Con el nombre original, bandit aborta con `Multiple .bandit files found`: lo detecté en una verificación y lo corregí. Excluir la carpeta con `-x` no alcanza, porque bandit busca esos archivos antes de aplicar las exclusiones.

Verificación: se repitió la corrida completa del producto después de crear esta carpeta y el resultado es idéntico al de la corrida final del entregable 1.2 (ruff 8, pylint 59 con puntaje 9,79, bandit 0, eslint 0, shellcheck 0, yamllint 0, hadolint 0 y 577 pruebas de reglas propias). El detalle está en `prueba-de-reglas/verificacion-sin-contaminacion.txt`. Esa verificación es anterior a un cambio posterior: C901 se eximió en `tests/` y se fijó la línea de base de ruff en 5 (ver la sección 11 del reporte del entregable 1.2), de modo que hoy ruff informa 5 hallazgos del producto y no 8.

## 7. Limitaciones

- Las herramientas de Python, shellcheck y yamllint se instalaron en un entorno virtual fuera del repositorio, porque la carpeta `.devtools/` del proyecto no funciona en este equipo. Las versiones están en `configuracion-efectiva/00-versiones.txt`.
- Para eslint se usó `--stdin-filename` con una ruta de `services/gateway/static/`, de modo que le aplique la misma configuración que a `app.js` sin copiar el ejemplo dentro del producto.
- Las rutas que aparecen en algunas salidas son de este equipo (por ejemplo, la del entorno virtual en la línea `# Comando:`).
- El ejemplo de Python usa un archivo con extensión `.txt`; el número de línea de las salidas coincide con el de ese archivo, porque la copia temporal es idéntica.
