# Pruebas de linters y análisis estático (SAST)

Guía para correr, entender y **verificar** las pruebas de código estático de
SIEM-IA. "Estático" significa que ninguna de estas herramientas ejecuta el
sistema: leen el código fuente y buscan problemas antes de que corra.

> Resumen en una línea: `./scripts/pruebas_de_codigo_estatico.sh` tiene que
> terminar en `✅ Todo en verde.` — y para demostrar que ese verde significa
> algo, se inyectan vulnerabilidades a propósito y se comprueba que pasa a ❌
> (ver [§5](#5-cómo-verificar-que-el-análisis-es-correcto-prueba-de-mutación)), o se
> corre `./scripts/pruebas_de_verificacion.sh`, que lo hace solo (ver [§9](#9-verificación-8020-automática)).

## Dónde ver los linters, de un vistazo

| Quiero ver… | Dónde |
|---|---|
| El resultado de todos juntos | `./scripts/pruebas_de_codigo_estatico.sh` (terminal, una línea por herramienta) |
| El detalle de una herramienta | Los comandos de la [§3](#cada-herramienta-por-separado-para-ver-el-detalle) |
| Los hallazgos subrayados mientras escribo | VS Code → panel **Problems** (`Ctrl+Shift+M`), ver [§7](#7-linters-dentro-de-visual-studio-code) |
| Su configuración | `ruff.toml`, `eslint.config.js`, `.pylintrc`, y los parámetros de bandit en `scripts/pruebas_de_codigo_estatico.sh` |
| La prueba de que detectan de verdad | `./scripts/pruebas_de_verificacion.sh` (casos M1 y M2) |
| Qué verifica cada archivo de **pruebas** (no linters) | [`docs/04` §Registro de pruebas](docs/04-auditoria-pruebas-y-demostracion.md#registro-de-pruebas) |

---

## 1. Qué herramientas corren y qué busca cada una

Hay dos categorías, con objetivos distintos:

| Categoría | Herramienta | Lenguaje | Qué detecta | Configuración |
|---|---|---|---|---|
| **Linter** | `ruff` | Python | Estilo, imports, errores comunes y además las reglas `S` (port de bandit) | `ruff.toml` |
| **Linter** | `eslint` + `eslint-plugin-security` + `eslint-plugin-no-unsanitized` | JavaScript del dashboard | XSS vía `innerHTML` (hallazgo S-02), `eval`, regex peligrosas, `==` | `eslint.config.js` |
| **SAST** | `pylint` + `pylint-secure-coding-standard` | Python | Calidad del código + reglas de seguridad `E80xx` (`os.system`, `shell=True`, `eval`, `pickle`, `yaml.load`) | `.pylintrc` |
| **SAST** | `bandit` | Python | Vulnerabilidades conocidas: `subprocess`, hashes débiles, deserialización insegura, contraseñas en el código | parámetros en el script |

Qué código analiza cada una:

- **ruff**: todo el proyecto (`tests/` incluido, sin tolerancia a hallazgos).
- **pylint**: `libs/` y `services/` (el código del producto).
- **bandit**: todo menos `.devtools`, `.venv`, `node_modules`, `tests` y `elasticsearch`.
- **eslint**: `services/gateway/static/**/*.js`.

## 2. Instalación (una sola vez)

Desde `Elastic-SIEM-Project/`:

```bash
python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt
npm install          # solo para eslint; requiere Node.js 18+
```

Las herramientas de Python quedan en `.devtools/bin/` sin tocar el Python del
sistema. Si falta alguna, el script lo avisa y se corta, en vez de reportar
un falso "0 hallazgos".

## 3. Cómo correrlas

### Todo junto (lo que se usa para demostrar)

```bash
./scripts/pruebas_de_codigo_estatico.sh   # solo linters + SAST
./scripts/pruebas_completas.sh            # esto + pruebas unitarias y de servicio (~150 s)
```

### Cada herramienta por separado (para ver el detalle)

```bash
export PYTHONPATH="$PWD/.devtools"

.devtools/bin/ruff check .                                          # linter Python
node_modules/.bin/eslint 'services/gateway/static/**/*.js'          # linter JS
.devtools/bin/bandit -r . -x './.devtools,./.venv,./node_modules,./tests,./elasticsearch' -lll   # solo severidad alta

mapfile -t CODIGO < <(find libs services -name '*.py' -not -path '*/__pycache__/*')
.devtools/bin/pylint --fail-under=9.0 \
  --init-hook="import sys, glob; sys.path[:0] = ['libs', *sorted(glob.glob('services/*'))]" \
  "${CODIGO[@]}"
```

## 4. Cómo leer el resultado

Cada etapa imprime uno de estos estados:

| Estado | Significado |
|---|---|
| `✔ OK` | La herramienta terminó sin errores |
| `BASE` | La cantidad de hallazgos es igual a la **línea de base** (hoy: 0) |
| `MEJORA` | Hay menos hallazgos que la línea de base: hay que bajar `BASE_*` en el script |
| `✘ FALLA` / `FALLA` | Aparecieron hallazgos nuevos y se muestra el detalle |

**Línea de base:** `BASE_RUFF` y `BASE_BANDIT_ALTOS` en el script son la
cantidad de hallazgos conocidos y aceptados. Hoy las dos valen **0**: el
proyecto no tiene ningún hallazgo pendiente. La puerta falla ante cualquier
hallazgo nuevo. Esos números solo pueden bajar, nunca subir sin justificarlo.

Para pylint, la etapa pasa si la **nota global** es ≥ 9.0/10.

Resultado esperado hoy:

```
▶ LINTERS   — estilo y prolijidad, no buscan vulnerabilidades
    ruff · tests/                  ✔ OK
    ruff · proyecto                BASE   0 hallazgo(s) conocido(s), sin regresiones
    eslint (gateway/static/*.js)   ✔ OK

▶ SAST      — seguridad: vulnerabilidades conocidas, no ejecuta nada
    pylint + secure-coding-standard ✔ OK
    bandit · severidad alta        BASE   0 hallazgo(s) conocido(s), sin regresiones

  ✅ Todo en verde.
```

## 5. Cómo verificar que el análisis es correcto (prueba de mutación)

Un "todo en verde" por sí solo **no prueba nada**: también saldría verde si
las herramientas no estuvieran mirando ningún archivo. Para demostrar que
detectan de verdad, se hace una **prueba de mutación**: se agrega código
vulnerable a propósito, se comprueba que la puerta falla y se borra.

### Paso 1 — Inyectar las vulnerabilidades

```bash
cat > services/collector/mutante.py <<'EOF'
import hashlib
import os
import pickle
import subprocess
import yaml


def ejecutar(cmd):
    subprocess.run(cmd, shell=True)
    os.system("ls " + cmd)
    return eval(cmd)


def hashear(p):
    return hashlib.md5(p.encode()).hexdigest()


def cargar(blob, texto):
    yaml.load(texto)
    return pickle.loads(blob)


PASSWORD = "admin123"
EOF

cat > services/gateway/static/mutante.js <<'EOF'
function pintar(evento) {
  document.getElementById("x").innerHTML = evento.mensaje;
  document.body.insertAdjacentHTML("beforeend", evento.ip);
  eval("console.log(" + evento.id + ")");
  if (evento.n == 1) { return; }
}
pintar(window.dato);
EOF
```

### Paso 2 — Correr la puerta: tiene que fallar

```bash
./scripts/pruebas_de_codigo_estatico.sh
```

Resultado esperado: `❌ 3 etapa(s) con fallos` (ruff, eslint y bandit).

### Paso 3 — Comprobar qué detectó cada herramienta

Resultados de una corrida real:

| Vulnerabilidad inyectada | ruff | bandit | pylint | eslint |
|---|---|---|---|---|
| `subprocess.run(..., shell=True)` | ✔ S602 | ✔ HIGH B602 | ✔ E8003 | |
| `os.system(...)` | ✔ S605 | ✔ HIGH B605 | ✔ E8002 | |
| `eval(...)` | ✔ S307 | ✔ MEDIUM B307 | ✔ E8001 | |
| `hashlib.md5` | ✔ S324 | ✔ HIGH B324 | ✗ | |
| `yaml.load` | ✔ S506 | ✔ MEDIUM B506 | ✔ E8005 | |
| `pickle.loads` | ✔ S301 | ✔ MEDIUM B301 | ✔ E8013 | |
| Contraseña escrita en el código | ✔ S105 | ✔ LOW B105 | ✗ | |
| `innerHTML = dato` (XSS, S-02) | | | | ✔ no-unsanitized/property |
| `insertAdjacentHTML(dato)` | | | | ✔ no-unsanitized/method |
| `eval` en JS | | | | ✔ no-eval + security |
| `==` en vez de `===` | | | | ✔ eqeqeq |

Para ver el detalle de cada una:

```bash
.devtools/bin/ruff check services/collector/mutante.py
.devtools/bin/bandit services/collector/mutante.py
.devtools/bin/pylint services/collector/mutante.py        # da 0.00/10
node_modules/.bin/eslint services/gateway/static/mutante.js
```

### Paso 4 — Limpiar y volver a verde

```bash
rm services/collector/mutante.py services/gateway/static/mutante.js
./scripts/pruebas_de_codigo_estatico.sh    # tiene que volver a ✅ Todo en verde.
```

> ⚠️ No olvidar el paso 4: si se commitean los archivos mutantes, se introducen
> vulnerabilidades reales en el repositorio.

## 6. Limitación conocida: la etapa de pylint

En la prueba de mutación, **pylint detecta todas las vulnerabilidades** (el
archivo mutante solo saca 0.00/10), **pero su etapa sigue en `✔ OK`**. El
motivo es que `--fail-under=9.0` mira el **promedio de todo el proyecto**, y
un archivo malo entre muchos buenos apenas baja la nota global (de 9.77 a
9.53).

En la práctica esa etapa no frena por sí sola un `os.system()` nuevo. Hoy lo
frenan **ruff y bandit**, que sí fallan. Para que pylint también lo bloquee,
habría que agregar `--fail-on=` con los códigos de seguridad (E8001, E8002,
E8003…) al comando del script.

Además, pylint avisa
`E0015: Unrecognized option found: os-system, subprocess-run-check, …` sobre
`.pylintrc`. Eso significa que la sección `[SECURE_CODING_STANDARD]` de ese
archivo no se está aplicando con la versión instalada del plugin. Las reglas
E80xx igual se activan con sus valores por defecto, como muestra la tabla
anterior.

## 7. Linters dentro de Visual Studio Code

El repositorio trae configuración en `NeuralDefender-IyCS/.vscode/` para ver
los hallazgos en vivo mientras se escribe, con las mismas reglas que el
script.

1. Instalar las extensiones recomendadas (VS Code las sugiere al abrir la
   carpeta): **Python**, **Ruff**, **Pylint** y **ESLint**.
2. Abrir la carpeta **raíz del repositorio** (`NeuralDefender-IyCS`), no
   `Elastic-SIEM-Project`, porque las rutas de la configuración salen de ahí.
3. Los problemas aparecen subrayados en el código y en el panel **Problems**
   (`Ctrl+Shift+M`).
4. Para analizar todo el proyecto: `Ctrl+Shift+P` → **Tasks: Run Task** →
   - `SIEM: análisis estático completo (linters + SAST)`
   - `SIEM: ruff`, `SIEM: bandit` o `SIEM: eslint`: cargan los hallazgos en el panel Problems

| Archivo | Para qué sirve |
|---|---|
| `.vscode/settings.json` | Apunta cada extensión a `.devtools/` y `node_modules/` con las configs del proyecto |
| `.vscode/pylint.sh` | Wrapper que lanza pylint con el `PYTHONPATH`, `.pylintrc` e `--init-hook` correctos |
| `.vscode/tasks.json` | Tareas para correr cada herramienta sobre todo el proyecto |
| `.vscode/extensions.json` | Lista de extensiones recomendadas |

Bandit no tiene una extensión que analice en vivo. En el editor lo cubre Ruff,
que incluye las mismas reglas (prefijo `S`).

Si una extensión no marca nada, abrir el panel **Output** y elegir "Ruff",
"Pylint" o "ESLint" en el desplegable para ver el error.

## 8. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `Faltan ejecutables en .devtools/bin` | No se instalaron las dependencias de desarrollo | Paso de instalación de la [§2](#2-instalación-una-sola-vez), con `--upgrade` |
| `eslint … OMITIDO (falta npm install)` | No existe `node_modules/` | `npm install` |
| `ModuleNotFoundError` al correr pylint o bandit a mano | Falta el `PYTHONPATH` | `export PYTHONPATH="$PWD/.devtools"` |
| pylint marca imports como no resueltos | Falta el `--init-hook` | Usar el comando de la [§3](#3-cómo-correrlas) o el script |
| `MEJORA` en vez de `BASE` | Se corrigieron hallazgos | Bajar `BASE_RUFF` / `BASE_BANDIT_ALTOS` en el script |

## 9. Verificación 80/20 automática

La prueba de mutación de la §5 se hace a mano y toca el árbol de trabajo.
`./scripts/pruebas_de_verificacion.sh` hace lo mismo, sin tocar el repositorio:
copia el proyecto a un directorio temporal y corre **25 casos**:

- **20 casos sanos (80 %)** que tienen que **pasar**: ruff, eslint, pylint,
  bandit, la certificación por AST y 15 grupos que cubren los 39 archivos de
  pruebas unitarias y de servicio.
- **5 casos mutantes (20 %)** que tienen que **fallar**: M1 inyecta
  `subprocess.run(..., shell=True)` (lo frena **bandit**), M2 inyecta
  `innerHTML = dato` (lo frena **eslint**), M3 un `os.system` en un servicio
  (lo frena la certificación por **AST**), M4 borra el permiso de la ruta de
  decisión (lo frenan las pruebas de **autenticación**) y M5 hace que el agente
  use lecciones sin aprobar (lo frenan las pruebas de **memoria**).

Termina en `✅ Verificación correcta` solo si salen exactamente 20 ✔ y 5 ✘.
Detalle y salida esperada en
[`docs/04`](docs/04-auditoria-pruebas-y-demostracion.md#verificación-8020-las-pruebas-detectan-errores).

Documentación relacionada: `docs/04-auditoria-pruebas-y-demostracion.md`
(estrategia general de pruebas y qué verifica cada archivo) y `nicotito.md` §10.
