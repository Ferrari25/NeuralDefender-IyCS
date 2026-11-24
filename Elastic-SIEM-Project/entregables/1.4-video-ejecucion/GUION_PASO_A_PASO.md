# Entregable 1.4 - Guía para grabar el video de la corrida

Objetivo del video: que se vea claramente que las reglas del documento 1.1 se ejecutaron y que el código las superó. Duración sugerida: 10 a 12 minutos.

Esta guía tiene tres partes: preparación (sin grabar), grabación escena por escena, y qué hacer si algo falla. Todo lo marcado como `comando` se copia y se pega.

## 0. Qué hay que saber antes de empezar

1. **El editor instalado es VSCodium (`codium`), no VS Code.** Es el mismo programa sin la tienda de Microsoft. Las tres extensiones que usa el proyecto existen en su tienda, pero hay que instalarlas.
2. **El proyecto tiene 5 hallazgos de complejidad (C901) declarados como línea de base.** La compuerta oficial los tolera y falla ante cualquiera nuevo. En el video no los escondas: se muestran y se explican (escena 3).
3. **La parte del IDE no la pude probar con la interfaz gráfica.** Sí verifiqué que los mismos comandos producen los mismos diagnósticos (ruff y eslint sobre los archivos de demo) y que las extensiones existen en la tienda. Por eso hay un ensayo obligatorio en la sección 2.
4. **Mientras existan los archivos de demo del IDE, la compuerta oficial falla a propósito.** Siempre hay que correr `limpiar_demo_ide.sh` al terminar la escena 4.

Carpetas que se usan en toda la guía:

| Nombre | Ruta |
|---|---|
| Carpeta del IDE (la que tiene `.vscode/`) | `/home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS` |
| Carpeta del proyecto | la anterior + `/Elastic-SIEM-Project` |

## 1. Preparación, una sola vez y sin grabar

### 1.1 Comprobar que todo funciona en la terminal

```
cd /home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS/Elastic-SIEM-Project
PAUSA=0 ./entregables/1.4-video-ejecucion/correr_reglas.sh
```

Tarda unos 75 segundos. Tiene que terminar con la línea `Todo en orden: el codigo supera las reglas y las reglas detectan las violaciones.` y el comando `echo $?` tiene que dar `0`. Si se ve así, comparalo con `corrida-de-referencia.txt` (la salida de mi corrida).

Si dice `Faltan herramientas`, ejecutá lo que propone y volvé a correrlo. Si Docker no responde, probá `docker ps`.

### 1.2 Instalar las extensiones en VSCodium

```
codium --install-extension charliermarsh.ruff
codium --install-extension ms-python.pylint
codium --install-extension dbaeumer.vscode-eslint
```

Comprobá con `codium --list-extensions | grep -E "ruff|pylint|eslint"`: tienen que aparecer las tres.

**Recomendado: desactivá Pylance para esta carpeta.** Ya la tenés instalada, pero es otro analizador (de tipos y de imports) que no forma parte de las reglas del documento 1.1. Si queda activa, puede llenar el panel de problemas con avisos que no son de ruff, pylint ni eslint y arruinar el "0 problemas" de la escena 3. En el panel de extensiones (`Ctrl+Shift+X`) buscá **Pylance**, abrí su menú de la rueda dentada y elegí **Deshabilitar (área de trabajo)**. Al final del video no hace falta volver a activarla.

### 1.3 Abrir la carpeta correcta en el IDE

```
codium /home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS
```

Importante: abrí la carpeta `NeuralDefender-IyCS` y no `Elastic-SIEM-Project`. La configuración del IDE (`.vscode/`) está en la carpeta de afuera; si abrís la de adentro, el IDE no la aplica.

Cuando aparezca "¿Confías en los autores de esta carpeta?", elegí **Sí, confío**. Sin eso, las extensiones no corren.

### 1.4 Ensayo del IDE (obligatorio)

1. Abrí la terminal integrada con el menú **Terminal**, **Nuevo terminal**, y corré `cd Elastic-SIEM-Project && ./entregables/1.4-video-ejecucion/preparar_demo_ide.sh`.
2. En el explorador, abrí `libs/zz_demo_violaciones.py`. Esperá unos segundos. Tienen que aparecer subrayados rojos y amarillos en `os.system`, `eval`, `pickle`, etc.
3. Abrí el panel de problemas con `Ctrl+Shift+M`. Tiene que listar decenas de problemas, con fuentes `Ruff` y `Pylint`.
4. Abrí `services/gateway/static/zz_demo_violaciones.js`: tiene que mostrar errores de `eslint` (por ejemplo `no-unsanitized/property`, `no-eval`).
5. Limpiá: `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh`. Tiene que decir `Limpio`.

Si en el paso 2 no aparece nada, mirá la sección 4 antes de grabar.

### 1.5 Preparar la grabación

Hay dos grabadores instalados: **vokoscreenNG** (el más simple) y **OBS Studio**.

| Ajuste | Valor |
|---|---|
| Qué grabar | Pantalla completa, o solo la ventana del IDE |
| Resolución y cuadros | 1920x1080 a 30 cuadros por segundo |
| Audio | Micrófono activado; hacé una prueba de 10 segundos y escuchala |
| Formato | MP4 |
| Zoom del IDE | `Ctrl` y `+` hasta que el texto se lea cómodo en un video (unas 3 veces) |
| Terminal | La integrada del IDE; fuente grande |

Antes de grabar:
- Cerrá las notificaciones del sistema y cualquier ventana con datos personales.
- **No abras el archivo `.env`** (tiene contraseñas) ni lo dejes visible en el explorador de archivos durante la grabación.
- Cerrá todas las pestañas del IDE y ejecutá `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh`.
- Abrí la terminal integrada ya ubicada en `Elastic-SIEM-Project`.

## 2. Grabación escena por escena

Resumen:

| Escena | Dónde | Duración | Qué se demuestra |
|---|---|---|---|
| 1 | IDE | 0:40 | Presentación |
| 2 | IDE | 1:30 | Las reglas existen: archivos de configuración |
| 3 | IDE | 2:00 | El código del producto supera las reglas |
| 4 | IDE | 1:30 | Las reglas detectan violaciones |
| 5 | Terminal integrada | 5:00 a 6:00 | Todas las herramientas, con código de salida |
| 6 | Terminal | 0:30 | Cierre y limpieza |

Lo que está entre comillas es una sugerencia de qué decir, con tus palabras.

### Escena 1 - Presentación (0:40)

1. Con el IDE abierto y sin ninguna pestaña, mostrá el explorador con las carpetas `Elastic-SIEM-Project` y `.vscode`.
2. Decí: "Este es el proyecto NeuralDefender. Voy a mostrar que las reglas de análisis estático del documento 1.1 están configuradas, que se ejecutan y que el código las supera."

### Escena 2 - Las reglas existen (1:30)

Abrí uno por uno estos archivos (doble clic en el explorador) y detenete 10 a 15 segundos en cada uno:

| Archivo | Qué señalar con el mouse |
|---|---|
| `Elastic-SIEM-Project/ruff.toml` | Línea 10: `select` con la familia `S` (seguridad) y `C901`; línea 15: `max-complexity = 10` |
| `Elastic-SIEM-Project/.pylintrc` | Línea 8: el plugin de seguridad; líneas 16 a 18: modos de archivo; líneas 35 a 38: límites |
| `Elastic-SIEM-Project/eslint.config.js` | Líneas 66 y 67: `no-unsanitized` (XSS); línea 73: `no-eval` |
| `Elastic-SIEM-Project/.shellcheckrc`, `.hadolint.yaml`, `.yamllint` | Son cortos: mostrá que existen |
| `.vscode/settings.json` | Las rutas de `ruff` y `pylint` y la sección de `eslint` |

Decí: "Cada lenguaje tiene su archivo de reglas. Estas son las que va a aplicar cada herramienta."

La tabla completa de archivos y líneas, con la sección del documento 1.1 de cada una, está en la sección 2.1 de esta guía. Dejala abierta al costado mientras grabás.

### Escena 3 - El código supera las reglas, en el IDE (2:00)

1. Abrí, uno a uno, estos archivos del producto. Están verificados: no tienen ningún diagnóstico de ruff ni de pylint.

   | Archivo | Por qué mostrarlo |
   |---|---|
   | `libs/siem_validators.py` | Validación de entradas: lista blanca de IP y usuario |
   | `services/auth/siem_auth.py` | Autenticación, el archivo más grande de los limpios |
   | `services/audit/cadena.py` | Registro de auditoría encadenado |
   | `services/collector/es_client.py` | Cliente de Elasticsearch |
   | `services/gateway/static/app.js` | JavaScript del panel (eslint, 0 problemas) |

2. Con cada archivo abierto, mostrá el panel de problemas (`Ctrl+Shift+M`) y dejá a la vista que dice **0 problemas** (o "No se han detectado problemas"). Esperá 3 a 5 segundos después de abrir cada archivo, porque los linters tardan un poco.
3. Abrí `services/classifier/classifier.py`. Acá van a aparecer diagnósticos de ruff `C901` en tres funciones (`_playbook`, `detect_auth_incidents` y `_link_campaigns`). **No lo evites:** es la deuda técnica declarada.

   Decí: "Estos hallazgos de complejidad están declarados como línea de base en la compuerta del proyecto. Son 5 en total, el proyecto los tolera y falla ante cualquiera nuevo. Están documentados en el reporte 1.2 como deuda pendiente."

### Escena 4 - Las reglas detectan violaciones, en el IDE (1:30)

1. En la terminal integrada: `./entregables/1.4-video-ejecucion/preparar_demo_ide.sh`.
2. Abrí `libs/zz_demo_violaciones.py`. Pasá el mouse sobre dos o tres subrayados para que se vea el mensaje, por ejemplo:
   - `os.system` (error de seguridad de pylint, `E8002`)
   - `eval` (error de seguridad de ruff y pylint)
   - `pickle.loads` (error de seguridad)
3. Mostrá el panel de problemas: tiene que listar decenas de problemas, con fuente Ruff y Pylint.
4. Abrí `services/gateway/static/zz_demo_violaciones.js`: mostrá el error `no-unsanitized/property` sobre `innerHTML = datos` (el vector de XSS) y `no-eval`.
5. **Cerrá las dos pestañas y limpiá**: `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh`. Tiene que decir `Limpio`.

Decí: "Si alguien escribe código que viola las reglas de seguridad, el IDE lo marca al instante. Estos archivos son solo de demostración y los borro ahora."

### Escena 5 - Todas las herramientas, en la terminal (5:00 a 6:00)

1. Corré la tarea oficial desde el IDE, para mostrar la integración: menú **Terminal**, **Ejecutar tarea...**, y elegí **SIEM: análisis estático completo (linters + SAST)**. Tiene que terminar con `Todo en verde`. (Si la tarea no aparece, saltá este paso: el script siguiente ya la incluye como bloque 1.)
2. Corré el script completo, **con pausas** para poder narrar:

   ```
   ./entregables/1.4-video-ejecucion/correr_reglas.sh
   ```

3. **Cómo funciona cada bloque.** El script imprime solo, en este orden, estos carteles. Podés leerlos tal cual o decirlos con tus palabras:

   | Cartel | Qué muestra | Cuándo pasar al siguiente |
   |---|---|---|
   | `QUÉ VA A PASAR` | En lenguaje simple, qué hace la herramienta | Leelo y apretá Enter |
   | `VIOLACIÓN INTENCIONAL` | Solo en la parte 2: las líneas del archivo de ejemplo que tienen el defecto | Señalalas con el mouse |
   | `DE DÓNDE SALEN LAS REGLAS` | Las **líneas reales** del archivo de configuración, numeradas, y una nota que explica qué hace cada una | Es lo más importante del video: detenete acá |
   | `[Enter para ejecutar]` | Pausa antes de correr la herramienta | Apretá Enter cuando termines de explicar |
   | Salida de la herramienta | Lo que encuentra o no encuentra | Dejala a la vista unos segundos |
   | `QUÉ SIGNIFICA` | Cómo interpretar esa salida | Leelo |
   | `>>> PASA` o `>>> DETECTÓ` | El veredicto, con el código de salida | Señalalo |

   El **bloque 1** es especial: muestra cinco paneles seguidos (ruff, pylint, eslint, bandit y los criterios de aprobación), con una pausa entre cada uno `[Enter para ver la siguiente herramienta]`. Tomate el tiempo de cada panel: ahí se ve que la compuerta no inventa reglas, las lee de los archivos.

4. **Parte 1 (bloques 1 a 7): el código supera las reglas.** Cada bloque tiene que terminar en `>>> PASA`.
5. En el bloque 1b se listan los 5 C901 de ruff. Decí lo mismo que en la escena 3.
6. **Parte 2 (bloques 8 a 16): las reglas detectan violaciones.** Cada bloque tiene que terminar en `>>> DETECTÓ la violación`. Primero se muestran las líneas con el defecto (por ejemplo `os.system`), después de dónde sale la regla y después el hallazgo de la herramienta apuntando a esa misma línea.
7. Al final aparece la tabla **RESUMEN** con los 16 bloques y el **MAPA: de dónde sale cada regla**. Dejalos en pantalla 5 segundos cada uno.
8. Ejecutá `echo $?` y mostrá que da `0`.

Si querés una corrida más corta, por ejemplo para ensayar, usá `PAUSA=0` (sin pausas) o `EXPLICAR=0` (sin los carteles explicativos).

**Qué decir en cada bloque** (una frase, para no quedarte sin palabras):

| Bloque | Frase sugerida |
|---|---|
| 1 | "La compuerta del proyecto encadena ruff, eslint, pylint y bandit; las reglas salen de estos cuatro archivos" |
| 1b | "Estos 5 hallazgos de complejidad están declarados como deuda técnica; la compuerta falla ante cualquiera nuevo" |
| 2 | "shellcheck revisa los 27 scripts; sus reglas vienen incluidas en la herramienta y `.shellcheckrc` fija el dialecto" |
| 3 | "bash -n comprueba la sintaxis sin ejecutar nada" |
| 4 | "hadolint revisa los 9 Dockerfile: versión fija, sin root y buenas prácticas" |
| 5 | "yamllint revisa los 5 YAML de configuración con el conjunto estándar de reglas" |
| 6 | "Docker comprueba que el compose sea desplegable" |
| 7 | "Estas son reglas propias del sistema: cada prueba ES una regla; por ejemplo, ningún componente ejecuta procesos" |
| 8 a 11 | "Ahora al revés: les paso código con defectos de seguridad y comprobamos que cada herramienta lo encuentra" |
| 12 a 16 | "Lo mismo para shell, Dockerfile y YAML: cada defecto es detectado" |

### Escena 6 - Cierre (0:30)

1. Ejecutá `git status --short | grep zz_demo` y mostrá que no imprime nada (no quedó ningún archivo de demo).
2. Decí: "El código del producto supera las reglas de calidad y seguridad de los cinco lenguajes, y comprobamos que las reglas realmente detectan las violaciones. Los 5 hallazgos de complejidad están declarados como línea de base y documentados."
3. Detené la grabación.

## 2.1 De dónde salen las reglas (para mostrarlo)

Lo automático (el script) no inventa nada: cada herramienta lee su propio archivo. Este es el mapa. Todos los archivos están en `Elastic-SIEM-Project/`, salvo `.vscode/`.

| Herramienta | Archivo | Líneas clave | Qué hay ahí | Sección del 1.1 |
|---|---|---|---|---|
| ruff | `ruff.toml` | 10 | Familias de reglas activas (`S` seguridad, `C901` complejidad) | 3.1 |
| ruff | `ruff.toml` | 15 | Complejidad máxima: 10 | 3.1 |
| ruff | `ruff.toml` | 29 | Excepciones, solo para `tests/` | 3.1 |
| pylint | `.pylintrc` | 8 | Carga el plugin de seguridad | 3.3 |
| pylint | `.pylintrc` | 16 a 18 | Permisos máximos de archivos, directorios y fifos | 3.3 |
| pylint | `.pylintrc` | 30 y 35 a 38 | Largo de línea y límites de tamaño por función | 3.2 |
| pylint | `scripts/pruebas_de_codigo_estatico.sh` | 108 | Puntaje mínimo de 9,0 (no está en `.pylintrc`) | 3.2 |
| bandit | `.bandit` | 11 y 12 | Sin lista de pruebas: aplica todas las de bandit | 3.4 |
| bandit | `scripts/pruebas_de_codigo_estatico.sh` | 22 | Carpetas excluidas (el `.bandit` no las aplica en modo recursivo) | 3.4 |
| eslint | `eslint.config.js` | 66 y 67 | Reglas contra XSS (`no-unsanitized`) | 4 |
| eslint | `eslint.config.js` | 70 a 80 | `eval`, `child_process`, regex peligrosas | 4 |
| eslint | `eslint.config.js` | 83 y 84 | Calidad: variables sin usar, `===` | 4 |
| compuerta | `scripts/pruebas_de_codigo_estatico.sh` | 59 | Línea de base: 5 C901 conocidos | 7 |
| shellcheck | `.shellcheckrc` | 4 | Dialecto `bash`. Las reglas `SC2086`, `SC2035` y `SC2164` vienen con la herramienta | 5.1 |
| hadolint | `.hadolint.yaml` | 4 | Umbral de falla. Las reglas `DL3006`, `DL3007`, `DL3002`, `DL3020` y `DL3042` vienen con la herramienta | 5.2 |
| yamllint | `.yamllint` | 2 | `extends: default`: el conjunto estándar de reglas | 5.3 |
| Reglas propias | `tests/test_no_autonomy.py` y 8 archivos más | 135 (la regla principal) | Cada archivo de prueba **es** una regla del sistema | 6 |
| Editor | `.vscode/settings.json` | 10, 14, 25 | Integración con ruff, pylint y eslint | 2 |
| Editor | `.vscode/tasks.json` | 5, 13, 27, 41 | Las tareas que ejecutan lo mismo que la terminal | 2 |

**Cómo mostrarlo en el IDE:** abrí el archivo con `Ctrl+P` y escribí el nombre (por ejemplo `ruff.toml`), saltá a la línea con `Ctrl+G` y el número, y señalá la regla con el mouse. Es la forma de enseñar, sin palabras de más, que "esta línea es la que aplica la herramienta".

Una aclaración honesta que conviene decir en el video: **las reglas de shellcheck y hadolint no están escritas en el proyecto.** Vienen dentro de las herramientas y están activas por defecto; el proyecto solo ajusta el dialecto y el umbral. Lo que sí está en el proyecto es *que se usan* y *con qué ajustes*.

## 3. Qué tiene que verse en el video (lista de control)

Antes de entregar, mirá el video y marcá:

- [ ] Se ven los archivos de configuración de reglas abiertos (`ruff.toml`, `.pylintrc`, `eslint.config.js`).
- [ ] Se ven las versiones de las herramientas (portada del script).
- [ ] El panel de problemas del IDE muestra 0 problemas en al menos tres archivos del producto.
- [ ] El IDE marca las violaciones en el archivo de demo, con el mensaje visible.
- [ ] Los 16 bloques del script se ven con su resultado (`PASA` o `DETECTO`).
- [ ] Se ve la tabla RESUMEN completa y el código de salida `0`.
- [ ] Se explican los 5 C901 como línea de base.
- [ ] No se ve el archivo `.env` ni contraseñas.
- [ ] El audio se entiende.

Entrega: el archivo de video en MP4, con un nombre como `NeuralDefender_1.4_corrida_reglas.mp4`. Como respaldo, podés guardar la salida del script: `PAUSA=0 ./entregables/1.4-video-ejecucion/correr_reglas.sh 2>&1 | tee corrida.txt`.

## 4. Si algo falla

| Síntoma | Causa probable | Solución |
|---|---|---|
| El IDE no subraya nada en `zz_demo_violaciones.py` | Carpeta equivocada abierta, o el workspace no es de confianza | Cerrá y abrí la carpeta `NeuralDefender-IyCS` (no la de adentro) y aceptá la confianza |
| Subraya solo con ruff pero no con pylint | La extensión de pylint no corre su envoltorio | Verificá que `.vscode/pylint.sh` sea ejecutable (`ls -l .vscode/pylint.sh` tiene que mostrar `x`; si no, `chmod +x .vscode/pylint.sh`). Mirá el panel Salida, y elegí `Pylint` en el menú desplegable |
| No marca los `.js` | Falta la extensión o eslint pide permiso | Instalá `dbaeumer.vscode-eslint`. Si aparece un aviso de ESLint en la barra de estado, aprobá el uso |
| `correr_reglas.sh` dice `Hay archivos de demo del IDE sin limpiar` | Quedó el demo de la escena 4 | `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh` |
| `correr_reglas.sh` dice `Faltan herramientas` | Falta `.devtools`, `node_modules` o la imagen de hadolint | Los tres comandos que imprime el propio script |
| La compuerta oficial falla con hallazgos nuevos | Algún archivo cambió después de la preparación | Mirá cuál es en la salida; no lo tapes: corregilo o consultame |
| Un bloque dice `FALLA` y no sabés por qué | - | Detené la grabación, corré ese comando solo (el script lo muestra en `Comando:`) y mirá la salida |
| El IDE tarda mucho en mostrar diagnósticos | Primera apertura de pylint | Esperá 10 a 15 segundos y volvé a abrir el archivo |
| El panel de problemas muestra avisos de otra fuente (por ejemplo Pylance) en archivos limpios | Pylance u otra extensión de Python está activa | Deshabilitá esa extensión para esta carpeta (sección 1.2). Los avisos de ruff, pylint y eslint son los únicos que cuentan |

## 5. Archivos de esta carpeta

| Archivo | Para qué sirve |
|---|---|
| `GUION_PASO_A_PASO.md` | Esta guía |
| `correr_reglas.sh` | Corre las 16 comprobaciones con carteles claros y un resumen. `PAUSA=0` lo corre sin pausas |
| `preparar_demo_ide.sh` | Copia los archivos con violaciones al producto para que el IDE los marque |
| `limpiar_demo_ide.sh` | Los borra y verifica que no quede nada |
| `corrida-de-referencia.txt` | La salida de una corrida completa, para comparar |
