# Entregable 1.4 - Paso a paso exacto para grabar el video

Estado: guardado para retomar más adelante. Todavía no se grabó nada.

Qué cubre este archivo: el orden exacto de lo que hay que hacer, con comandos y rutas. La guía más general (qué decir, tabla de dónde sale cada regla, problemas posibles) está en `GUION_PASO_A_PASO.md`, en esta misma carpeta.

Cómo se reparte el trabajo: la persona que graba ejecuta todo a mano y **no habla**; los subtítulos y el audio se agregan después. Por eso hay esperas marcadas en cada paso: dejan lugar para los subtítulos sin pisar la acción.

## Antes de empezar: tres cosas que hay que saber

1. **La pantalla mide 5760x1080** (tres monitores juntos). Hay que grabar un solo monitor de 1920x1080, o el video sale enorme.
2. **Faltan instalar tres extensiones del IDE**: ruff, pylint y eslint. Solo está instalada Pylance, que conviene desactivar.
3. **No hay ningún motor de voz instalado** (`espeak-ng` y similares). Eso afecta al audio que se agrega después (ver la fase C).

Lo que no se pudo probar: la interfaz gráfica del IDE. Si algo no se ve como se describe, hay que frenar y no seguir.

## Ruta del proyecto

Se usa en todos los comandos:

```
/home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS
```

Dentro hay dos carpetas que importan:

| Carpeta | Qué es |
|---|---|
| `.vscode` | Configuración del IDE |
| `Elastic-SIEM-Project` | El código |

## FASE A - Preparación (sin grabar)

**A1. Abrir una terminal normal y entrar al proyecto**

```
cd /home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS/Elastic-SIEM-Project
```

**A2. Ensayo del script sin pausas** (tarda unos 75 segundos)

```
PAUSA=0 ./entregables/1.4-video-ejecucion/correr_reglas.sh
```

Tiene que terminar con `Todo en orden: el código supera las reglas y las reglas detectan las violaciones.` Después escribir `echo $?`, que tiene que dar `0`. Si no, frenar.

**A3. Instalar las 3 extensiones que faltan**

```
codium --install-extension charliermarsh.ruff
codium --install-extension ms-python.pylint
codium --install-extension dbaeumer.vscode-eslint
codium --list-extensions | grep -E "ruff|pylint|eslint"
```

El último comando tiene que listar las tres.

**A4. Abrir el IDE en la carpeta correcta** (la de afuera, no `Elastic-SIEM-Project`)

```
codium /home/saferrari/Proyectos/NeuralDefender-IyCS-ALL/NeuralDefender-IyCS/NeuralDefender-IyCS
```

- Si pregunta si se confía en los autores, elegir que sí.
- Si las extensiones recién instaladas no responden: `Ctrl+Shift+P`, escribir `Reload Window` y elegir **Developer: Reload Window**.

**A5. Desactivar Pylance** (es otro analizador y ensucia el panel de problemas)

En el IDE, `Ctrl+Shift+X` abre las extensiones. Buscar `Pylance`, tocar la rueda dentada y elegir **Deshabilitar (área de trabajo)**.

**A6. Ensayo del IDE**

1. En el IDE, menú **Terminal**, **Nuevo terminal**. Abre en la carpeta de afuera.
2. Escribir: `cd Elastic-SIEM-Project`
3. Escribir: `./entregables/1.4-video-ejecucion/preparar_demo_ide.sh`
4. Con `Ctrl+P` escribir `libs/zz_demo_violaciones.py` y abrirlo. Esperar unos 10 segundos: tienen que aparecer subrayados rojos y amarillos.
5. Abrir el panel de problemas con `Ctrl+Shift+M`: tiene que listar decenas de problemas.
6. Limpiar: `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh` (tiene que decir `Limpio`) y cerrar la pestaña.

Si en el punto 4 no aparece nada, no seguir.

**A7. Elegir qué pantalla grabar**

1. En una terminal correr `xrandr --listmonitors`: muestra los tres monitores con su tamaño.
2. Mover la ventana del IDE a uno de 1920x1080 y maximizarla.
3. En el grabador (vokoscreenNG u OBS) elegir **solo esa pantalla**, o un área de 1920x1080.
4. Hacer una prueba de 10 segundos y mirarla.

**A8. Dejar todo limpio**

- En el IDE, `Ctrl` y el signo `+` tres veces para agrandar el texto. Cerrar todas las pestañas.
- **No abrir ni dejar visible el archivo `.env`** (tiene contraseñas).
- En la terminal de A1: `rm -f entregables/1.4-video-ejecucion/tiempos.log`
- En la terminal del IDE: `clear`

## FASE B - Grabación (en silencio)

Respetar las esperas: son las que permiten poner los subtítulos sin pisar la acción.

### B0 y B1

| Paso | Qué hacer | Esperar |
|---|---|---|
| B0 | Iniciar la grabación. En la terminal del IDE escribir `date +%T.%N` y Enter. Es la marca para calcular la hora exacta | 5 s |
| B1 | En el explorador de la izquierda desplegar `Elastic-SIEM-Project` y `.vscode` | 5 s |

### B2. Las reglas existen

Con `Ctrl+P` escribir el nombre **con la carpeta por delante**, y mirar que el título de la pestaña no diga `entregables`: hay copias de estos archivos en `entregables/1.3-evidencia-reglas/configuracion`. Después `Ctrl+G` y el número de línea, y señalar con el mouse.

| Escribir en `Ctrl+P` | Líneas (con `Ctrl+G`) | Esperar en cada una |
|---|---|---|
| `Elastic-SIEM-Project/ruff.toml` | 10, 15, 29 | 6 s |
| `Elastic-SIEM-Project/.pylintrc` | 8, 16, 35 | 6 s |
| `Elastic-SIEM-Project/eslint.config.js` | 66, 70, 78 | 6 s |
| `Elastic-SIEM-Project/.bandit` | 11 | 6 s |
| `Elastic-SIEM-Project/.shellcheckrc` | 4 | 6 s |
| `Elastic-SIEM-Project/.hadolint.yaml` | 4 | 6 s |
| `Elastic-SIEM-Project/.yamllint` | 2 | 6 s |

### B3. El código las supera

Abrir uno por uno con `Ctrl+P`. En cada uno apretar `Ctrl+Shift+M`, esperar 5 segundos a que cargue y dejar a la vista el panel con 0 problemas otros 6 segundos:

1. `Elastic-SIEM-Project/libs/siem_validators.py`
2. `Elastic-SIEM-Project/services/auth/siem_auth.py`
3. `Elastic-SIEM-Project/services/audit/cadena.py`
4. `Elastic-SIEM-Project/services/gateway/static/app.js`

Después abrir `Elastic-SIEM-Project/services/classifier/classifier.py` y esperar 10 segundos: aparecen 3 avisos de complejidad (C901). Pasar el mouse sobre uno 5 segundos. **No evitarlo ni ocultarlo**: es deuda técnica declarada.

### B4. Las reglas detectan, en el IDE

1. En la terminal del IDE: `./entregables/1.4-video-ejecucion/preparar_demo_ide.sh` (3 s)
2. `Ctrl+P`, abrir `Elastic-SIEM-Project/libs/zz_demo_violaciones.py`. Esperar 10 s.
3. Pasar el mouse 5 s sobre cada una de estas líneas: la 21 (`os.system`), la 25 (`eval`) y la 27 (`pickle.loads`).
4. `Ctrl+Shift+M` y dejar el panel visible 6 s.
5. Abrir `Elastic-SIEM-Project/services/gateway/static/zz_demo_violaciones.js`. Esperar 8 s y señalar la línea 9 (`innerHTML`) 5 s.
6. Cerrar las dos pestañas y correr: `./entregables/1.4-video-ejecucion/limpiar_demo_ide.sh` (tiene que decir `Limpio`). 4 s.

### B5. Todas las herramientas, en la terminal

1. Maximizar el panel de la terminal con el botón de flecha arriba de su esquina superior derecha, para que quepa la salida.
2. Escribir `clear` y después: `./entregables/1.4-video-ejecucion/correr_reglas.sh`
3. Hay que apretar **Enter unas 42 veces**. El script avisa cada vez con `[Enter para ...]`. Esperas antes de cada Enter:

| Qué se ve en pantalla | Esperar |
|---|---|
| Portada con las versiones | 8 s |
| Cada panel `DE DÓNDE SALEN LAS REGLAS` | 8 s |
| `[Enter para ejecutar]` | 3 s |
| La salida de la herramienta | 4 s |
| `QUÉ SIGNIFICA` y el veredicto (`PASA` o `DETECTÓ`) | 6 s |
| Tabla `RESUMEN` y `MAPA` al final | 8 s cada una |

### B6. Cierre

1. Inmediatamente después de que termine el script, escribir `echo $?` (tiene que dar `0`). 4 s.
2. Escribir `git status --short | grep zz_demo` (no tiene que imprimir nada). 4 s.
3. Escribir `date +%T.%N` y Enter. Esperar 3 s y detener la grabación.

## FASE C - Después de grabar

1. **No borrar ni editar** `Elastic-SIEM-Project/entregables/1.4-video-ejecucion/tiempos.log`. Tiene la hora exacta de cada bloque del script; sirve para sincronizar los subtítulos.
2. Avisar la ruta del video y si algo salió distinto (un error, un paso repetido).

Qué se hace después:

- **Subtítulos:** se pueden generar y pegar al video con `ffmpeg`, que está instalado.
- **Audio:** hay que decidir cómo, porque no hay motor de voz instalado. Opciones:
  1. Grabar la propia voz encima del video.
  2. Instalar `espeak-ng`, una voz robótica pero simple: `! sudo apt install espeak-ng` (el `!` hace que el comando corra dentro de la sesión; requiere contraseña de administrador).
  3. Probar instalar una voz más natural (Piper) sin `sudo`.

## Reglas de oro

- Después de la escena B4, correr siempre `limpiar_demo_ide.sh`. Si quedan archivos de demo (`zz_demo_violaciones*`), `correr_reglas.sh` se niega a correr y la compuerta oficial falla a propósito.
- No abrir el archivo `.env` durante la grabación.
- Los 5 avisos de complejidad (C901) no se esconden: se muestran en B3 y en el bloque 1b del script, y se explican como deuda técnica declarada.

## Archivos que usa esta guía

Todos están en `Elastic-SIEM-Project/entregables/1.4-video-ejecucion/`.

| Archivo | Para qué sirve |
|---|---|
| `correr_reglas.sh` | Corre las 16 comprobaciones con explicaciones, y escribe `tiempos.log` |
| `preparar_demo_ide.sh` | Copia los archivos con violaciones al producto para que el IDE los marque |
| `limpiar_demo_ide.sh` | Los borra y verifica que no quede nada |
| `corrida-de-referencia.txt` | Salida de una corrida completa, para comparar |
| `GUION_PASO_A_PASO.md` | Guía general: qué decir, mapa de dónde sale cada regla, problemas posibles |
| `PASO_A_PASO_GRABACION.md` | Este archivo |
