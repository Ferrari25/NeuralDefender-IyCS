# Gemma local y pruebas de interfaz

> Resumen de los cambios del 2026-10-30: el Agente 2 ahora funciona con un LLM
> real y gratuito, y hay pruebas de interfaz con un navegador de verdad. La
> puerta completa (`./scripts/pruebas_completas.sh`) pasa en verde: linters,
> SAST y 1415 pruebas. La verificación 80/20 también da bien.

## 1. Gemma real y gratuito

### Por qué

La `GEMINI_API_KEY` del `.env` **no es válida** (Google responde 401). Por eso,
hasta ahora el Agente 2 siempre usaba el análisis de reglas fijas, aunque
estuviera `SIEM_USE_LLM=true`.

### Qué se hizo

El Agente 2 usa **Gemma 3**, el modelo abierto de Google, que corre en la
propia máquina con Ollama:

- Es gratis, no necesita key ni tiene cuota, y los logs no salen del equipo.
- Corre en un contenedor nuevo, `ollama`, dentro de una red interna (`llm-net`)
  sin salida a internet. Así, un texto malicioso metido en un log no tiene
  adónde mandar datos.
- **Probado con un ciclo real:** el pipeline terminó "en modo gemma" y Gemma
  escribió un análisis concreto del incidente (364 intentos fallidos contra
  172.19.0.7, MITRE T1110, preguntas de investigación específicas). Tardó
  **unos 75 s por incidente**, porque corre en CPU sin GPU.
- Si un ciclo pasa de 480 s, los incidentes que faltan se analizan con las
  reglas fijas, así la corrida nunca se cuelga. Ese límite se cambia con
  `SIEM_LLM_PRESUPUESTO`. Si Ollama está caído o falta el modelo, también se
  usan las reglas fijas.
- En el panel aparece la etiqueta **«IA (Gemma local)»**, y cada incidente
  muestra qué modelo lo analizó.
- Para usar la API de Google en su lugar: `SIEM_LLM_PROVEEDOR=gemini` y una key
  válida de https://aistudio.google.com (el modelo se elige con
  `SIEM_GEMINI_MODELO`; con la capa gratuita también sirve `gemma-3-27b-it`).

### Configuración (`.env`)

| Variable | Default | Qué hace |
|----------|---------|----------|
| `SIEM_USE_LLM` | `false` | Interruptor general del LLM. Tiene que estar en `true`. |
| `SIEM_LLM_PROVEEDOR` | `gemma` | `gemma` (local, Ollama) o `gemini` (API de Google). |
| `SIEM_OLLAMA_MODELO` | `gemma3:4b` | Modelo de Gemma. Con poca RAM: `gemma3:1b`. |
| `SIEM_LLM_PRESUPUESTO` | `480` | Segundos máximos de LLM por ciclo; el resto va a reglas fijas. |
| `SIEM_GEMINI_MODELO` | `gemini-flash-lite-latest` | Modelo cuando el proveedor es `gemini`. |

### Comandos

```bash
./scripts/siem.sh modelo              # baja gemma3:4b (una sola vez, ~3.4 GB)
./scripts/siem.sh modelo gemma3:1b    # alternativa liviana (~800 MB)
docker compose up -d ollama analyst   # levanta Ollama y el Agente 2
./scripts/siem.sh pipeline            # corre un ciclo: debería decir "modo gemma"
```

### Archivos

- `services/analyst/proveedores_llm.py` (nuevo): clientes de Gemma (Ollama) y Gemini.
- `services/analyst/siem_agent.py`: usa el proveedor elegido, esquema JSON de
  salida y límite de tiempo por ciclo.
- `docker-compose.yml`: servicio `ollama` (imagen `ollama/ollama:0.40.3`), red
  `llm-net` y volumen `ollama-modelos`.
- `scripts/siem.sh`: comando `modelo`.
- `services/gateway/static/app.js`: etiqueta «IA (Gemma local)» y modelo usado.
- Pruebas: `tests/unit/test_gemma_local.py` (nuevo) y ajustes en
  `test_interruptor_del_llm.py`, `test_no_autonomy.py` y otros.

## 2. Pruebas de interfaz

### Cómo funcionan

Están en `tests/interfaz/` (13 pruebas) y usan **Playwright**, que maneja un
**Chromium real**:

1. Levantan el panel en un servidor HTTP real, en un puerto temporal, con datos
   de prueba. No tocan los datos reales ni el panel que corre en Docker.
2. El navegador hace lo que haría una persona: escribe usuario y contraseña,
   hace clic en filas, aprueba y descarta acciones, cierra sesión.
3. Revisan lo que se ve en pantalla y también lo que quedó guardado en el
   registro de decisiones.

### Qué cubren

- Login: sin sesión redirige al login, contraseña incorrecta, login correcto.
- Cierre de sesión.
- Buscador de la tabla.
- Detalle del incidente, también abriéndolo con el teclado (accesibilidad).
- Cuadro de confirmación: cancelar no guarda nada, confirmar sí guarda.
- Descartar pide un motivo y lo guarda.
- Un usuario viewer no ve los botones de decisión.
- La etiqueta de Gemma y el modelo usado.
- Un ataque XSS en el texto del análisis se muestra como texto y no se ejecuta.
- Además, fallan si la página tira errores de JavaScript.

Para comprobar que sirven, se rompió a propósito la confirmación y la
protección XSS: fallaron las 3 pruebas correspondientes. Después el código
quedó como estaba.

### Cómo correrlas

```bash
cd Elastic-SIEM-Project && export PYTHONPATH="$PWD/.devtools"
.devtools/bin/pytest tests/interfaz                         # ~13 s, sin ventana
.devtools/bin/pytest tests/interfaz --headed --slowmo 400   # para ver el navegador trabajando
.devtools/bin/pytest tests/interfaz -k aprobar              # una sola
```

También corren automáticamente en `./scripts/pruebas_de_servicio.sh`, en la
etapa nueva **INTERFAZ** (y por lo tanto en `pruebas_completas.sh`). Si falta
Chromium, se saltean en vez de fallar.

Instalación en un equipo nuevo (una sola vez):

```bash
python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt
PYTHONPATH=.devtools python3 -m playwright install chromium
```

La guía completa está en [`pruebas_de_interfaz.md`](pruebas_de_interfaz.md).
También se actualizaron `CLAUDE.md`, `docs/01`, `docs/04` y `docs/05`.

## Para tener en cuenta

- Gemma ocupa unos 4 GB de RAM mientras analiza. Si la máquina va justa, usar
  `SIEM_OLLAMA_MODELO=gemma3:1b`, que es más rápido pero da análisis menos completos.
- Docker Compose muestra un aviso: el volumen de modelos "no fue creado por
  Compose". No afecta en nada; aparece porque se creó a mano para adelantar la
  descarga. En un equipo nuevo no aparece.
- La key de Gemini inválida sigue en el `.env`, que está versionado en git.
  Sigue pendiente rotarla, o borrarla si no se va a usar.
