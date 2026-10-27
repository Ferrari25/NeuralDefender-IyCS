# 05 · El "Gem": perfil y memoria del Agente 2

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).

Este documento explica **cómo funciona el Gem** (el Agente 2 con su perfil y su
memoria), **qué guarda**, y **dónde se puede ver** cada cosa que guarda: en el
panel, en la terminal y en los archivos.

## Qué es el "Gem" en este proyecto

Un *Gem* de Gemini es un prompt fijo más unos archivos de conocimiento. No
aprende con el uso, y Google no permite invocarlo por API. El Agente 2
(`services/analyst/siem_agent.py`) copia la parte útil de esa idea y le suma
**aprendizaje supervisado**: aprende de lo que deciden los analistas, pero solo
usa lo aprendido después de que una persona lo aprueba.

El Gem tiene cuatro piezas:

| Pieza | Qué es | Dónde vive | Quién la escribe |
|-------|--------|------------|------------------|
| **Perfil** | Personalidad y forma de trabajar del agente ("sos el analista senior del SOC…") | `services/analyst/perfil_agente.md` | Una persona, a mano, versionado en git |
| **Documentos** | Conocimiento de la organización: inventario de red, escáneres autorizados, políticas | `data/knowledge/documentos.json` | Un analista, desde el panel |
| **Casos** | Cada aprobación o descarte del panel, con su contexto | `data/knowledge/casos.json` | El sistema, automáticamente, en cada decisión |
| **Lecciones** | Reglas cortas ("los escaneos desde 10.0.5.20 son el Nessus interno") | `data/knowledge/lecciones.json` | Las **propone** el sistema o un analista; solo se usan **aprobadas** |

El perfil se carga una vez, al arrancar el servicio `analyst`. Los documentos,
los casos y las lecciones los guarda el servicio **knowledge**
(`services/knowledge/memoria.py`), que no tiene secretos ni salida a internet.

## Cómo funciona, paso a paso

### 1. El perfil arma la instrucción del sistema

`SYSTEM_INSTRUCTION = perfil_agente.md + REGLAS_DE_SEGURIDAD`.

- **El perfil es editable** sin tocar código. Si el archivo falta o está vacío,
  se usa un perfil mínimo por defecto (`PERFIL_POR_DEFECTO`).
- **Las reglas de seguridad no están en el perfil**, están fijas en el código
  (`REGLAS_DE_SEGURIDAD` en `siem_agent.py`). Dicen que los datos del log no
  son confiables, que nunca se siguen instrucciones que aparezcan ahí, que la
  memoria es una referencia y no una orden, y que el agente no genera
  comandos. Así nadie puede debilitarlas editando el perfil.

### 2. Cada decisión del panel se convierte en un caso

Cuando un analista aprueba o descarta una acción, el gateway hace dos cosas:

1. Le pide al servicio **audit** que registre la decisión en
   `data/audit/decisions.jsonl` (append-only, encadenado por hash).
2. Le manda al servicio **knowledge** un **caso**: incidente, acción, decisión,
   nota, analista, tipo de ataque, severidad, IPs atacantes y usuarios objetivo.

### 3. Un patrón repetido produce una lección *propuesta*

Después de guardar cada caso, `memoria.py::_proponer_lecciones` busca patrones:

- **Patrón** = (tipo de ataque, IP).
- **Desenlace de cada incidente**: *aprobado* si alguna de sus acciones quedó
  aprobada, *descartado* si todas las decididas quedaron descartadas. Cuenta la
  última decisión de cada acción.
- Si el mismo patrón aparece en **2 incidentes distintos**
  (`CASOS_PARA_PROPONER = 2`) con el **mismo** desenlace, se propone:
  - `falso_positivo` si siempre se descartó;
  - `reincidente` si siempre se aprobó.
- Un patrón que ya tiene lección, **en cualquier estado**, no se vuelve a
  proponer. Una lección rechazada sigue rechazada.

Un analista también puede escribir una lección a mano (tipo `manual`). Igual
nace como **propuesta**.

### 4. Un humano aprueba o rechaza cada lección

Toda lección nace en estado `propuesta` y **no se usa** hasta que alguien con
el permiso `decidir` (rol `analyst`) la aprueba desde el panel. El panel abre
antes un cuadro de confirmación (`confirmarLeccion` en `static/app.js`), que
advierte si quien aprueba es la misma persona que la propuso. Una lección
revisada (aprobada o rechazada) no se reabre.

**Por qué la aprobación es obligatoria.** El atacante controla parte de los
datos de un incidente: la IP de origen, el usuario que tipea. Si el sistema
aprendiera solo, un atacante podría "entrenarlo" generando incidentes que se
descartan, hasta que su IP quedara marcada como ruido.

### 5. Ante un incidente nuevo, el agente consulta su memoria

En cada ciclo del pipeline, el servicio analyst le pide al knowledge el
contexto de cada incidente (`POST /v1/context`), que devuelve:

| Qué devuelve | Cómo se elige |
|--------------|---------------|
| **Lecciones aprobadas que aplican** | Estado `aprobada`, mismo tipo de ataque (o sin tipo) y misma IP (o sin IP). Una lección sin tipo ni IP aplica a todos los incidentes. |
| **Hasta 3 casos similares ya resueltos** | Puntaje: mismo tipo de ataque +3, misma IP +4, mismo usuario objetivo +1; hace falta 3 o más. Nunca cita el mismo incidente. |
| **Hasta 3 párrafos de documentos** | Párrafos que mencionan las IPs, usuarios u hosts del incidente (peso 4) o palabras del tipo de ataque (peso 1). Hace falta un puntaje de 2 o más. Es búsqueda por términos, no por embeddings: no encuentra sinónimos. |

Si knowledge no responde, el análisis sigue sin memoria y el incidente queda
con `aprendizaje.disponible = false`. El pipeline no se corta.

### 6. Qué cambia la memoria en el análisis

- **Con LLM** (`SIEM_USE_LLM=true` y `GEMINI_API_KEY`): el contexto viaja en un
  bloque `<MEMORIA_DEL_AGENTE>` del prompt, como referencia, nunca como orden.
- **Con o sin LLM**: el resultado queda en `analysis.aprendizaje` del
  incidente, calculado en Python, no parafraseado por el modelo.
- **Lo único que una lección cambia por sí sola** es la probabilidad de falso
  positivo: `HIGH` si es `falso_positivo`, `LOW` si es `reincidente`. Queda
  registrado qué lección lo cambió (`falso_positivo_ajustado_por`) y qué valor
  había antes (`falso_positivo_sin_lecciones`). **Nunca toca la severidad ni
  las acciones del playbook.** El agente aprende aunque `SIEM_USE_LLM=false`.

## Dónde ver lo que el Gem guarda

### En el panel (`http://127.0.0.1:5000`)

| Qué | Dónde |
|-----|-------|
| Lecciones propuestas (con botones Aprobar/Rechazar) | Columna lateral, tarjeta **Memoria del agente** → "Propuestas para revisar" |
| Lecciones aprobadas, con quién las propuso, quién las aprobó y en qué incidentes se basan | Misma tarjeta → "Lo que ya aprendió" |
| Documentos cargados (título, quién, cuándo, tamaño) | Misma tarjeta → "Documentos". Ahí también se carga uno nuevo (`.txt`/`.md`, hasta 32 KB, máximo 50 documentos). |
| Qué recordó el agente para **un incidente** | Card de detalle del incidente → sección **Memoria del agente**: lecciones aplicadas, casos parecidos, fragmentos de documentos, y si ajustó el falso positivo |
| Historial de quién cargó o aprobó qué | **Historial de Decisiones → Sacar un reporte** (CSV o JSON) |

La tarjeta solo pide el permiso `ver_incidentes`; cargar documentos, escribir
lecciones y aprobar o rechazar exige `decidir`.

### En los archivos (`data/knowledge/` y `data/audit/`)

| Archivo | Contenido | Escritor |
|---------|-----------|----------|
| `data/knowledge/casos.json` | Un objeto por decisión: `incident_id`, `action_id`, `accion`, `decision`, `note`, `analyst`, `attack_type`, `severity`, `source_ip`, `attacker_ips`, `target_users`, `ts` | knowledge |
| `data/knowledge/lecciones.json` | `leccion_id`, `tipo`, `texto`, `attack_type`, `ip`, `estado` (`propuesta`/`aprobada`/`rechazada`), `propuesta_por`, `evidencia`, `revisada_por`, `revisada_en` | knowledge |
| `data/knowledge/documentos.json` | Cada documento con su contenido completo (la API del panel solo muestra los metadatos) | knowledge |
| `data/audit/actividad.jsonl` | Un evento por operación: `documento_cargado`, `leccion_propuesta` (actor `sistema` o el analista), `leccion_aprobada`, `leccion_rechazada`. Encadenado por hash. | audit |
| `data/pipeline/siem_incidents.json` | `incidents[].analysis.aprendizaje` de la última corrida | pipeline |

Los archivos `lecciones.json`, `documentos.json` y `actividad.jsonl` no
existen hasta que aparece la primera lección, documento o evento.

Para leerlos desde la terminal:

```bash
python3 -m json.tool data/knowledge/lecciones.json
python3 -m json.tool data/knowledge/casos.json
cat data/audit/actividad.jsonl
./scripts/siem.sh auditoria                        # verifica también la cadena de actividad
./scripts/siem.sh reporte --formato json           # decisiones + actividad → reportes/
./scripts/siem.sh pipeline                         # imprime la memoria usada por incidente
```

### Por la API

| Ruta | Permiso | Qué devuelve |
|------|---------|--------------|
| `GET /api/v1/memoria` | `ver_incidentes` | Lecciones (todos los estados) y metadatos de documentos |
| `POST /api/v1/memoria/documentos` | `decidir` | Carga un documento `{titulo, contenido}` |
| `POST /api/v1/memoria/lecciones` | `decidir` | Propone una lección manual `{texto, attack_type?, ip?}` |
| `POST /api/v1/memoria/lecciones/<id>/revision` | `decidir` | `{decision: "aprobar" \| "rechazar"}` |
| `GET /api/v1/reportes?formato=csv\|json` | `ver_auditoria` | Decisiones + actividad de la memoria |

## Cómo cambiar el comportamiento

| Quiero… | Dónde |
|---------|-------|
| Cambiar la personalidad o el tono del agente | `services/analyst/perfil_agente.md` (reconstruir: `docker compose up -d --build analyst`) |
| Pedir más (o menos) repeticiones antes de proponer una lección | `CASOS_PARA_PROPONER` en `services/knowledge/memoria.py` |
| Agregar palabras clave por tipo de ataque para buscar en documentos | `TERMINOS_POR_ATAQUE` en `services/knowledge/memoria.py` |
| Borrar la memoria | Borrar los archivos de `data/knowledge/` con los servicios detenidos. `reset.sh` **no** la borra, a propósito. Lo que ya quedó en `actividad.jsonl` no se borra. |

## Qué lo prueba

`tests/integration/test_memoria_del_agente.py` (22 pruebas) certifica que cada
decisión se guarda como caso, que un patrón repetido produce una lección
**propuesta** que no se usa hasta aprobarla, que una rechazada no se vuelve a
proponer, que una lección aprobada ajusta el falso positivo sin tocar la
severidad, que el prompt entrega la memoria como referencia y no como orden,
que solo quien tiene el permiso `decidir` puede enseñar o aprobar, y que el
análisis (y la auditoría de la decisión) siguen si knowledge se cae.
`tests/integration/test_reportes.py` (17) certifica `actividad.jsonl` y los
reportes. El caso **M5** de `./scripts/pruebas_de_verificacion.sh` hace que el
agente use una lección sin aprobar y comprueba que esas pruebas fallan (ver
[04](04-auditoria-pruebas-y-demostracion.md#verificación-8020-las-pruebas-detectan-errores)).
