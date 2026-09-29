# Demostración desde cero

> **Para qué es este documento.** Es el guion completo de la defensa: qué correr, en
> qué orden, qué decir mientras corre y qué contestar si preguntan. Está pensado para
> leerse **antes** y tenerlo abierto **durante**.
>
> Todo lo que dice acá está verificado sobre el sistema corriendo. Los números de
> ejemplo son de una corrida real del 26-09-2026.

---

## 1. Qué demuestra este guion, y por qué importa

La pregunta que un evaluador va a hacer, explícita o no, es:

> *«¿Cómo sé que ese panel no está mostrando un archivo JSON que ustedes prepararon?»*

`demo.sh` deja el laboratorio presentable y `demo-ataque.sh` lanza un ataque en vivo,
pero los dos parten de un sistema que ya tiene datos. Este guion responde la pregunta
de la única forma que no admite réplica: **poniendo todo en cero delante del público**
y construyendo el resultado paso a paso.

Cuatro números arrancan en cero y hay que mostrarlos:

| | Al empezar | Al terminar |
|---|---|---|
| Reglas de detección en Kibana | **0** | 14 |
| Alertas en Elasticsearch | **0** | 4 |
| Documentos de Filebeat | **0** | 140 |
| Incidentes en el panel | **0** | 3 |

### Lo que NO hay que afirmar

**No digas «todo lo que ves sale de las reglas que acabo de subir».** No es cierto, y
es fácil de refutar: el escaneo de puertos y el phishing los detecta el Agente 1
leyendo `network_logs/` **sin pasar por Elasticsearch**. Aparecerían aunque no hubiera
una sola regla desplegada.

Lo cierto es mejor, y está en §5.

---

## 2. Antes de empezar

### Comprobación

```bash
./scripts/demo-desde-cero.sh --estado
```

Tiene que responder con los cuatro números. Si Kibana no contesta, levantá el stack:

```bash
./scripts/start.sh
```

### Qué tener abierto

| Ventana | Qué |
|---------|-----|
| Terminal 1 | El guion (`./scripts/demo-desde-cero.sh`) |
| Navegador, pestaña 1 | Kibana → **Security → Rules** (`http://127.0.0.1:5601`) |
| Navegador, pestaña 2 | Kibana → **Security → Alerts** |
| Navegador, pestaña 3 | El panel (`http://127.0.0.1:5000/login`) |
| Terminal 2 | Libre, para `audit_verify.py` al final |

El panel exige login. Los usuarios del laboratorio los crea `./scripts/demo.sh`:

| Usuario | Contraseña | Rol |
|---------|------------|-----|
| `analista` | `Soc-Analista-2026` | ve y decide |
| `observador` | `Soc-Viewer-2026x` | solo lectura, sin botones |
| `auditor` | `Soc-Auditor-2026` | verifica la cadena |

> Son credenciales de laboratorio, conocidas a propósito. Los secretos reales
> (`ELASTIC_PASSWORD`, `GEMINI_API_KEY`) están en `.env`, que no se versiona.

### Cuánto tarda

**6 a 9 minutos** de reloj, de los cuales unos 4 son espera a que las reglas disparen
(corren cada 1 a 10 minutos). Esa espera **es** parte de la demostración: es el SIEM
trabajando, no el script. Hablá durante ella; en §4 hay qué decir.

Si el tiempo apremia, `--sin-docker` omite la fuerza bruta con Hydra y baja a ~3
minutos — pero perdés la única fila «Elastic SIEM» del cuadro final, que es lo más
valioso. **No lo uses en la defensa.**

---

## 3. El guion

```bash
./scripts/demo-desde-cero.sh
```

Va narrado y con pausas. Pide confirmación antes de borrar.

### Paso 1 · Todo a cero

Borra las reglas desplegadas, las alertas, los índices de Filebeat y los artefactos
del pipeline. **No baja Docker**: el stack sigue arriba, así que tarda segundos.

> **Lo que hay que decir:** «Estoy borrando todo lo regenerable. El registro de
> auditoría no: se archiva en `audit/archive/`, porque es la única prueba de que hubo
> supervisión humana y un script del propio repositorio no puede destruirla.»

Eso último no es un detalle de guion: es el hallazgo **A-01**, y conviene decirlo
antes de que lo pregunten.

### Paso 2 · Mostrar que no hay nada

**Acá se recarga el navegador, a la vista de todos.**

- Kibana → Security → Rules → **0 reglas**
- Kibana → Security → Alerts → **0 alertas**
- El panel → vacío, con el mensaje «Sin incidentes en la ventana de 24 horas»

> **Lo que hay que decir:** «Esto es el sistema recién instalado. Lo que aparezca de
> acá en adelante se construye delante de ustedes.»

### Paso 3 · Desplegar las reglas

```bash
./scripts/deploy-rules.sh        # lo corre el guion solo
```

Las 14 reglas viven versionadas en `rules/ndjson/`. **Recargá la pestaña de Rules:
pasa de 0 a 14.**

> **Lo que hay que decir:** «Las reglas son código: viajan en el repositorio y se
> despliegan con un comando. Antes se creaban a mano en la consola, y eso significaba
> que quien clonara el proyecto no obtenía el mismo sistema — es el hallazgo F-02, y
> está cerrado.»
>
> **Y la aclaración que evita el malentendido:** «Desplegar acá significa subir reglas
> de *detección*. Le enseña a Elastic qué reconocer. No ejecuta nada sobre ninguna
> máquina.»

### Paso 4 · Generar los ataques

Tres ataques, con una IP nueva cada vez en el rango `198.51.100.0/24` que RFC 5737
reserva para documentación:

| Ataque | MITRE | Cómo |
|--------|-------|------|
| Escaneo de 26 puertos | T1046 | Eventos NDJSON en `network_logs/` |
| Captura de credenciales | T1566 | Ídem |
| Fuerza bruta SSH | T1110 | **Hydra real** contra el contenedor `ssh-target` |

> **Lo que hay que decir de la fuerza bruta:** «Este no es sintético. Hydra prueba 25
> contraseñas por SSH contra un contenedor real, los intentos quedan en su
> `/var/log/auth.log`, Filebeat los recoge, Logstash los normaliza y Elasticsearch los
> indexa. Es la misma ruta que seguiría un ataque de verdad.»

### Paso 5 · La ingesta

El guion espera y muestra el conteo de documentos subir de 0.

> **Lo que hay que decir:** «El índice no existía hace un minuto. Filebeat lo creó al
> llegar el primer evento.»

### Paso 6 · Las reglas disparan

La espera larga. El guion consulta el conteo de alertas hasta que aparecen.

**Recargá la pestaña de Alerts.** Mostrá el nombre de la regla que disparó.

> **Lo que hay que decir mientras espera:** «Cada regla tiene su intervalo: la de
> fuerza bruta agresiva corre cada minuto, otras cada diez. Esto que estamos esperando
> es Elastic evaluando las reglas contra los datos que acaban de entrar. No lo hace el
> proyecto: lo hace el SIEM.»

### Paso 7 · Clasificación y panel

El pipeline corre las tres etapas y el guion imprime el cuadro final:

```
      tipo                   sev       ev  procedencia de la detección
      ──────────────────────────────────────────────────────────────────────
      port_scan              alta      26  Agente 1 · determinística (sin pasar por Kibana)
      ssh_brute_force        alta      20  Elastic SIEM · SSH Brute Force – Aggressive per Source IP
      credential_harvesting  alta       1  Agente 1 · determinística (sin pasar por Kibana)
```

**Abrí el panel y recargá.** Los incidentes están ahí.

---

## 4. Los dos caminos de detección

Esta es la parte que conviene contar bien, porque es donde el proyecto tiene algo que
decir y donde una explicación floja se nota.

```
                    ┌─ reglas de Kibana ──→ alertas ─┐
  ataque → logs ────┤                                ├──→ Agente 1 → Agente 2 → panel
                    └─ network_logs/ ────────────────┘
```

| Camino | Qué detecta | Qué aporta |
|--------|-------------|------------|
| **Elastic SIEM** | Fuerza bruta SSH, escaneo de puertos, phishing | La alerta trae el **nombre de la regla**, la severidad del SIEM, el puntaje de riesgo y la técnica MITRE. El incidente queda explicable: «la regla X disparó por esto». |
| **Agente 1** | Los tres tipos, sin depender de que la regla ya haya disparado | El clasificador determinístico cuenta fallos de auth, puertos distintos y envíos de credenciales leyendo `network_logs/`/logs de auth directamente. No espera a Elasticsearch para detectar, pero si la alerta correspondiente YA existe, la usa. |

> **Lo que hay que decir:** «Hay dos caminos y es deliberado, y desde la corrección de
> D-11 los tres tipos de ataque los pueden usar los dos. Si la regla de Kibana
> (SSH, Port Scan o Phishing) ya disparó para esa IP, el panel muestra su nombre real.
> Si Elasticsearch estuviera caído o la regla todavía no llegó a su intervalo de
> ejecución, el clasificador igual detecta el patrón leyendo los logs directamente — la
> detección no depende de un solo motor, pero cuando los dos coinciden, el panel lo
> dice.»

### Si preguntan por qué un escaneo o un phishing aparecen "sin regla SIEM"

Puede pasar, pero ya no es la regla general. `network_logs/` es a la vez la entrada de
Filebeat y la fuente que lee el clasificador directamente — así que el escaneo o el
phishing se detectan de inmediato, sin esperar a que Kibana evalúe su regla (que corre
cada varios minutos, según el `interval` de cada una). Si en el momento de correr
`siem_pipeline.py` la alerta de Kibana (`Port Scan – …`, `Credential Submission…`, etc.)
**todavía no disparó**, el incidente queda como "Sin regla SIEM (detección propia)" —
temporalmente. Volver a correr el pipeline un rato después, ya con la alerta indexada,
lo actualiza a la regla real. `verify-cobertura.py` es justamente la herramienta para
demostrar esto: compara las alertas reales de Elasticsearch contra lo que muestra el
panel y avisa si algo quedó sin actualizar.

> **Esto se corrigió el 26-09-2026 (hallazgo D-11)** y se completó el 28-09-2026: antes,
> el clasificador ponía a mano `rule_name="Network port scan detection"` en esos
> incidentes (un nombre que no existe en Kibana) y **nunca** consultaba las alertas
> reales de escaneo/phishing aunque existieran. Ahora nunca inventa un nombre, y cuando
> la alerta real ya está, la usa — con el mismo criterio de "la más grave gana" que ya
> tenía la fuerza bruta SSH.

---

## 5. Después del guion: cerrar el círculo

El guion termina con los incidentes en el panel. Faltan las dos piezas que completan
el argumento del proyecto.

### 5.1 · La decisión humana

Entrá como `analista`, abrí un incidente y **aprobá una acción**.

> **Lo que hay que decir:** «El sistema sugirió un comando. No lo ejecutó, y no puede:
> no existe ninguna ruta que ejecute nada. Lo que hace el botón es registrar que una
> persona identificada decidió.»

Después cerrá sesión y entrá como `observador`: **los botones no están**. Y si alguien
lo intenta por API, el servidor responde 403.

### 5.2 · La auditoría es verificable

```bash
./scripts/demo-auditoria.sh
```

Copia el registro, altera una decisión aprobada para que diga «descartada», y el
verificador del proyecto la detecta señalando la línea y terminando con **código 1**.
Trabaja sobre una copia y prueba con SHA-256 que el archivo real no cambió.

> **Lo que hay que decir:** «El registro no es imposible de editar: cualquiera con
> permisos puede. Es **detectable**, y por eso sirve como evidencia.»

> ⚠️ **No edites `decisions.jsonl` a mano para esto.** Es el registro de auditoría del
> equipo y no hay forma prolija de deshacer el cambio.

---

## 6. Si algo falla

| Síntoma | Qué pasó | Qué hacer |
|---------|----------|-----------|
| `Kibana no responde` | El stack está abajo | `./scripts/start.sh` y esperá a que libere la consola |
| **`LA CAPTURA DE ELASTICSEARCH NO SE RENOVÓ`** | El pipeline siguió con datos viejos | **No presentes así.** Ver `/tmp/desde-cero-pipeline.log`. Suele ser un 400 en una consulta |
| `todavía no hay alertas` | Las reglas no llegaron a correr | No es un error: el Agente 1 detecta igual. Esperá otro minuto y corré `python3 siem_pipeline.py` de nuevo |
| La fuerza bruta no completa | Faltan los contenedores de simulación | `docker compose --profile simulation up -d ssh-target hydra-attacker` |
| El panel muestra el diseño viejo | Jinja cachea las plantillas | Reiniciá `python3 dashboard.py` |

La fila en negrita es la importante: el guion **aborta** si la captura no se renovó,
justamente porque la demostración afirma que nada estaba guardado.

---

## 7. Preguntas probables

| Pregunta | Respuesta corta |
|----------|-----------------|
| *¿Cómo sé que no son datos preparados?* | Lo acabamos de construir desde cuatro ceros, recargando el navegador en cada paso. |
| *¿El sistema puede bloquear una IP?* | No. No existe ninguna ruta que ejecute nada — se demuestra con `tests/test_no_autonomy.py`, que recorre el AST de todo el código. |
| *¿Y si la IA alucina un comando?* | Los comandos salen de un catálogo fijo en `classifier.py`; el LLM no tiene *function calling*. Hay una prueba con un LLM hostil simulado. |
| *¿Por qué a veces el escaneo aparece sin regla del SIEM?* | Porque el clasificador lo detecta sin esperar a Kibana; si la alerta real (`Port Scan – …`) ya disparó para esa IP, el panel la muestra. El panel siempre dice cuál de las dos pasó. Ver §4. |
| *¿Puedo reproducir esto desde cero?* | Es literalmente lo que acabamos de hacer. `./scripts/start.sh` levanta el stack y despliega las 14 reglas. |
| *¿Cuánto está probado?* | 1043 pruebas, 95 % de cobertura sobre el alcance declarado, y la puerta de calidad corre SAST además de los tests. |

---

## 8. Comandos, en una tarjeta

```bash
# Antes
./scripts/demo-desde-cero.sh --estado      # ¿en qué estado está?
./scripts/start.sh                         # si el stack está abajo
python3 dashboard.py                       # el panel, en otra terminal

# La demostración
./scripts/demo-desde-cero.sh               # el guion completo, narrado

# Después
./scripts/demo-auditoria.sh                # romper la cadena y detectarlo
python3 audit_verify.py                    # verificar el registro real

# Variantes
./scripts/demo-desde-cero.sh --limpiar     # solo dejar todo en cero
./scripts/demo-desde-cero.sh --rapido      # sin pausas (para ensayar)
./scripts/demo-desde-cero.sh --sin-docker  # sin Hydra (no usar en la defensa)
```

---

**Ver también:** [`../scripts/demo-desde-cero.sh`](../scripts/demo-desde-cero.sh) ·
[`auditoria/03-evidencia-para-la-catedra.md`](auditoria/03-evidencia-para-la-catedra.md)
(mapa de evidencia y objetivos de cátedra) ·
[`12-registro-de-pruebas.md`](12-registro-de-pruebas.md) §4.19–§4.20 (los hallazgos
D-11 y D-12, que salieron al construir este guion).
