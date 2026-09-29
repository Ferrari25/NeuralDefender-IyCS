# 04 · Auditoría, pruebas y demostración

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).
>
> Este documento fusiona tres temas relacionados: qué se auditó y qué se
> encontró, qué se prueba y cómo reproducirlo, y el guion para demostrarlo
> todo en vivo desde cero. El detalle histórico palabra por palabra de cada
> hallazgo sigue en el historial de git — esto es la versión que alguien
> necesita leer hoy, no el proceso completo para llegar hasta acá.

## Auditoría y hallazgos

### Qué pide la materia y cómo se cumple (28-09-2026)

| Objetivo | Estado | Cómo se demuestra |
|----------|:------:|--------------------|
| **Pruebas de código estático** | ✅ | `./scripts/pruebas_de_codigo_estatico.sh` — ruff, eslint (linters) + pylint+secure-coding-standard, bandit (SAST). Líneas de base en cero, verificado contra mutaciones inyectadas a propósito. |
| **Pruebas de servicio** | ✅ | `./scripts/pruebas_de_servicio.sh` — 232 pruebas de integración sobre la API HTTP real, `deploy-rules.sh` contra un Kibana simulado, `reset.sh` contra un sandbox, autenticación completa. |
| **Desarrollo e implementación en entorno de simulación** | ✅ | Los tres ataques se simulan y detectan de punta a punta; el panel exige login; las 14 reglas se despliegan como código; `src/verify-cobertura.py` demuestra que ninguna alerta real del SIEM se pierde en el camino al panel. Falta la suite E2E de navegador (ver Pendientes, más abajo). |

Comando único para reproducir todo: `./scripts/pruebas_completas.sh`.

### Cómo se hizo la auditoría

El proyecto pasó por varias rondas de revisión estructurada (una auditoría
integral inicial, y correcciones puntuales identificadas después, cada una
con su propia prueba de regresión). El criterio fue siempre el mismo: no
negociar sobre la propiedad central del sistema — **la IA sugiere, el humano
decide, y nada ejecuta acciones de contención** (certificado por
`tests/test_no_autonomy.py`, que recorre el AST de todo el código) — y
verificar cada afirmación contra una corrida real, no contra lo que el código
"debería" hacer.

### Hallazgos — bloqueantes y de diseño

Todos con su prueba de regresión en `tests/`. "RESUELTO" significa que hay
una prueba que falla si el problema vuelve a aparecer.

| # | Qué se encontró | Estado |
|---|------------------|--------|
| F-01 | El dashboard no pedía autenticación; el campo `analyst` del registro salía de una variable de entorno, no de quién estaba logueado | ✅ RESUELTO — login Argon2id, sesiones, CSRF, 3 roles |
| F-02 | Solo 4 de las reglas documentadas estaban realmente desplegadas en Kibana | ✅ RESUELTO — 14 reglas versionadas, `deploy-rules.sh` idempotente |
| F-03 | El JavaScript del panel no pasaba por ningún linter | ✅ RESUELTO — ESLint + plugins de seguridad |
| F-04 | No hay pruebas de navegador (E2E) | ⚠️ ABIERTO — ver Pendientes |
| F-05 | El contrato de `/api/v1/incidents` es inconsistente entre endpoints | 🔸 MENOR |
| F-06 | La demo depende de haber atacado en las últimas 24h | ✅ MITIGADO — los scripts de demo preparan todo desde cero |
| F-07 | Cobertura desigual: `src/siem_agent.py` muy por debajo del resto (depende de la API de Gemini, la parte menos verificable sin red) | 🔸 PARCIAL — 39%, con pruebas dedicadas para la normalización de severidad |
| F-08 | La suite dependía de la fecha del sistema | ✅ RESUELTO — fixtures centralizados + guarda de regresión |
| D-01 | Una regla ruidosa de Kibana tapaba a las demás en la muestra que ve el LLM | ✅ RESUELTO — agrupa por regla, no por recencia global |
| D-02 | La víctima aparecía como atacante en las alertas agrupadas por host | ✅ RESUELTO — distingue atacante/víctima/usuario por el campo agrupado |
| D-11 | El panel atribuía a una regla de Elastic detecciones que en realidad hizo el clasificador propio, con nombres inventados | ✅ RESUELTO — `detection_source` declara la procedencia real; ningún `rule_name` se escribe a mano (certificado por AST) |
| D-12 | Una agregación sin `.keyword` sobre `filebeat-*` rompía toda la captura del SIEM | ✅ RESUELTO |
| D-13 | Las alertas de escaneo de puertos y phishing nunca se cruzaban contra los incidentes — solo SSH lo hacía | ✅ RESUELTO — `src/classifier.py` cruza esas alertas por IP y técnica; sigue sin existir un detector genérico para una técnica MITRE completamente nueva (decisión de diseño) |

### Pendiente, por prioridad

| # | Pendiente | Esfuerzo | Por qué importa |
|---|-----------|:--------:|------------------|
| P4 | Suite E2E con Playwright | Medio | Es la única capa del sistema (la interfaz) sin pruebas automatizadas |
| P5 | Vista de triage y pantalla de decisión como rutas separadas | Medio | Presentación del MVP |
| P6 | CI corriendo `pruebas_completas.sh` | Bajo | Evidencia continua, no solo bajo demanda |
| P7 | Contrato estable de `/api/v1/` (F-05) | Bajo | Consistencia de la API |
| P8 | Umbrales de clasificación a configuración externa | Bajo | Ajustar sin tocar código |

**Fuera de alcance, a propósito:** MFA/SSO/recuperación de contraseña,
Suricata/IDS de red real (las simulaciones NDJSON cumplen el rol), un LLM
local vía Ollama (el fallback determinístico ya cubre el caso sin nube),
respaldos cifrados y retención (brecha normativa identificada, no resuelta).

### Conclusión de la auditoría

El núcleo del sistema está construido, verificado y es defendible: la cadena
completa (ataque → detección → clasificación → análisis → supervisión →
auditoría) funciona de punta a punta, la no-autonomía está certificada por
análisis estático y no por convención, y el registro de decisiones es
inmutable de forma verificable, no solo por costumbre. Lo más valioso para
una defensa no es el porcentaje de cobertura — es poder mostrar que las
pruebas **encuentran cosas de verdad**: esta auditoría documenta más de una
decena de defectos reales que las herramientas encontraron.

---

## Registro de pruebas

### Cómo reproducirlo

```bash
export PYTHONPATH="$PWD/.devtools"

./scripts/pruebas_de_codigo_estatico.sh   # linters + SAST
./scripts/pruebas_de_servicio.sh          # estático (AST) + unitarias + servicio + cobertura
./scripts/pruebas_completas.sh            # los dos anteriores juntos
```

O por separado:

```bash
python3 -m pytest tests/unit -q              # solo unitarias
python3 -m pytest tests/integration -q       # solo servicio
python3 -m pytest tests/test_no_autonomy.py -q   # solo la certificación por AST
```

### Los tres tipos, y por qué son distintos

| Tipo | Qué verifica | Ejemplo |
|------|--------------|---------|
| **Estático (SAST + linters)** | Lee el código, no lo ejecuta. Busca vulnerabilidades conocidas (`bandit`, `pylint-secure-coding-standard`) y estilo/prolijidad (`ruff`, `eslint`) | `subprocess.run(..., shell=True)` sin justificar |
| **Estático (AST, propio)** | `tests/test_no_autonomy.py` recorre el AST del proyecto para certificar una propiedad del producto: nada ejecuta comandos | Detecta `os.system()` disfrazado como `getattr(os, "sys"+"tem")` |
| **Unitaria** (`tests/unit/`) | Una función o módulo aislado, sin contactar nada externo | `classifier.detect_port_scans()` con eventos sintéticos |
| **Servicio** (`tests/integration/`) | El contrato real de un componente completo — API HTTP con cliente Flask real, scripts como procesos reales contra un sandbox | Login completo con CSRF y cookies de sesión reales |

### Inventario, última corrida (28-09-2026)

**Unitarias — 846 pruebas, 5 omitidas, ~4s.** Los archivos más grandes:
`test_validators.py` (91, validadores de entrada no confiable),
`test_reglas_como_codigo.py` (155, catálogo de reglas versionado),
`test_iconos.py` (67, sprite SVG sin huérfanos), `test_gestion_usuarios.py`
(66, almacén/hashing/CLI), `test_s01_inyeccion_comandos.py` (57, inyección
por copiar-pegar), `test_contraste_de_la_interfaz.py` (53, WCAG AA),
`test_s02_xss_dashboard.py` (51, XSS y accesibilidad),
`test_severidad_del_agente.py` (43), `test_b0x_robustez_y_formatos.py` (39).
El resto (18 archivos más) cubre desde la identidad de incidentes hasta el
tag de "resuelto" y el interruptor del LLM, uno por función específica.

**Servicio — 232 pruebas, ~46s.** `test_api01_autenticacion.py` (60, login/
roles/sesión/CSRF/fuerza bruta), `test_api_v1.py` (38, contrato completo con
cliente Flask), `test_scripts_de_demostracion.py` (40, los guiones de demo no
ejecutan nada al imprimirse y nombran scripts reales),
`test_a02_a04_integridad.py` (35, cadena de hash y concurrencia real),
`test_despliegue_de_reglas.py` (23, `deploy-rules.sh` contra un Kibana
simulado), `test_api_caracterizacion.py` (17), `test_a01_reset_preserva_auditoria.py`
(12, `reset.sh` real contra un sandbox), `test_auditoria_append_only.py` (7).

**Estático (AST) — 38 pruebas, 2 omitidas, ~15s.** `tests/test_no_autonomy.py`:
certificación de que ningún módulo ejecuta procesos, abre una shell o se
conecta a un host remoto por su cuenta.

**Total: 1116 pruebas.**

### Cobertura

```bash
./scripts/pruebas_de_servicio.sh   # incluye el paso de cobertura al final
```

Umbral: **≥ 80%** sobre `src/classifier.py`, `src/siem_lib.py`,
`src/dashboard.py`, `src/siem_validators.py`, `src/siem_auth.py`,
`src/manage_users.py`. `src/siem_agent.py` queda fuera del alcance estricto a
propósito: su camino principal depende de la API de Gemini, y solo se
prueban el respaldo determinístico y un cliente LLM hostil simulado (F-07,
más arriba).

### Selección por marca

```bash
pytest -m "not bug"   # todas las pruebas activas
pytest -m bug         # 0 pruebas — no queda ningún bug congelado
```

---

## Demostración desde cero

**Para qué sirve.** Es el guion completo de una demo/defensa: qué correr, en
qué orden, qué decir mientras corre y qué contestar si preguntan. La pregunta
que un evaluador va a hacer, explícita o no, es *"¿cómo sé que ese panel no
está mostrando un archivo JSON que ustedes prepararon?"* — este guion la
responde de la única forma que no admite réplica: poniendo todo en cero
delante del público y construyendo el resultado paso a paso.

Cuatro números arrancan en cero: reglas de detección en Kibana (0 → 14),
alertas en Elasticsearch (0 → 4+), documentos de Filebeat (0 → 100+),
incidentes en el panel (0 → 3+).

**No digas "todo lo que ves sale de las reglas que acabo de subir".** No es
cierto y es fácil de refutar: el escaneo de puertos y el phishing los puede
detectar el Agente 1 leyendo `network_logs/` directamente, sin pasar por
Elasticsearch — aparecerían aunque no hubiera una sola regla desplegada (ver
más abajo, "Los dos caminos de detección").

### Antes de empezar

```bash
./scripts/demo-desde-cero.sh --estado   # comprobación; si Kibana no contesta:
./scripts/start.sh
```

Qué tener abierto: terminal con el guion, Kibana en dos pestañas (Security →
Rules y Security → Alerts), el panel (`http://127.0.0.1:5000/login`), y una
terminal libre para `src/audit_verify.py` al final. Los usuarios de
laboratorio los crea `./scripts/demo.sh` (`analista`/`observador`/`auditor`,
credenciales conocidas a propósito — los secretos reales están en `.env`,
sin versionar).

**Cuánto tarda:** 6 a 9 minutos, de los cuales ~4 son espera a que las reglas
disparen (corren cada 1 a 10 minutos) — esa espera **es** parte de la
demostración, es el SIEM trabajando, no el script. `--sin-docker` baja a ~3
minutos omitiendo la fuerza bruta con Hydra, pero pierde la única fila
"Elastic SIEM" del cuadro final — no usar en una defensa real.

### El guion

```bash
./scripts/demo-desde-cero.sh
```

Va narrado y con pausas, pide confirmación antes de borrar.

1. **Todo a cero** — borra reglas, alertas, índices de Filebeat y artefactos
   del pipeline. No baja Docker. El registro de auditoría **no** se borra: se
   archiva en `audit/archive/` (hallazgo A-01) — decirlo antes de que lo
   pregunten.
2. **Mostrar que no hay nada** — recargar Kibana (0 reglas, 0 alertas) y el
   panel (vacío) a la vista de todos.
3. **Desplegar las reglas** (`./scripts/deploy-rules.sh`) — recargar Rules:
   pasa de 0 a 14. Aclarar: desplegar acá es subir reglas de *detección*, no
   ejecuta nada sobre ninguna máquina.
4. **Generar los ataques** — escaneo de 26 puertos y captura de credenciales
   (NDJSON sintético) + fuerza bruta SSH real con Hydra contra el contenedor
   `ssh-target` (no es sintético: los intentos quedan en su
   `/var/log/auth.log`, Filebeat los recoge, Logstash los normaliza,
   Elasticsearch los indexa — la misma ruta que un ataque real).
5. **La ingesta** — el conteo de documentos de Filebeat sube de 0.
6. **Las reglas disparan** — la espera larga. Recargar Alerts y mostrar el
   nombre de la regla. Mientras se espera: cada regla tiene su intervalo (la
   de fuerza bruta agresiva corre cada minuto, otras cada diez) — es Elastic
   evaluando las reglas contra los datos que acaban de entrar, no el
   proyecto.
7. **Clasificación y panel** — el pipeline corre las tres etapas; abrir el
   panel y recargar. Los incidentes están ahí.

### Los dos caminos de detección

```
                    ┌─ reglas de Kibana ──→ alertas ─┐
  ataque → logs ────┤                                ├──→ Agente 1 → Agente 2 → panel
                    └─ network_logs/ ────────────────┘
```

| Camino | Qué detecta | Qué aporta |
|--------|-------------|------------|
| **Elastic SIEM** | Fuerza bruta SSH, escaneo de puertos, phishing | La alerta trae el nombre de la regla, la severidad del SIEM, el riesgo y la técnica MITRE. |
| **Agente 1** | Los tres tipos, sin depender de que la regla ya haya disparado | Cuenta fallos de auth, puertos distintos y envíos de credenciales leyendo los logs directamente. No espera a Elasticsearch, pero si la alerta ya existe, la usa. |

**Si preguntan por qué un escaneo o un phishing aparecen "sin regla SIEM":**
puede pasar, pero ya no es la regla general (hallazgo D-13, resuelto). Si en
el momento de correr `src/siem_pipeline.py` la alerta de Kibana todavía no
disparó, el incidente queda como "Sin regla SIEM (detección propia)"
temporalmente — volver a correr el pipeline un rato después, ya con la
alerta indexada, lo actualiza a la regla real. `src/verify-cobertura.py` es
la herramienta para demostrar esto: compara las alertas reales de
Elasticsearch contra lo que muestra el panel y avisa si algo quedó sin
actualizar.

### Después del guion: cerrar el círculo

**La decisión humana.** Entrar como `analista`, abrir un incidente y aprobar
una acción — el sistema sugirió un comando, no lo ejecutó, y no puede: no
existe ninguna ruta que ejecute nada. Cerrar sesión y entrar como
`observador`: los botones no están; por API, el servidor responde 403.

**La auditoría es verificable.**

```bash
./scripts/demo-auditoria.sh
```

Copia el registro, altera una decisión aprobada para que diga "descartada", y
el verificador la detecta señalando la línea y terminando con código 1.
Trabaja sobre una copia y prueba con SHA-256 que el archivo real no cambió —
el registro no es imposible de editar, es **detectable**, y por eso sirve
como evidencia. **No editar `data/decisions.jsonl` a mano para esto:** es el
registro de auditoría real y no hay forma prolija de deshacer el cambio.

### Si algo falla

| Síntoma | Qué pasó | Qué hacer |
|---------|----------|-----------|
| `Kibana no responde` | El stack está abajo | `./scripts/start.sh` y esperar a que libere la consola |
| **La captura de Elasticsearch no se renovó** | El pipeline siguió con datos viejos | No presentar así. Revisar el log del pipeline — suele ser un 400 en una consulta |
| `todavía no hay alertas` | Las reglas no llegaron a correr | No es un error: el Agente 1 detecta igual. Esperar y correr `python3 src/siem_pipeline.py` de nuevo |
| La fuerza bruta no completa | Faltan los contenedores de simulación | `docker compose --profile simulation up -d ssh-target hydra-attacker` |
| El panel muestra el diseño viejo | Jinja cachea las plantillas | Reiniciar `python3 src/dashboard.py` |

### Preguntas probables

| Pregunta | Respuesta corta |
|----------|-----------------|
| ¿Cómo sé que no son datos preparados? | Se acaba de construir desde cuatro ceros, recargando el navegador en cada paso. |
| ¿El sistema puede bloquear una IP? | No. No existe ninguna ruta que ejecute nada — certificado por `tests/test_no_autonomy.py`, que recorre el AST de todo el código. |
| ¿Y si la IA alucina un comando? | Los comandos salen de un catálogo fijo en `src/classifier.py`; el LLM no tiene *function calling*. Hay una prueba con un LLM hostil simulado. |
| ¿Por qué a veces el escaneo aparece sin regla del SIEM? | El clasificador lo detecta sin esperar a Kibana; si la alerta real ya disparó para esa IP, el panel la muestra. Ver "Los dos caminos de detección". |
| ¿Puedo reproducir esto desde cero? | Es literalmente lo que se acaba de hacer: `./scripts/start.sh` levanta el stack y despliega las 14 reglas. |
| ¿Cuánto está probado? | 1116 pruebas, ≥80% de cobertura sobre el alcance declarado, y la puerta de calidad corre SAST además de los tests. |

### Comandos, en una tarjeta

```bash
# Antes
./scripts/demo-desde-cero.sh --estado      # ¿en qué estado está?
./scripts/start.sh                         # si el stack está abajo
python3 src/dashboard.py                   # el panel, en otra terminal

# La demostración
./scripts/demo-desde-cero.sh               # el guion completo, narrado

# Después
./scripts/demo-auditoria.sh                # romper la cadena y detectarlo
python3 src/audit_verify.py                # verificar el registro real

# Variantes
./scripts/demo-desde-cero.sh --limpiar     # solo dejar todo en cero
./scripts/demo-desde-cero.sh --rapido      # sin pausas (para ensayar)
./scripts/demo-desde-cero.sh --sin-docker  # sin Hydra (no usar en la defensa)
```
