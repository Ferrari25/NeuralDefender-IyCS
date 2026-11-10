# CLAUDE.md — Orientación del proyecto (se carga automáticamente cada sesión)

> Este archivo lo lee Claude Code solo al iniciar. Es el punto de entrada: explica
> qué es el proyecto y **dónde está el contexto completo**, sin duplicarlo.

## Qué es

**NeuralDefender:** un Elastic Stack SIEM + una capa de IA con dashboard de supervisión
humana. Un ataque genera logs → Elastic detecta → un Agente 1 determinístico
clasifica → un Agente 2 (LLM con fallback) explica en lenguaje claro → un analista
**aprueba/descarta** cada acción sugerida desde un dashboard, y cada decisión queda
registrada de forma inmutable. Principio rector: **la IA sugiere, el humano decide.**

Ataques contemplados: SSH brute force (T1110), port scan (T1046), phishing/captura
de credenciales (T1566).

## Dónde está el contexto completo (leer según haga falta)

- **`docs/`** — documentación del sistema, en 6 archivos (la fuente de verdad
  técnica): `00-arquitectura.md` (contexto, componentes, requerimientos, flujo
  de datos), `01-instalacion-uso-y-simulaciones.md`, `02-reglas-y-dashboard.md`,
  `03-autenticacion-y-control-de-acceso.md`,
  `04-auditoria-pruebas-y-demostracion.md` (hallazgos, qué se corrigió, qué
  queda pendiente, qué prueba cada archivo de `tests/`, la verificación 80/20 y
  el guion de demo), y `05-gem-memoria-del-agente.md` (cómo aprende el Agente 2
  y dónde ver lo que guarda).
- **`pruebas_de_linters.md`** — linters y SAST: qué hace cada herramienta, cómo
  verlos en la terminal y en VS Code. **`pruebas_de_penetracion.md`** — pentest
  simulado y alternativas de remediación.
- **`nicotito.md`** — puesta en marcha completa desde cero en un equipo nuevo.

## Mapa rápido del código (capa IA = microservicios)

La capa IA son **8 microservicios** (`services/<nombre>/`, cada uno con su
`Dockerfile`, su `requirements.txt` y su `<nombre>_service.py` con la API HTTP),
más una librería compartida (`libs/`). Cada servicio es dueño de sus datos en
`data/<servicio>/`. Arquitectura completa: `docs/00-arquitectura.md` §Microservicios.

| Servicio | Archivos clave | Rol |
|----------|----------------|-----|
| `gateway` | `dashboard.py`, `sesion_web.py`, `templates/`, `static/` | Panel de supervisión (Flask). **Único publicado** (127.0.0.1:5000). Sesión, CSRF, RBAC. |
| `auth` | `siem_auth.py`, `manage_users.py` (CLI) | Usuarios, Argon2id, roles, anti-fuerza bruta → `data/auth/users.json`. |
| `audit` | `cadena.py`, `audit_verify.py` (CLI), `reportes.py` | **Único escritor** de los registros append-only encadenados (decisiones, corridas, actividad de memoria, accesos al panel) → `data/audit/`. Arma los reportes. |
| `collector` | `collector.py`, `es_client.py` | El único con credenciales de ES. Captura → `data/collector/siem_clean.json`. |
| `classifier` | `classifier.py` | Agente 1 determinístico (reglas/umbral + playbook). Sin estado; lee `network_logs/` (ro). |
| `analyst` | `siem_agent.py`, `proveedores_llm.py`, `perfil_agente.md` | Agente 2 (Gemma 3 local vía contenedor `ollama`, o Gemini; con fallback). Sin estado; el único con `GEMINI_API_KEY` y acceso a `ollama`. Consulta su memoria a `knowledge`. |
| `knowledge` | `memoria.py` | Memoria del Agente 2: documentos, casos resueltos, lecciones (**aprobadas a mano**) → `data/knowledge/`. |
| `pipeline` | `orquestador.py`, `siem_pipeline.py` (CLI) | Orquesta collector→classifier→analyst→audit por HTTP → `data/pipeline/siem_incidents.json`. |

`libs/`: `siem_lib.py` (tiempo, saneamiento, JSON), `siem_validators.py` (lista
blanca de IP/usuario), `siem_servicios.py` (**única puerta entre servicios**:
registro cerrado de destinos + token interno `SIEM_INTERNAL_TOKEN`).

## Cómo correrlo (resumen — detalle en `docs/01-instalacion-uso-y-simulaciones.md`)

```bash
./scripts/start.sh                                  # stack Elastic + 14 reglas + los 8 microservicios
./scripts/siem.sh usuarios crear ana --rol analyst  # primer usuario (una sola vez)
bash simulation/run-brute-force.sh                  # generar ataque (o --offline, sin Docker; vale para los tres)
./scripts/siem.sh pipeline                          # detección → análisis
# → http://127.0.0.1:5000/login  (supervisión)
# Solo la capa IA, sin el stack Elastic (el collector queda en 503 y el ciclo sigue):
docker compose up -d --build gateway
bash simulation/run-port-scan.sh --offline && ./scripts/siem.sh pipeline
```

Las herramientas de cada servicio corren DENTRO de su contenedor:
`./scripts/siem.sh {pipeline|usuarios|auditoria|reporte|cobertura|logs-es|estado}`.
Mapa de carpetas y "¿dónde busco…?": `README.md` §Dónde está todo. Regla: código en
`services/`, todo lo generado en `data/<servicio>/`, reportes en `reportes/`.

## Notas que ahorran tiempo

- **El Agente 2 usa Gemma 3 local por defecto** (`SIEM_LLM_PROVEEDOR=gemma`, contenedor
  `ollama` en la red `llm-net` sin internet; modelo `gemma3:4b`, se baja una vez con
  `./scripts/siem.sh modelo`). `SIEM_LLM_PROVEEDOR=gemini` usa la API con `GEMINI_API_KEY`.
  Con cualquiera hace falta `SIEM_USE_LLM=true` (default `false`); si no, o si el LLM
  falla, va al **fallback determinístico**. Gemma en CPU tarda ~30-90 s por incidente;
  `SIEM_LLM_PRESUPUESTO` (480 s, tope 540 por el timeout de 600 s del orquestador) corta
  y manda el resto al fallback. Los incidentes sin cambios reutilizan el análisis del
  ciclo anterior (`SIEM_LLM_REUSO`, 3600 s). Sin `SIEM_LLM_PROVEEDOR` se usa Gemma
  (Gemini solo a propósito: los incidentes salen del equipo). `reset.sh` no borra el volumen
  del modelo.
- **El Agente 2 aprende, pero solo con aprobación humana** (`services/knowledge/`, ver
  `docs/00-arquitectura.md` §Memoria del Agente 2). Cada decisión del panel es un caso;
  un patrón repetido genera una lección *propuesta* que no se usa hasta que un analista
  la aprueba. Una lección solo ajusta `falso_positivo_probabilidad`, nunca severidad ni acciones.
- **Toda decisión pasa por un cuadro de confirmación** (`confirmarDecision` /
  `confirmarLeccion` en `static/app.js`) que resume incidente, acción, comando y
  advertencias. Cada decisión guarda su contexto (acción, tipo, severidad, FP) para los
  reportes — nunca el comando. Reportes: `GET /api/v1/reportes?formato=csv|json`.
- **Los comandos de respuesta salen del playbook de `services/classifier/classifier.py`, no del LLM**
  (mitigación de inyección de prompt vía logs), y los datos que se interpolan en
  ellos pasan por `libs/siem_validators.py`: si no validan, la acción no se ofrece.
- **Antes de tocar código, correr `./scripts/pruebas_completas.sh`** (linters + SAST + pruebas, ~150 s).
  La puerta falla ante cualquier hallazgo nuevo; las líneas de base están en cero.
  Incluye las **pruebas de interfaz** (`tests/interfaz/`, Chromium + Playwright, ver
  `pruebas_de_interfaz.md`); sin Chromium instalado se saltean.
  `./scripts/pruebas_de_verificacion.sh` (~90 s) demuestra que la puerta detecta errores:
  sobre una copia temporal, 20 casos sanos tienen que pasar y 5 defectos inyectados
  tienen que fallar (80/20). Si cambiás el código que muta un caso, el script lo avisa.
  Cada archivo de `tests/` tiene que pasar también corrido solo.
  **La suite levanta la malla de microservicios en proceso** (`malla_en_proceso` en
  `tests/conftest.py`): no hace falta Docker para probar, y `servicio_caido(...)`
  simula un contenedor caído.
- **Entre servicios, solo `siem_servicios.llamar()` con destino y ruta literales.**
  `tests/test_no_autonomy.py` lo verifica por AST, enumera la API completa de cada
  servicio, y exige que ninguno ejecute procesos (la allowlist de `subprocess`
  quedó vacía con la migración). Una ruta nueva tiene que figurar ahí.
- **Las reglas de detección son código** (`rules/ndjson/`, 14 archivos). Se
  despliegan con `./scripts/deploy-rules.sh` (idempotente) y se bajan con
  `./scripts/export-rules.sh`. Los campos de agrupación usan `.keyword`: en
  `filebeat-*` son `text` y agregar sobre ellos falla. Ver `rules/rules.md`.
- **El pipeline corre solo cada 2 min** (`services/pipeline/programador.py`,
  `SIEM_PIPELINE_INTERVALO=120` en compose; `0` = solo a mano). Mismo candado que el
  ciclo manual. Con `SIEM_USE_LLM=true` cada corrida usa el LLM (Gemma local: CPU, no tokens).
- **`network_logs/*.json`** es la fuente de port scan/phishing (no hay Suricata);
  es a la vez input de Filebeat y fuente offline del clasificador.
- **El panel exige login** (API-01): sin `SECRET_KEY` en `.env` no arranca, y sin
  usuarios nadie entra. Ningún servicio arranca sin `SIEM_INTERNAL_TOKEN` (start.sh
  lo genera si falta). El campo `analyst` del registro sale de la sesión, no del
  entorno — `ANALYST_NAME` ya no existe. Ver `docs/03-autenticacion-y-control-de-acceso.md`.
- **Agregar sobre `filebeat-*` exige `.keyword`.** No hay plantilla de índice, así que
  el mapeo es dinámico y los campos de texto quedan `text` + subcampo `keyword`.
  Agregar sobre el `text` devuelve 400 y aborta la captura del SIEM (D-12). Vale para
  las reglas y para `services/collector/es_client.py`.
- **Cada incidente declara su procedencia** en `detection_source`: `"elastic"` si vino
  de una alerta real (y entonces `rule_name` es el de esa regla), `"clasificador"` si
  lo detectó el Agente 1 leyendo `network_logs/`. No inventar nombres de regla (D-11).
- **El diseño está tokenizado** (`services/gateway/static/tokens.css`): paleta, escala tipográfica,
  radios y espaciado en grilla de 2px. Lo cargan las dos pantallas — `app.css` y
  `login.css` solo consumen, y ninguna define un `:root` propio. Hay pruebas que
  fallan ante un px suelto o un contraste por debajo de WCAG AA.
- **Secretos:** todo en `.env`, que ya **no** está versionado (plantilla: `.env.example`).
  El historial de git (commit `0ee27c6` y anteriores) todavía lo contiene: hay que
  rotar todo lo que tenía (`ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD`, claves de
  Kibana, `GEMINI_API_KEY`, `SECRET_KEY`, `SIEM_INTERNAL_TOKEN`): `./scripts/rotar-secretos.sh`
  lo hace (con copia de respaldo del `.env`) salvo la key de Gemini y `KIBANA_SAVEDOBJECTS_KEY`.
  Ojo: la contraseña de `elastic` también quedó versionada en `logstash/config/logstash.yml`
  (la imagen de Logstash reescribía el archivo con los `xpack.monitoring.*` del entorno);
  ahora usa `${ELASTIC_PASSWORD}`, pero sigue en el historial: rotarla.
  **Siguen versionados** (decisión del dueño, ver `.gitignore`): `elasticsearch/certs/ca.key`,
  `elasticsearch/certs/node.key`, `data/auth/users.json` (+ `.bak`) y `users.json.bak` en la
  raíz. Cada commit que los toca sube hashes de contraseña y claves privadas: si el repo se
  comparte, regenerar los certificados (CA y nodo) y cambiar las contraseñas de los usuarios
  del panel también.

