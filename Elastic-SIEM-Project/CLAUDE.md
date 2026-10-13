# CLAUDE.md — Orientación del proyecto (se carga automáticamente cada sesión)

> Este archivo lo lee Claude Code solo al iniciar. Es el punto de entrada: explica
> qué es el proyecto y **dónde está el contexto completo**, sin duplicarlo.

## Qué es

**SIEM-IA:** un Elastic Stack SIEM + una capa de IA con dashboard de supervisión
humana. Un ataque genera logs → Elastic detecta → un Agente 1 determinístico
clasifica → un Agente 2 (LLM con fallback) explica en lenguaje claro → un analista
**aprueba/descarta** cada acción sugerida desde un dashboard, y cada decisión queda
registrada de forma inmutable. Principio rector: **la IA sugiere, el humano decide.**

Ataques contemplados: SSH brute force (T1110), port scan (T1046), phishing/captura
de credenciales (T1566).

## Dónde está el contexto completo (leer según haga falta)

- **`docs/`** — documentación del sistema, en 5 archivos (la fuente de verdad
  técnica): `00-arquitectura.md` (contexto, componentes, requerimientos, flujo
  de datos), `01-instalacion-uso-y-simulaciones.md`, `02-reglas-y-dashboard.md`,
  `03-autenticacion-y-control-de-acceso.md`, y
  `04-auditoria-pruebas-y-demostracion.md` (hallazgos, qué se corrigió, qué
  queda pendiente, y el guion de demo).
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
| `audit` | `cadena.py`, `audit_verify.py` (CLI) | **Único escritor** de los registros append-only encadenados → `data/audit/`. |
| `collector` | `collector.py`, `es_client.py` | El único con credenciales de ES. Captura → `data/collector/siem_clean.json`. |
| `classifier` | `classifier.py` | Agente 1 determinístico (reglas/umbral + playbook). Sin estado; lee `network_logs/` (ro). |
| `analyst` | `siem_agent.py`, `perfil_agente.md` | Agente 2 (Gemini con fallback). Sin estado; el único con `GEMINI_API_KEY`. Consulta su memoria a `knowledge`. |
| `knowledge` | `memoria.py` | Memoria del Agente 2: documentos, casos resueltos, lecciones (**aprobadas a mano**) → `data/knowledge/`. |
| `pipeline` | `orquestador.py`, `siem_pipeline.py` (CLI) | Orquesta collector→classifier→analyst→audit por HTTP → `data/pipeline/siem_incidents.json`. |

`libs/`: `siem_lib.py` (tiempo, saneamiento, JSON), `siem_validators.py` (lista
blanca de IP/usuario), `siem_servicios.py` (**única puerta entre servicios**:
registro cerrado de destinos + token interno `SIEM_INTERNAL_TOKEN`).

## Cómo correrlo (resumen — detalle en `docs/01-instalacion-uso-y-simulaciones.md`)

```bash
./scripts/start.sh                                  # stack Elastic + 14 reglas + los 8 microservicios
./scripts/siem.sh usuarios crear ana --rol analyst  # primer usuario (una sola vez)
bash simulation/run-brute-force.sh                  # generar ataque (o --offline para port scan/phishing)
./scripts/siem.sh pipeline                          # detección → análisis
# → http://127.0.0.1:5000/login  (supervisión)
# Solo la capa IA, sin el stack Elastic (el collector queda en 503 y el ciclo sigue):
docker compose up -d --build gateway
bash simulation/run-port-scan.sh --offline && ./scripts/siem.sh pipeline
```

Las herramientas de cada servicio corren DENTRO de su contenedor:
`./scripts/siem.sh {pipeline|usuarios|auditoria|cobertura|logs-es|estado}`.

## Notas que ahorran tiempo

- **El Agente 2 (Gemini) tiene un interruptor aparte de la key**: `SIEM_USE_LLM=true`
  en `.env` (default `false`). Con la key puesta pero el interruptor apagado, sigue
  yendo al **fallback determinístico** — es a propósito, para no gastar tokens sin
  querer. El sistema funciona completo offline con el fallback.
- **El Agente 2 aprende, pero solo con aprobación humana** (`services/knowledge/`, ver
  `docs/00-arquitectura.md` §Memoria del Agente 2). Cada decisión del panel es un caso;
  un patrón repetido genera una lección *propuesta* que no se usa hasta que un analista
  la aprueba. Una lección solo ajusta `falso_positivo_probabilidad`, nunca severidad ni acciones.
- **Los comandos de respuesta salen del playbook de `services/classifier/classifier.py`, no del LLM**
  (mitigación de inyección de prompt vía logs), y los datos que se interpolan en
  ellos pasan por `libs/siem_validators.py`: si no validan, la acción no se ofrece.
- **Antes de tocar código, correr `./scripts/pruebas_completas.sh`** (linters + SAST + pruebas, ~150 s).
  La puerta falla ante cualquier hallazgo nuevo; las líneas de base están en cero.
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
- **Secretos:** todo en `.env` (gitignored). Pendiente: rotar `ELASTIC_PASSWORD`,
  `KIBANA_SYSTEM_PASSWORD`, `GEMINI_API_KEY`.

