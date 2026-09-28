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

- **`docs/`** — documentación del sistema (la fuente de verdad técnica):
  - `01-arquitectura.md`, `02-requerimientos.md`, `03-instalacion-y-montaje.md`,
    `04-uso-y-ejecucion.md`, `05-simulaciones-de-ataque.md`, `06-flujo-de-datos.md`,
    `07-reglas-de-deteccion.md`, `08-puesta-en-marcha-paso-a-paso.md`.
- **`.claude/claude-context/outputs/auditoria-y-mejoras-2026-06-11.md`** — auditoría
  del Council y changelog completo de todo lo aplicado.
- **`.claude/claude-context/`** — flujo del Council (`CLAUDE.md`), agentes, skills y
  contexto reutilizable. Los entregables del Council van a su carpeta `outputs/`.

## Mapa rápido del código (capa IA)

| Archivo | Rol |
|---------|-----|
| `siem_lib.py` | Módulo común (ES, queries, saneamiento, utils JSON/JSONL, cadena de hash). |
| `siem_validators.py` | Validadores de entrada no confiable (lista blanca de IP/usuario). |
| `audit_verify.py` | Verifica la integridad de la cadena del registro de auditoría. |
| `siem_auth.py` | Autenticación, sesiones y permisos por rol (viewer/analyst/auditor). |
| `manage_users.py` | CLI de gestión de usuarios (crear, listar, rol, baja/alta). |
| `prepare-for-ia.py` | Extrae alertas + logs de ES → `siem_clean.json`. |
| `classifier.py` | Agente 1 determinístico (reglas/umbral + playbook). |
| `siem_agent.py` | Agente 2 (LLM Gemini con fallback determinístico). |
| `siem_pipeline.py` | Orquestador prepare→classify→analyze. |
| `dashboard.py` + `templates/` | GUI de supervisión (Flask, :5000). |

## Cómo correrlo (resumen — detalle en `docs/08`)

```bash
./scripts/start.sh                                  # stack + despliegue de las 13 reglas
# o por partes:
docker compose up -d                              # stack Elastic (setup automatiza kibana_system)
./scripts/deploy-rules.sh                         # 13 reglas de detección versionadas
docker compose --profile simulation up -d         # contenedores de ataque (no arrancan por defecto)
bash simulation/run-brute-force.sh                 # generar ataque
python3 siem_pipeline.py                            # detección → análisis
python3 manage_users.py crear ana --rol analyst      # primer usuario (una sola vez)
python3 dashboard.py                                # http://127.0.0.1:5000/login → supervisión
# Demo sin Docker:
bash simulation/run-port-scan.sh --offline && python3 siem_pipeline.py && python3 dashboard.py
```

## Notas que ahorran tiempo

- **El LLM (Gemini) está en cuota 0** → el **fallback determinístico** es el camino
  real hoy. El sistema funciona completo offline.
- **Los comandos de respuesta salen del playbook de `classifier.py`, no del LLM**
  (mitigación de inyección de prompt vía logs), y los datos que se interpolan en
  ellos pasan por `siem_validators.py`: si no validan, la acción no se ofrece.
- **Antes de tocar código, correr `./scripts/check.sh`** (SAST + 1053 pruebas, ~150 s).
  La puerta falla ante cualquier hallazgo nuevo; las líneas de base están en cero.
- **Las reglas de detección son código** (`rules/ndjson/`, 13 archivos). Se
  despliegan con `./scripts/deploy-rules.sh` (idempotente) y se bajan con
  `./scripts/export-rules.sh`. Los campos de agrupación usan `.keyword`: en
  `filebeat-*` son `text` y agregar sobre ellos falla. Ver `rules/rules.md`.
- **`network_logs/*.json`** es la fuente de port scan/phishing (no hay Suricata);
  es a la vez input de Filebeat y fuente offline del clasificador.
- **El panel exige login** (API-01): sin `SECRET_KEY` en `.env` no arranca, y sin
  usuarios nadie entra. El campo `analyst` del registro sale de la sesión, no del
  entorno — `ANALYST_NAME` ya no existe. Ver `docs/15`.
- **Agregar sobre `filebeat-*` exige `.keyword`.** No hay plantilla de índice, así que
  el mapeo es dinámico y los campos de texto quedan `text` + subcampo `keyword`.
  Agregar sobre el `text` devuelve 400 y aborta la captura del SIEM (D-12). Vale para
  las reglas y para `siem_lib`.
- **Cada incidente declara su procedencia** en `detection_source`: `"elastic"` si vino
  de una alerta real (y entonces `rule_name` es el de esa regla), `"clasificador"` si
  lo detectó el Agente 1 leyendo `network_logs/`. No inventar nombres de regla (D-11).
- **El diseño está tokenizado** (`static/tokens.css`): paleta, escala tipográfica,
  radios y espaciado en grilla de 2px. Lo cargan las dos pantallas — `app.css` y
  `login.css` solo consumen, y ninguna define un `:root` propio. Hay pruebas que
  fallan ante un px suelto o un contraste por debajo de WCAG AA.
- **Secretos:** todo en `.env` (gitignored). Pendiente: rotar `ELASTIC_PASSWORD`,
  `KIBANA_SYSTEM_PASSWORD`, `GEMINI_API_KEY`.

## Flujo del Council

Si el usuario escribe `/council [tarea]` o pide "activar el council", seguir el
flujo de `.claude/claude-context/CLAUDE.md` (leer los 4 agentes, simular el debate,
entregar consenso). Los entregables se guardan en `.claude/claude-context/outputs/`.
