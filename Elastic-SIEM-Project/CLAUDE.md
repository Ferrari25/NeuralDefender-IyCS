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

## Mapa rápido del código (capa IA)

| Archivo | Rol |
|---------|-----|
| `src/siem_lib.py` | Módulo común (ES, queries, saneamiento, utils JSON/JSONL, cadena de hash). |
| `src/siem_validators.py` | Validadores de entrada no confiable (lista blanca de IP/usuario). |
| `src/audit_verify.py` | Verifica la integridad de la cadena del registro de auditoría. |
| `src/siem_auth.py` | Autenticación, sesiones y permisos por rol (viewer/analyst/auditor). |
| `src/manage_users.py` | CLI de gestión de usuarios (crear, listar, rol, baja/alta). |
| `src/prepare-for-ia.py` | Extrae alertas + logs de ES → `data/siem_clean.json`. |
| `src/classifier.py` | Agente 1 determinístico (reglas/umbral + playbook). |
| `src/siem_agent.py` | Agente 2 (LLM Gemini con fallback determinístico). |
| `src/siem_pipeline.py` | Orquestador prepare→classify→analyze. |
| `src/dashboard.py` + `templates/` | GUI de supervisión (Flask, :5000). |

## Cómo correrlo (resumen — detalle en `docs/01-instalacion-uso-y-simulaciones.md`)

```bash
./scripts/start.sh                                  # stack + despliegue de las 14 reglas
# o por partes:
docker compose up -d                              # stack Elastic (setup automatiza kibana_system)
./scripts/deploy-rules.sh                         # 14 reglas de detección versionadas
docker compose --profile simulation up -d         # contenedores de ataque (no arrancan por defecto)
bash simulation/run-brute-force.sh                 # generar ataque
python3 src/siem_pipeline.py                            # detección → análisis
python3 src/manage_users.py crear ana --rol analyst      # primer usuario (una sola vez)
python3 src/dashboard.py                                # http://127.0.0.1:5000/login → supervisión
# Demo sin Docker:
bash simulation/run-port-scan.sh --offline && python3 src/siem_pipeline.py && python3 src/dashboard.py
```

## Notas que ahorran tiempo

- **El Agente 2 (Gemini) tiene un interruptor aparte de la key**: `SIEM_USE_LLM=true`
  en `.env` (default `false`). Con la key puesta pero el interruptor apagado, sigue
  yendo al **fallback determinístico** — es a propósito, para no gastar tokens sin
  querer. El sistema funciona completo offline con el fallback.
- **Los comandos de respuesta salen del playbook de `src/classifier.py`, no del LLM**
  (mitigación de inyección de prompt vía logs), y los datos que se interpolan en
  ellos pasan por `src/siem_validators.py`: si no validan, la acción no se ofrece.
- **Antes de tocar código, correr `./scripts/pruebas_completas.sh`** (linters + SAST + pruebas, ~150 s).
  La puerta falla ante cualquier hallazgo nuevo; las líneas de base están en cero.
- **Las reglas de detección son código** (`rules/ndjson/`, 14 archivos). Se
  despliegan con `./scripts/deploy-rules.sh` (idempotente) y se bajan con
  `./scripts/export-rules.sh`. Los campos de agrupación usan `.keyword`: en
  `filebeat-*` son `text` y agregar sobre ellos falla. Ver `rules/rules.md`.
- **`network_logs/*.json`** es la fuente de port scan/phishing (no hay Suricata);
  es a la vez input de Filebeat y fuente offline del clasificador.
- **El panel exige login** (API-01): sin `SECRET_KEY` en `.env` no arranca, y sin
  usuarios nadie entra. El campo `analyst` del registro sale de la sesión, no del
  entorno — `ANALYST_NAME` ya no existe. Ver `docs/03-autenticacion-y-control-de-acceso.md`.
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

