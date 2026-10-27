# SIEM-IA — Elastic SIEM + capa de IA + dashboard de supervisión

- **Ameed Othman 12220692 (CS)**
- **Ahmed Muwafi 12010640 (NIS)**
- **Motaz Saqqa 12113083 (NIS)**

Un Elastic Stack SIEM (Elasticsearch + Kibana + Logstash + Filebeat) con una
capa de IA encima y un dashboard propio de supervisión humana. Un ataque
genera logs → Elastic detecta → un Agente 1 determinístico clasifica → un
Agente 2 (LLM con fallback) lo explica en lenguaje claro → un analista humano
**aprueba o descarta** cada acción sugerida, y cada decisión queda registrada
de forma inmutable. Principio rector: **la IA sugiere, el humano decide.**

> 🚀 **¿Primera vez con este repositorio?** [`nicotito.md`](./nicotito.md) tiene
> la guía completa para levantar todo desde cero en un equipo nuevo: Docker,
> `.env`, la API de Gemini, usuarios, simulaciones y cómo demostrar las
> pruebas.
>
> 📚 **Documentación técnica completa** (arquitectura, requisitos, flujo de
> datos, reglas de detección, seguridad, pruebas) vive en
> [`docs/00-arquitectura.md`](./docs/00-arquitectura.md), que indexa los otros 5.

## Ataques contemplados

| Ataque | Script | Técnica MITRE |
|--------|--------|---------------|
| Fuerza bruta SSH | `simulation/run-brute-force.sh` | T1110 |
| Escaneo de puertos | `simulation/run-port-scan.sh` | T1046 |
| Phishing / robo de credenciales | `simulation/run-phishing.sh` | T1566 |

Port scan y phishing también soportan `--offline` (generan logs detectables
sin necesidad de Docker).

## La capa de IA, en 4 pasos

1. **`services/collector/collector.py`** — extrae y limpia alertas + logs de auth desde Elasticsearch.
2. **`services/classifier/classifier.py`** (Agente 1, determinístico) — clasifica por reglas/umbrales,
   arma un playbook de acciones con comandos fijos y su explicación, la lista
   de factores detrás de cada severidad, y correlación de campañas (incidentes
   que comparten IP atacante, incluso entre distintos tipos de ataque).
3. **`services/analyst/siem_agent.py`** (Agente 2, LLM + fallback) — explica el incidente en
   lenguaje claro, con antecedentes de esa IP si ya hubo una decisión previa.
   Funciona completo sin conexión con el análisis determinístico de respaldo.
4. **`services/gateway/dashboard.py`** (Flask) — el analista aprueba/descarta cada acción desde
   la tabla de Eventos de Seguridad Activos; cada decisión queda en un
   registro append-only (`data/audit/decisions.jsonl`), encadenado por hash.

Cada paso es un **microservicio** en su propio contenedor (más `auth`, `audit`,
la memoria del agente `knowledge` y el orquestador `pipeline`); ver
[`docs/00-arquitectura.md` §Microservicios](./docs/00-arquitectura.md#microservicios-de-la-capa-ia).

```bash
./scripts/start.sh                                  # stack Elastic + reglas + microservicios
./scripts/siem.sh usuarios crear ana --rol analyst  # primer usuario
./scripts/siem.sh pipeline                          # extrae → clasifica → analiza
# → http://127.0.0.1:5000/login
```

Detalle completo, y panel por panel, en
[`docs/01-instalacion-uso-y-simulaciones.md`](./docs/01-instalacion-uso-y-simulaciones.md)
y [`docs/02-reglas-y-dashboard.md`](./docs/02-reglas-y-dashboard.md).

## Dónde está todo

Tres reglas ordenan el repositorio:

1. **El código de cada microservicio vive en `services/<servicio>/`.**
2. **Todo lo que el sistema genera vive en `data/<servicio>/`**, y solo lo
   escribe el servicio dueño de esa carpeta.
3. **Lo que una persona saca para leer va a `reportes/`.**

```
Elastic-SIEM-Project/
├── services/                   código de la capa IA (un microservicio por carpeta)
│   ├── gateway/                panel web: dashboard.py, templates/, static/   (único publicado, :5000)
│   ├── auth/                   usuarios y roles: siem_auth.py, manage_users.py
│   ├── audit/                  auditoría append-only: cadena.py, audit_verify.py, reportes.py
│   ├── collector/              extracción desde Elasticsearch
│   ├── classifier/             Agente 1: reglas, umbrales y playbook de acciones
│   ├── analyst/                Agente 2: siem_agent.py + perfil_agente.md (la parte "Gem")
│   ├── knowledge/              memoria del Agente 2: memoria.py (documentos, casos, lecciones)
│   └── pipeline/               orquestador del ciclo collector → classifier → analyst → audit
├── libs/                       código compartido por todos los servicios
├── data/                       TODO lo que el sistema genera (volúmenes de Docker)
│   ├── audit/                  decisions.jsonl · analysis_history.jsonl · actividad.jsonl
│   │   └── archivo/            auditoría archivada por reset.sh (solo lectura, nunca se borra)
│   ├── auth/                   users.json (hashes Argon2id)
│   ├── knowledge/              documentos.json · casos.json · lecciones.json
│   ├── collector/              siem_clean.json (última captura del SIEM)
│   └── pipeline/               siem_incidents.json (lo que muestra el panel)
├── reportes/                   reportes generados con ./scripts/siem.sh reporte
├── scripts/                    operación: start, reset, siem.sh, demos, puerta de calidad
├── simulation/                 scripts de ataque (brute force, port scan, phishing)
├── network_logs/               eventos de red/web: entrada de Filebeat y del Agente 1
├── rules/ndjson/               reglas de detección de Kibana, como código
├── elasticsearch/ kibana/ logstash/ filebeat/    configuración del stack Elastic
├── tests/                      unit/ · integration/ · test_no_autonomy.py
└── docs/                       documentación técnica, 6 documentos (índice en 00-arquitectura.md)
```

**¿Dónde busco…?**

| Quiero… | Está en |
|---------|---------|
| ver qué decidió cada analista | `data/audit/decisions.jsonl`, o desde el panel: **Historial de Decisiones → Sacar un reporte** |
| sacar un reporte (CSV/JSON) | panel, o `./scripts/siem.sh reporte --formato csv [--desde AAAA-MM-DD] [--hasta AAAA-MM-DD]` → `reportes/` |
| ver qué aprendió el agente | panel, tarjeta **Memoria del agente**, o `data/knowledge/lecciones.json` — todo lo que guarda el "Gem" en [`docs/05`](./docs/05-gem-memoria-del-agente.md#dónde-ver-lo-que-el-gem-guarda) |
| ver los casos y documentos que usa el agente | `data/knowledge/casos.json` · `data/knowledge/documentos.json` |
| entender cómo aprende el agente | [`docs/05-gem-memoria-del-agente.md`](./docs/05-gem-memoria-del-agente.md) |
| ver los linters y qué hace cada uno | [`pruebas_de_linters.md`](./pruebas_de_linters.md) (terminal y VS Code) |
| saber qué verifica cada archivo de pruebas | [`docs/04` §Registro de pruebas](./docs/04-auditoria-pruebas-y-demostracion.md#registro-de-pruebas) |
| demostrar que las pruebas detectan errores | `./scripts/pruebas_de_verificacion.sh` (80 % de casos sanos pasan, 20 % de defectos inyectados fallan) |
| ver quién aprobó cada lección o cargó un documento | `data/audit/actividad.jsonl` (también figura en el reporte) |
| cambiar la "personalidad" del agente | `services/analyst/perfil_agente.md` |
| cambiar las acciones y los comandos sugeridos | `services/classifier/classifier.py` (`_playbook`) |
| verificar que nadie tocó la auditoría | `./scripts/siem.sh auditoria` |
| el incidente que muestra el panel | `data/pipeline/siem_incidents.json` |

**Scripts operativos** (`scripts/`)
- `start.sh` / `reset.sh` — levantar el stack / reiniciar de cero (la auditoría
  y la memoria del agente se conservan)
- `siem.sh` — atajos para operar la capa IA (`pipeline`, `usuarios`, `auditoria`,
  `reporte`, `cobertura`, `estado`)
- `deploy-rules.sh` / `export-rules.sh` — reglas de detección como código
- `pruebas_de_codigo_estatico.sh` / `pruebas_de_servicio.sh` / `pruebas_completas.sh` —
  la puerta de calidad (ver
  [`docs/04-auditoria-pruebas-y-demostracion.md`](./docs/04-auditoria-pruebas-y-demostracion.md))
- `pruebas_de_verificacion.sh` — verificación 80/20: prueba que la puerta de
  calidad detecta defectos inyectados a propósito

**Documentación**
- `docs/` — 6 documentos: arquitectura, instalación/uso/simulaciones, reglas y
  dashboard, autenticación, auditoría/pruebas/demostración, y el "Gem" (memoria
  del agente). Índice en [`docs/00-arquitectura.md`](./docs/00-arquitectura.md).
- `nicotito.md` — puesta en marcha completa desde cero
- `pruebas_de_linters.md` — linters y SAST, y cómo verlos en VS Code
- `pruebas_de_penetracion.md` — pentest simulado y alternativas de remediación
- `rules/rules.md` — catálogo explicado de las 14 reglas de detección
