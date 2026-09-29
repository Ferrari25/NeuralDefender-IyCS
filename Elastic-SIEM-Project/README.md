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
> [`docs/00-arquitectura.md`](./docs/00-arquitectura.md), que indexa los otros 4.

## Ataques contemplados

| Ataque | Script | Técnica MITRE |
|--------|--------|---------------|
| Fuerza bruta SSH | `simulation/run-brute-force.sh` | T1110 |
| Escaneo de puertos | `simulation/run-port-scan.sh` | T1046 |
| Phishing / robo de credenciales | `simulation/run-phishing.sh` | T1566 |

Port scan y phishing también soportan `--offline` (generan logs detectables
sin necesidad de Docker).

## La capa de IA, en 4 pasos

1. **`src/prepare-for-ia.py`** — extrae y limpia alertas + logs de auth desde Elasticsearch.
2. **`src/classifier.py`** (Agente 1, determinístico) — clasifica por reglas/umbrales,
   arma un playbook de acciones con comandos fijos y su explicación, la lista
   de factores detrás de cada severidad, y correlación de campañas (incidentes
   que comparten IP atacante, incluso entre distintos tipos de ataque).
3. **`src/siem_agent.py`** (Agente 2, LLM + fallback) — explica el incidente en
   lenguaje claro, con antecedentes de esa IP si ya hubo una decisión previa.
   Funciona completo sin conexión con el análisis determinístico de respaldo.
4. **`src/dashboard.py`** (Flask) — el analista aprueba/descarta cada acción desde
   la tabla de Eventos de Seguridad Activos; cada decisión queda en un
   registro append-only (`data/decisions.jsonl`), encadenado por hash.

```bash
python3 src/siem_pipeline.py    # extrae → clasifica → analiza
python3 src/dashboard.py        # http://127.0.0.1:5000/login
```

Detalle completo, y panel por panel, en
[`docs/01-instalacion-uso-y-simulaciones.md`](./docs/01-instalacion-uso-y-simulaciones.md)
y [`docs/02-reglas-y-dashboard.md`](./docs/02-reglas-y-dashboard.md).

## Estructura del repositorio

**Stack Elastic**
- `docker-compose.yml` — Elasticsearch, Kibana, Logstash, Filebeat + servicio
  `setup` + perfil `simulation` (contenedores de ataque, no arrancan por defecto)
- `elasticsearch/`, `kibana/`, `logstash/`, `filebeat/` — configuración por servicio
- `.env` / `.env.example` — variables de entorno (`.env` real gitignored)
- `rules/ndjson/` — catálogo de reglas de detección versionadas
- `simulation/` — scripts de simulación de ataque
- `network_logs/` — punto de entrada de eventos de red/web (Filebeat + detección offline)

**Capa de IA y dashboard**
- `src/siem_lib.py` — módulo común (acceso a ES, queries, saneamiento)
- `src/prepare-for-ia.py`, `src/classifier.py`, `src/siem_agent.py` — extraer → clasificar → analizar
- `src/siem_pipeline.py` — orquestador de un solo comando
- `src/dashboard.py` + `templates/` + `static/` — GUI de supervisión (Flask)
- `src/siem_auth.py`, `src/manage_users.py` — autenticación y gestión de usuarios del panel
- `src/verify-cobertura.py` — demuestra que todo lo que dispara en el SIEM llega al panel

**Scripts operativos** (`scripts/`)
- `start.sh` / `reset.sh` — levantar el stack / reiniciar de cero
- `deploy-rules.sh` / `export-rules.sh` — reglas de detección como código
- `pruebas_de_codigo_estatico.sh` / `pruebas_de_servicio.sh` / `pruebas_completas.sh` —
  la puerta de calidad (ver
  [`docs/04-auditoria-pruebas-y-demostracion.md`](./docs/04-auditoria-pruebas-y-demostracion.md))

**Documentación**
- `docs/` — 5 documentos: arquitectura, instalación/uso/simulaciones, reglas y
  dashboard, autenticación, y auditoría/pruebas/demostración. Índice en
  [`docs/00-arquitectura.md`](./docs/00-arquitectura.md).
- `nicotito.md` — puesta en marcha completa desde cero
