# Auditoría del Council y mejoras aplicadas — SIEM-IA

**Fecha:** 2026-06-11
**Moderador:** Arquitecto de Ciberseguridad (Claude)
**Consejo:** Threat Hunter · Rule Engineer · Compliance Auditor
**Alcance:** auditoría completa contra la nota de contexto del Second Brain + aplicación de
todas las mejoras priorizadas (P0/P1/P2), construcción de la GUI de supervisión humana y
cierre del ciclo detección → análisis → acción supervisada.

---

## 1. Resumen ejecutivo

El proyecto tenía una base Elastic sólida y un PoC de análisis IA, pero funcionaba como
*análisis batch manual con LLM en la nube*, mientras la nota de contexto describe un
*pipeline autónomo con supervisión humana y privacidad local*. Esta intervención:

- Cerró los huecos de seguridad P0 (secretos versionados, healthcheck roto, crashes del agente).
- Mejoró la calidad de ingesta (Logstash/Filebeat) para que la IA vea datos fieles.
- Reescribió la capa Python: módulo común, **Agente 1 determinístico** + **Agente 2 LLM** con
  salida estructurada, mitigación de inyección de prompt y **fallback** sin red.
- Construyó la pieza que faltaba del diseño: una **GUI de supervisión humana** donde el analista
  aprueba/descarta cada acción sugerida, con **registro append-only** e inmutable de decisiones.

El flujo completo se valida offline (con el stack apagado) usando la última captura real
de `siem_clean.json`.

---

## 2. El nuevo flujo (detección → análisis → acción supervisada)

```
                      ┌──────────────────────── Elastic SIEM ────────────────────────┐
  Ataque (Hydra) ──▶ ssh-target ──▶ Filebeat ──▶ Logstash ──▶ Elasticsearch ──▶ regla
                      └───────────────────────────────────────────────────────────────┘
                                                                          │ alerta
                                                                          ▼
  prepare-for-ia.py        →  siem_clean.json   (extracción + limpieza + agregación por IP)
        │
        ▼
  classifier.py  (Agente 1, determinístico)  →  reglas/umbral + playbook de acciones
        │
        ▼
  siem_agent.py  (Agente 2, LLM/fallback)    →  análisis en lenguaje claro + severidad
        │
        ▼
  siem_incidents.json
        │
        ▼
  dashboard.py (Flask)  →  el analista APRUEBA / DESCARTA cada acción  →  decisions.jsonl (append-only)
```

Orquestación de un comando: `python3 siem_pipeline.py` corre las tres etapas en orden.

---

## 3. Hallazgos de la auditoría (contraste vs. la nota de contexto)

### Alineación
- Implementado ~30 %. La parte hecha se desviaba del diseño en 3 puntos:
  1. El "Agente 1 clasificador con reglas Sigma" (determinístico) estaba implementado como
     **otro LLM** → se perdía la etapa rápida/auditable. **Corregido** (ver §4).
  2. La promesa "el analista recibe la alerta ya analizada con un botón para aprobar/descartar"
     no existía: el flujo era batch manual. **Corregido** con la GUI.
  3. El "registro de cada decisión" no existía (`ai_report.json` se sobreescribía). **Corregido**
     con `decisions.jsonl` y `analysis_history.jsonl` append-only.

### Errores y vulnerabilidades (confirmados)
| ID | Archivo | Problema |
|----|---------|----------|
| B1 | docker-compose.yml | Healthcheck de ES sin credenciales con seguridad activada → 401 → dependientes bloqueados |
| B2 | siem_agent.py | `TypeError` al formatear `None` con `:,` cuando el LLM no devolvía JSON |
| B3 | siem_agent.py | `AttributeError` si faltaba `impacto` |
| B4 | siem_agent.py | Corría el LLM aunque hubiera 0 alertas → reporte alucinado |
| B5 | beats.conf | Grok sin `overwrite` → `message` se volvía array |
| B6 | beats.conf | Sin filtro `date` → `@timestamp` = hora de ingesta, no del evento |
| B7 | beats.conf | `[tags] =~ "ssh"` indefinido sobre arrays; geoip fallaba en IPs privadas |
| B8 | filebeat-ssh.yml | Config muerta (no montada, glob que nunca matchea) |
| S1 | logstash.yml / kibana.yml / docker-compose.yml | `elastic123` y `kibana123` versionadas en Git |
| S2 | .env | API key de Gemini en texto plano |
| S3 | siem_agent.py | Inyección de prompt vía `message` (controlado por atacante); comandos del LLM al operador sin validar |
| S4 | docker-compose.yml | 9200/5601/2222 expuestos a toda la LAN |
| S5 | flujo de datos | Logs con IPs/usuarios enviados a la nube de Gemini, contra la premisa de privacidad |
| S6 | siem_agent.py | Comentario ofensivo `#NICOPUTO` en archivo versionado |

---

## 4. Cambios aplicados (changelog por archivo)

### Seguridad / configuración (P0)
- **.env** — parametrizado; agregadas `KIBANA_SYSTEM_PASSWORD`, `KIBANA_SAVEDOBJECTS_KEY`,
  `ES_HOST`, `ANALYST_NAME`. Nota de rotación sobre la key de Gemini.
- **.env.example** (nuevo) — plantilla sin secretos, segura para commitear.
- **kibana/kibana.yml** — `kibana123` y la encryptionKey ahora vienen de `${...}`.
- **logstash/config/logstash.yml** — password de monitoreo desde `${ELASTIC_PASSWORD}`.
- **siem_agent.py** — eliminado el comentario `#NICOPUTO` (S6).

### docker-compose.yml (P0/P1)
- Healthcheck de ES **con credenciales** (`-u elastic:${ELASTIC_PASSWORD}`) — arregla B1.
- Servicio **`setup`** one-shot que fija el password de `kibana_system` vía API (auth real de Kibana).
- Puertos **bindeados a `127.0.0.1`** (9200/5601/5044/9600/2222) — arregla S4.
- **`restart: unless-stopped`** en servicios core.
- `ssh-target` y `hydra-attacker` movidos a **`profiles: ["simulation"]`** (no arrancan por defecto);
  imagen del atacante **pineada** a `ubuntu:22.04`.
- ES: removidos settings duplicados entre env y `elasticsearch.yml` (evita "duplicate settings").
- Filebeat: montado `/var/run/docker.sock` (necesario para `add_docker_metadata`).

### Pipeline de ingesta (P1)
- **logstash/pipeline/beats.conf** — `overwrite => ["message"]` (B5); filtro **`date`** para
  `@timestamp` real (B6); `if "ssh" in [tags]` (B7); **geoip solo para IPs públicas** vía `cidr`
  (B7); soporte para `Invalid user`.
- **filebeat/filebeat.yml** — migrado a **`filestream`**; paths **acotados** (auth.log/syslog/messages,
  no `/var/log/*.log`); **`drop_event`** descarta ruido GPU/Xorg en ingesta; removido
  `add_kubernetes_metadata`.
- **filebeat/filebeat-ssh.yml** — marcado **DEPRECATED** con encabezado (config muerta, B8).

### Capa Python (P1/P2)
- **siem_lib.py** (nuevo) — módulo común: config desde `.env`, sesión ES, queries **con rango
  temporal** y **agregación por IP**, saneamiento anti-inyección, utilidades JSON/JSONL append-only.
- **classifier.py** (nuevo, **Agente 1 determinístico**) — agrupa eventos en incidentes por IP,
  aplica reglas/umbral (MITRE T1110), y asigna un **playbook de acciones con comandos fijos**
  (no del LLM → el operador nunca recibe un comando alucinado/inyectado).
- **siem_agent.py** (reescrito, **Agente 2**) — enriquece cada incidente con análisis en lenguaje
  claro; **salida estructurada** (`response_mime_type=application/json`, sin parseo de markdown);
  **system instruction** que marca los logs como datos no confiables (mitiga S3); **fallback
  determinístico** si no hay key/red; aborta con 0 incidentes (B4); reporte tolerante a `None` (B2/B3);
  esquema **alineado con la nota "Prompts de IA"** (`explicacion`, `metodologia`, `contexto_riesgo`,
  `severidad_ajustada`, `falso_positivo_probabilidad`, `referencias`).
- **prepare-for-ia.py** (refactor) — usa `siem_lib`; ventana temporal + agregación; **no
  sobreescribe** `siem_clean.json` si ES está caído (preserva la captura para demos).
- **get-logs.py** (refactor) — utilidad de inspección ad-hoc sobre `siem_lib` (sin lógica duplicada).
- **siem_pipeline.py** (nuevo) — orquestador detección→análisis→acción.

### GUI de supervisión humana (cierra el diseño)
- **dashboard.py** (nuevo, Flask) — lee `siem_incidents.json`; endpoints `/api/incidents`,
  `/api/decision` (POST), `/api/decisions`; el estado de cada acción se reconstruye por **replay**
  del log append-only.
- **templates/index.html** (nuevo) — panel SOC oscuro con cards por incidente, análisis y
  botones **Aprobar/Descartar** por acción; auto-refresh cada 15 s.
- **decisions.jsonl** — registro **append-only e inmutable** de decisiones (analista, timestamp, nota).
- **analysis_history.jsonl** — registro append-only de cada corrida del análisis.
- **requirements.txt** (nuevo) — dependencias.
- Evidencia: `screenshots/dashboard-supervision.png`.

---

## 5. Verificación realizada

- `docker compose config` válido; `--profile simulation` aísla atacante/objetivo.
- `python3 -m py_compile` OK en los 7 scripts.
- Pipeline end-to-end **offline** (ES apagado): preserva datos → 1 incidente `ssh_brute_force`
  [CRITICA, 722 133 eventos, atacante 172.18.0.7, usuario testuser] → análisis fallback.
- GUI: HTTP 200, render de incidentes, POST de decisión → append en `decisions.jsonl` →
  estado reflejado por replay. Captura tomada.
- La key de Gemini está en cuota 0 (free tier) → el **fallback se activó correctamente**.

---

## 6. Pendiente / recomendado (no bloqueante)

1. **Rotar** la `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD` y la **GEMINI_API_KEY** (estuvieron
   expuestas en Git/sesión). Considerar limpiar el historial de Git para los secretos.
2. **Privacidad (S5):** evaluar **Ollama local** vs. Gemini con datos reales y documentar la
   decisión en el Second Brain (Ley 25.326). El fallback ya permite operar sin nube.
3. **Detection-as-code:** exportar las reglas de Kibana al repo para versionarlas.
4. **Orquestación automática:** un watcher que dispare el pipeline al aparecer alertas nuevas
   (hoy es por comando), para llegar al "tiempo de respuesta en segundos" de la nota.
5. Marcar la sección "✅ Hecho" de la nota de estado con lo realmente completado.

---

## 7. Cómo correr el sistema

```bash
# 1. Configuración
cp .env.example .env          # y completar valores reales
pip install -r requirements.txt

# 2. Stack Elastic (sin la simulación)
docker compose up -d

# 3. Simulación de ataque (perfil aparte)
docker compose --profile simulation up -d
bash simulation/run-brute-force.sh

# 4. Pipeline detección → análisis
python3 siem_pipeline.py

# 5. Supervisión humana
python3 dashboard.py          # http://127.0.0.1:5000
```
