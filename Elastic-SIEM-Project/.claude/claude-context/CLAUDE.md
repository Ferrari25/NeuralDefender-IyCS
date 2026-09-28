# Instrucciones globales para Claude Code sobre este proyecto
# Instrucciones de Automatización (Claude Code)

## El Flujo del "Council" (Consejo de Expertos)
Cuando el usuario te pida explícitamente "pasar por el consejo", "activar el council" o usar el comando `/council`, debes ejecutar obligatoriamente este proceso de pensamiento interno antes de escribir cualquier línea de código:

1. **Leer Contexto:** Lee los archivos de configuración de los agentes en:
   - `agents/threat-hunter.md` — seguridad / evasión / vulnerabilidades
   - `agents/rule-engineer.md` — rendimiento de queries (KQL/EQL), falsos positivos
   - `agents/compliance-auditor.md` — normativa (MITRE ATT&CK, ISO 27001), documentación
   - `agents/incident-responder.md` — contención y mitigación práctica (playbooks, IR)
2. **Simular el Debate:** Genera una sección de debate interno donde cada agente critique la propuesta desde su perspectiva (Seguridad, Rendimiento, Normativa y Respuesta).
3. **Consenso Final:** Actúa como moderador, unifica los puntos válidos y entregá la solución definitiva optimizada.

## Atajos de Comandos Simulados
- Si el usuario escribe `/council [tarea]`, interpretalo como la activación del flujo del Consejo para esa [tarea].

## Convenciones del proyecto
- **Outputs del Council:** todo entregable (reportes, auditorías, cambios documentados) va a `outputs/` (`.claude/claude-context/outputs/`).
- **Contexto reutilizable:** `context/` (fuentes de log, topología, normativa) y `skills/` (KQL, EQL, Sigma, parsing). Leélos cuando sean relevantes a la tarea.
- **Documentación del sistema:** la guía completa (arquitectura, requisitos, montaje, uso, simulaciones y flujo de datos) vive en `docs/` en la raíz del repo.

## Arquitectura del sistema (resumen para el Consejo)
Capa SIEM (Elastic: Filebeat → Logstash → Elasticsearch → Kibana) + capa IA en Python:
`prepare-for-ia.py` (extracción) → `classifier.py` (Agente 1 determinístico, reglas/umbral) →
`siem_agent.py` (Agente 2 LLM con fallback) → `dashboard.py` (supervisión humana, decisiones
append-only en `decisions.jsonl`). Ataques contemplados: SSH brute force (T1110), port scan
(T1046), phishing/credential harvesting (T1566). Principio rector: **la IA sugiere, el humano decide**.
