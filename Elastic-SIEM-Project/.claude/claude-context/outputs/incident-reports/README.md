# Reportes técnicos de incidentes

Reportes de incidente para el equipo / gerencia.

El pipeline genera la materia prima: `siem_incidents.json` (análisis + acciones) y
`analysis_history.jsonl`. Un reporte ejecutivo se arma a partir de un incidente +
las decisiones del analista en `decisions.jsonl` (qué se aprobó, qué se descartó,
tiempo de respuesta).

Estructura sugerida (alineada con el prompt de "reporte de incidente" del Second
Brain): Resumen ejecutivo · Cronología · Impacto potencial · Acciones tomadas ·
Recomendaciones preventivas.
