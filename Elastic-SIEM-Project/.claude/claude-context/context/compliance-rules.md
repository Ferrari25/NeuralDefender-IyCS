# Normativa que el sistema debe respetar

Marco de cumplimiento relevante para este proyecto (voz del compliance-auditor).

## MITRE ATT&CK — mapeo de detecciones
| Ataque | Táctica | Técnica |
|--------|---------|---------|
| SSH brute force | Credential Access | T1110 (Brute Force) |
| Port scan | Discovery | T1046 (Network Service Discovery) |
| Phishing / captura de credenciales | Initial Access | T1566 (Phishing) |

Cada alerta debe quedar mapeada a su técnica (ya lo hace `prepare-for-ia.py`/`classifier.py`).

## ISO 27001 — gestión de incidentes (A.16)
- **Trazabilidad:** cada decisión del analista se registra en `decisions.jsonl` (append-only,
  inmutable). Nunca se sobreescribe → evidencia preservada.
- **Documentación:** cada incidente lleva análisis, severidad, referencias y acciones. Los reportes
  van a `outputs/`.
- **Roles y responsabilidades:** las acciones del playbook indican responsable (SOC / sysadmin) y plazo.

## Ley 25.326 (Argentina) / privacidad de datos
- Los logs contienen datos personales (IPs, usuarios). Si se usa el LLM en la nube (Gemini), esos
  datos salen a un tercero → requiere base legal/evaluación.
- **Mitigación disponible:** el Agente 2 tiene un **fallback determinístico local**; el sistema
  funciona completo sin enviar nada a la nube. Recomendación de diseño: evaluar Ollama local.

## Principio de supervisión humana
El sistema **nunca** ejecuta una contención automática. Toda acción requiere aprobación humana
registrada — requisito tanto técnico (evitar cortar servicios legítimos) como de rendición de cuentas.
