# Triage de alertas

Análisis de falsos positivos y alertas validadas, con su justificación.

En el sistema el triage automático lo produce el pipeline:
- `classifier.py` asigna `false_positive_likelihood` por reglas.
- `siem_agent.py` lo refina (`falso_positivo_probabilidad`) en el análisis.
- El analista lo confirma o descarta en el dashboard → `decisions.jsonl`.

Ejemplo: incidente `INC-AUTH-172.18.0.5-...` (ssh_brute_force) → **verdadero
positivo**, FP=LOW (722.133 fallos desde una IP en minutos; no es un usuario
olvidando su contraseña).
