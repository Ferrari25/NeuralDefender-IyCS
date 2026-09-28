# Reglas de detección (detection-as-code)

Reglas listas para importar en Elastic (JSON/NDJSON), versionadas en vez de vivir
solo en la UI de Kibana.

- `brute-force.example.json` — la regla Threshold de fuerza bruta SSH (T1110)
  exportada. Importar en Kibana: **Security → Rules → Import**.

Pendiente recomendado: exportar también las reglas de port scan y phishing una vez
creadas en Kibana (hoy esos ataques se detectan en la capa IA por `classifier.py`).
Ver `docs/07-reglas-de-deteccion.md` en la raíz del repo.
