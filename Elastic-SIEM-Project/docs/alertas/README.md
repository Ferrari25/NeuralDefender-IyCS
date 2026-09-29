# Guía de alertas — índice

Esta carpeta responde una pregunta distinta a [`docs/07`](../07-reglas-de-deteccion.md):
no *cómo* se crea una regla paso a paso (eso ya está ahí, con capturas en
[`../../brute_force.md`](../../brute_force.md)), sino **qué alertas vale la pena tener
activas** y por qué — para no repetir, dentro del propio SIEM, el problema de
[alert fatigue](../00-contexto-y-problema.md) que todo este proyecto existe para
resolver.

- **[01 · Alertas recomendadas](01-alertas-recomendadas.md)** — cuáles activar primero,
  cuáles son opcionales, y qué tipo de regla evitar por ruidosa o redundante.
- **[Catálogo técnico completo](../../rules/rules.md)** — las 14 configuraciones de
  regla listas para pegar en Kibana (Define/About/Schedule/Actions), con severidad,
  riesgo y mapeo MITRE ATT&CK de cada una. Esta guía elige un subconjunto curado de
  ese catálogo; no lo duplica.

## Qué es una "regla de detección" en este sistema

Una **regla de Kibana** (Security → Rules) es lo que convierte logs crudos en una
**alerta**: sin regla, Elasticsearch tiene los datos pero nadie los está evaluando.
Cuando una regla dispara, escribe un documento en el índice
`.alerts-security.alerts-default`.

Eso conecta con la capa de IA de dos maneras distintas, a propósito:

1. **Vía alerta de Kibana** — `prepare-for-ia.py` lee ese índice de alertas y se lo
   pasa al Agente 1 (`classifier.py`), que ya viene con la severidad y la técnica
   MITRE que puso la regla.
2. **Sin alerta de Kibana** — para port scan y phishing (no hay Suricata desplegado
   todavía, ver [`docs/07`](../07-reglas-de-deteccion.md#los-otros-dos-ataques-port-scan-y-phishing)),
   el Agente 1 detecta directamente sobre los eventos crudos en `network_logs/` y
   `siem_clean.json`, aplicando su propio umbral. Por eso el umbral de una regla de
   Kibana y el umbral del clasificador Python **no tienen por qué coincidir**: son
   dos capas de detección independientes, no una duplicación.

## Cómo crear cualquier regla (resumen de los 4 pasos)

Detalle completo con capturas: [`docs/07`](../07-reglas-de-deteccion.md). Resumen para
tener el mapa mental antes de entrar a Kibana:

1. **Security → Rules → Detection rules (SIEM) → Create new rule.**
2. **Define rule** — elegís el tipo (`Threshold` para "más de N eventos agrupados
   por campo X", `Custom query` para "este patrón puntual", `Event Correlation/EQL`
   para "este evento seguido de este otro") y la condición.
3. **About rule** — nombre, descripción, severidad, risk score, técnica MITRE ATT&CK,
   y **la lista de falsos positivos esperables** (no es opcional: es lo que evita
   que la regla se convierta en ruido).
4. **Schedule** — cada cuánto corre y cuánto "mira para atrás".
5. **Rule actions** — `Per rule run` (un resumen por corrida) salvo que la severidad
   sea alta/crítica, donde conviene `For each alert` para no perder tiempo de
   reacción.
