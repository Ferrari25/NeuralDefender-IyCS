# Guion para videos (NotebookLM) — Presentación del flujo SIEM-IA

Este documento está pensado para **NotebookLM**: cada sección es una **escena**
auto-contenida con (a) un **prompt** para pedirle el video, (b) los **puntos clave**
que debe cubrir, y (c) **qué mostrar en pantalla**. Pedile las escenas en orden y
después unís los clips para tener la presentación completa.

> Cómo usarlo en NotebookLM: subí como fuentes este proyecto (`README.md`, la
> carpeta `docs/`, `rules/rules.md`) y luego, para cada escena, usá el prompt de
> "Video Overview" / "Customize" pegando el bloque **Prompt**. Los **Puntos clave**
> y **En pantalla** sirven para guiar el guion y las capturas.

**Hilo conductor (one-liner del proyecto):** *Un ataque genera logs → Elastic los
detecta y dispara una alerta → una IA la clasifica y explica → un analista humano
aprueba o descarta la respuesta sugerida. La IA sugiere, el humano decide.*

**Duración sugerida total:** 7 escenas, ~1–2 min cada una.

---

## Escena 1 · El problema (por qué existe esto)

**Prompt para NotebookLM**
> Creá un video de ~90 segundos que explique el problema que resuelve este
> proyecto: un analista de un SOC recibe entre 500 y 2000 alertas por día, sufre
> "alert fatigue", y el tiempo de detección de un atacante se mide en semanas. El
> tono es divulgativo para una audiencia técnica pero no experta. Cerrá planteando
> la pregunta: ¿se puede pasar de minutos a segundos por alerta sin perder
> precisión?

**Puntos clave**
- Volumen de alertas y fatiga del analista.
- Las herramientas dan datos, no comprensión.
- Consecuencias: alert fatigue, tiempo de respuesta alto, decisiones sin contexto.

**En pantalla:** la sección "El problema" de `SIEM-IA - Contexto y problema` /
`docs/README.md`. Imagen de un dashboard saturado de alertas.

---

## Escena 2 · La arquitectura (las dos capas)

**Prompt para NotebookLM**
> Video de ~90 segundos que explique la arquitectura en dos capas: (1) la capa
> SIEM con Elastic Stack — Filebeat recolecta, Logstash normaliza, Elasticsearch
> almacena y detecta, Kibana visualiza; (2) la capa de IA en Python — un Agente 1
> determinístico clasifica, un Agente 2 (LLM con fallback) explica, y un dashboard
> de supervisión humana. Mostrá cómo se conectan por un archivo de intercambio.

**Puntos clave**
- Capa SIEM: Filebeat → Logstash → Elasticsearch → Kibana.
- Capa IA: prepare-for-ia → classifier (Agente 1) → siem_agent (Agente 2) → dashboard.
- Decisión clave: Agente 1 determinístico ANTES del LLM (rápido, barato, auditable).

**En pantalla:** el diagrama de `docs/01-arquitectura.md`.

---

## Escena 3 · El flujo de datos de un evento

**Prompt para NotebookLM**
> Video de ~2 minutos que siga UN evento de punta a punta: el ataque genera un log
> de "Failed password", Filebeat lo envía, Logstash lo parsea y le pone el tag
> authentication_failure, Elasticsearch lo almacena, la regla de detección cuenta
> los fallos y dispara una alerta, el pipeline de IA la extrae, la clasifica, la
> explica, y termina como una tarjeta en el dashboard del analista.

**Puntos clave**
- Los 8 pasos: ataque → Filebeat → Logstash → Elasticsearch → regla/alerta →
  extracción → análisis (Agente 1 + 2) → dashboard → decisión registrada.
- La frontera de confianza: los logs son datos no confiables; los comandos salen
  de un playbook fijo, no del LLM.

**En pantalla:** el diagrama y la tabla de artefactos de `docs/06-flujo-de-datos.md`.

---

## Escena 4 · Los tres tipos de ataque y sus reglas

**Prompt para NotebookLM**
> Video de ~2 minutos sobre los tres tipos de ataque que detecta el sistema:
> fuerza bruta SSH (MITRE T1110), escaneo de puertos (T1046) y phishing/captura de
> credenciales (T1566). Para cada uno, explicá cómo se simula y cómo una regla de
> detección de Elastic decide que es un ataque (umbrales, cardinalidad,
> correlación de secuencias). Mostrá que variando severidad y riesgo, distintas
> reglas "saltan" distinto.

**Puntos clave**
- Tabla de los 3 ataques con su técnica MITRE y su simulación.
- Cómo salta cada regla: Threshold (conteo), Cardinality (puertos distintos), EQL
  (secuencia fallo→éxito).
- Variaciones de severidad/riesgo entre reglas.

**En pantalla:** `rules/rules.md` (la tabla resumen) y `docs/05-simulaciones-de-ataque.md`.

---

## Escena 5 · Demo en vivo: el ataque y la alerta naciendo

**Prompt para NotebookLM**
> Video de ~2 minutos tipo demostración: se levanta el stack con un comando, se
> crea una regla de detección en Kibana, se lanza un ataque de fuerza bruta SSH
> con Hydra, y se ve la alerta APARECER en Elastic — de cero a una alerta. Tono:
> walkthrough práctico, paso a paso.

**Puntos clave**
- `./scripts/start.sh` levanta todo y espera a que esté sano.
- Crear la regla Threshold (Define / About / Schedule).
- `bash simulation/run-brute-force.sh` genera los fallos.
- La alerta aparece en Security → Alerts tras la corrida de la regla.

**En pantalla:** terminal con los scripts, Kibana creando la regla, Security →
Alerts mostrando la alerta nueva. Apoyarse en `docs/07-reglas-de-deteccion.md` y
`docs/08-puesta-en-marcha-paso-a-paso.md`.

---

## Escena 6 · La IA analiza y el dashboard de supervisión

**Prompt para NotebookLM**
> Video de ~2 minutos: la alerta real entra al pipeline de IA. El Agente 1 la
> clasifica (tipo de ataque, severidad, criterio), el Agente 2 la explica en
> lenguaje claro, y aparece como una tarjeta en el dashboard Flask. Mostrá que el
> analista ve el LOG COMPLETO (cronología de los eventos), el criterio de la
> detección y las acciones recomendadas con su comando, y que aprueba o descarta
> cada una. Enfatizá: la IA sugiere, el humano decide.

**Puntos clave**
- `python3 siem_pipeline.py` empuja la alerta real al dashboard (no es precargado).
- La tarjeta: tipo/severidad, evidencia/cronología, criterio, recomendaciones.
- Botones Aprobar/Descartar → decisión registrada en `decisions.jsonl` (inmutable).

**En pantalla:** el dashboard (`screenshots/dashboard-alerta-real.png` y
`dashboard-evidencia.png`), `docs/04-uso-y-ejecucion.md`.

---

## Escena 7 · Cierre: por qué importa

**Prompt para NotebookLM**
> Video de ~60 segundos de cierre: este sistema democratiza la capacidad de
> respuesta — una organización chica con un solo administrador tiene el mismo
> nivel de análisis automatizado que una empresa con un SOC grande, usando solo
> tecnología open source. La supervisión humana es una feature, no una limitación:
> los falsos positivos en seguridad tienen consecuencias reales. Cerrá con la
> trazabilidad: cada decisión queda registrada para auditoría y para mejorar el
> sistema con el tiempo.

**Puntos clave**
- Democratización con open source (Elastic, Python, Docker, LLM local opcional).
- Supervisión humana = confiabilidad.
- Registro inmutable = auditoría (ISO 27001) y mejora continua.

**En pantalla:** la sección "Por qué importa" de `SIEM-IA - Contexto y problema`.

---

## Apéndice · Orden de armado y consejos

1. Pedí las 7 escenas a NotebookLM en orden; revisá que el hilo conductor se
   mantenga ("la IA sugiere, el humano decide").
2. Para que los videos sean consistentes, subí siempre las mismas fuentes
   (README, docs/, rules/) y mencioná los nombres de archivo en los prompts.
3. Si una escena queda larga, partila (ej. Escena 3 en "ingesta" y "detección").
4. Cierre recomendado de la presentación: Escena 5 (demo) + Escena 6 (dashboard)
   son el corazón; el resto contextualiza.
