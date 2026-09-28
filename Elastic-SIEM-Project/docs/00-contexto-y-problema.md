# 00 · Contexto y problema

Por qué existe este proyecto, antes de entrar en arquitectura o instalación.

## Misión

Reducir el tiempo que le toma a un analista de seguridad — o a una sola persona
encargada de seguridad en una organización sin SOC dedicado — pasar de "hay una
alerta" a "sé qué pasó y qué tengo que hacer", sin quitarle a esa persona la
decisión final. El sistema clasifica, correlaciona y explica; el humano aprueba
o descarta.

## Visión

Que un equipo de seguridad chico (una o dos personas, o incluso un/a sysadmin sin
formación especializada en seguridad) pueda operar con el mismo nivel de
detección y respuesta razonada que hoy solo es accesible para organizaciones con
un SOC de varias personas — usando exclusivamente herramientas open source
(Elastic Stack, Python) y sin depender obligatoriamente de servicios pagos en la
nube (el sistema funciona completo con el análisis determinístico local si no
hay LLM disponible).

## Alcance

**Incluido en este proyecto:**
- Ingesta y normalización de logs (Filebeat → Logstash → Elasticsearch) para
  autenticación SSH y eventos de red/web sintéticos.
- Motor de reglas de detección de Elastic Security (Kibana), con un catálogo
  curado de reglas listas para usar (ver [`docs/alertas/`](alertas/README.md)).
- Clasificación determinística de incidentes (Agente 1) con explicabilidad
  (qué factores llevaron a la severidad asignada) y correlación entre
  incidentes que comparten IP (detección de campañas de ataque).
- Análisis en lenguaje claro (Agente 2), con LLM (Gemini) o fallback
  determinístico, enriquecido con contexto histórico de decisiones previas
  sobre la misma IP.
- Dashboard de supervisión humana con registro de decisiones append-only e
  inmutable, para trazabilidad y auditoría.
- Simulación de 3 tipos de ataque (SSH brute force, port scan, phishing) para
  demo y testing, con y sin el stack de Elastic levantado.

**Explícitamente fuera de alcance (por ahora):**
- Contención automática: el sistema **nunca** ejecuta una acción de bloqueo por
  sí solo, ni con LLM ni sin él — ver [el principio rector](#el-principio-rector).
- Detección de red real con IDS (Suricata): los eventos de port scan/phishing
  son sintéticos, generados por los scripts de `simulation/`. No hay captura de
  tráfico real de red.
- Multi-tenant / múltiples organizaciones: es un despliegue de un solo host,
  pensado para una organización o un laboratorio de aprendizaje.
- Alta disponibilidad / clustering: Elasticsearch corre en modo un solo nodo.

## El problema real que se quiere resolver

Un analista de seguridad que trabaja en el SOC (Security Operations Center) de
cualquier organización mediana empieza su turno con entre 500 y 2000 alertas
acumuladas. No es exageración: es el orden de magnitud real que generan los
sistemas de seguridad modernos por día. Ese analista tiene que decidir cuáles
son reales, cuáles son ruido, y cuáles requieren acción inmediata — solo, o con
un equipo pequeño, bajo presión de tiempo.

El problema no es que falten herramientas. Los SIEM existen hace décadas. El
problema es que las herramientas actuales generan **información** pero no
generan **comprensión**. Le dicen al analista que hubo 47 intentos de login
fallidos desde una IP en los últimos 10 minutos. Pero no le dicen qué significa
eso en el contexto de su red, qué debería hacer exactamente, ni si esa misma IP
estuvo activa hace dos horas intentando otra cosa. El analista tiene que
construir ese razonamiento él solo, para cada alerta, todo el día.

Eso genera tres consecuencias graves:

**Alert fatigue.** Cuando un analista ve mil alertas por turno, el cerebro
empieza a normalizar. Las alertas dejan de sentirse urgentes y se desarrolla un
hábito inconsciente de descartar lo que parece repetitivo — ahí es exactamente
donde se esconden los ataques más sofisticados: en el ruido, con patrones
lentos y graduales que individualmente no alarman pero en conjunto son una
intrusión activa. *(Esta es la razón concreta por la que la guía de
[alertas recomendadas](alertas/01-alertas-recomendadas.md) insiste en curar
pocas reglas de calidad en vez de activar todas las posibles.)*

**Tiempo de respuesta alto.** El tiempo promedio entre que un atacante entra a
una red y que el equipo de seguridad lo detecta se mide, según la industria, en
semanas o meses — no horas. No es porque los analistas sean malos en su
trabajo: es porque el volumen de información hace imposible que una persona
correlacione eventos distribuidos en el tiempo de manera eficiente.

**Decisiones bajo presión sin contexto suficiente.** Cuando una alerta escala y
el analista tiene que actuar, muchas veces lo hace sin ver el cuadro completo:
¿esta IP es un atacante real o un scanner legítimo de un proveedor? ¿bloquearla
corta algún servicio crítico? ¿qué técnica está usando exactamente? Sin
respuestas rápidas, la decisión se toma con información incompleta.

## Qué agrega este sistema sobre un SIEM tradicional

Un SIEM tradicional (Elastic, Splunk, QRadar) es, en esencia, una base de datos
muy rápida con búsqueda y reglas de correlación. Cuando una regla dispara, crea
una alerta con datos técnicos crudos: timestamp, IP, puerto, cantidad de
ocurrencias. El analista lee eso y construye el análisis desde cero.

Lo que este proyecto agrega encima es una capa de razonamiento automático que
**no reemplaza** al analista: le entrega un primer análisis ya hecho, en
lenguaje que se lee y se entiende rápido, con una recomendación concreta. El
analista pasa de *construir* el análisis a *aprobar o descartar* una
recomendación ya elaborada — la diferencia entre leer "47 failed SSH logins
from 185.220.101.43 in 10 minutes" y leer "esta IP está ejecutando fuerza
bruta automatizada contra SSH, el patrón de temporización sugiere Hydra o
Medusa, no aparece en ningún listado de IPs conocidas; se recomienda bloquear
en el firewall perimetral; probabilidad de falso positivo: baja."

## El flujo concreto (cómo está implementado hoy)

1. Un agente clasificador **determinístico** (`classifier.py`, Agente 1) revisa
   el evento contra reglas/umbrales conocidos y determina tipo de ataque y
   severidad. Es rápido y auditable: o cumple el patrón, o no.
2. Ese resultado pasa a un agente de lenguaje (`siem_agent.py`, Agente 2 — LLM
   con fallback determinístico sin red) que explica qué está pasando, por qué
   es peligroso en ese contexto, y qué acción tomar.
3. Lo que llega al analista es una card en el [dashboard](04-uso-y-ejecucion.md):
   qué IP está involucrada, qué nivel de riesgo tiene, qué hizo exactamente, qué
   significa en términos de ataque, y botones para **aprobar** o **descartar**
   cada acción sugerida. El analista no escribe comandos ni correlaciona
   eventos a mano — los procesa en segundos en vez de minutos.
4. Cada decisión queda registrada de forma inmutable en `decisions.jsonl`. Si el
   analista descartó algo que después resultó ser real, o aprobó un bloqueo que
   cortó un servicio legítimo, ambas cosas quedan en el log — trazabilidad
   completa para auditoría y para recalibrar el criterio con el tiempo.

## Por qué esto importa más allá de un proyecto académico

La mayoría de las organizaciones no tienen un SOC con 20 analistas: tienen una
o dos personas encargadas de seguridad como parte de un rol más amplio, sin
tiempo para revisar miles de alertas por día. Un sistema así democratiza la
capacidad de respuesta: la inteligencia está en el software, no en la cantidad
de gente disponible.

El diseño con supervisión humana es una decisión deliberada, no una limitación.
El sistema **nunca** bloquea nada sin que un humano apruebe la acción — los
falsos positivos en seguridad tienen consecuencias reales (cortar un proveedor
legítimo, interrumpir un servicio crítico). **La IA sugiere, el humano decide.**
Ese equilibrio es lo que hace al sistema confiable en un entorno real.

## Alcance actual vs. ambición original

Este documento describe el problema y el flujo tal como están **implementados
hoy**: Agente 1 determinístico en Python + Agente 2 con Gemini y fallback local
+ dashboard Flask de supervisión. Durante el diseño se evaluaron piezas
adicionales (Suricata para detección de red real, Ollama como LLM 100% local,
Redis como cola de mensajes, un frontend en React) que **no forman parte del
sistema construido** — quedan como trabajo futuro razonable, en particular
Ollama local si en algún momento se procesan datos reales (ver
`.claude/claude-context/outputs/auditoria-y-mejoras-2026-06-11.md`, sección 6).
