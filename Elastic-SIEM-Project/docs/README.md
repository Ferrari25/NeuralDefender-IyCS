# Documentación del sistema SIEM-IA

Esta carpeta documenta la arquitectura, los requerimientos y la operación del
proyecto: cómo se monta, cómo se usa, cómo se ejecuta y cómo se corren las
simulaciones de ataque. Está pensada para que cualquiera pueda **reconstruir el
sistema desde cero** y entender el **flujo de datos** de punta a punta.

## Índice

| # | Documento | Qué responde |
|---|-----------|--------------|
| 00 | [Contexto y problema](00-contexto-y-problema.md) | Por qué existe este proyecto: el problema real que resuelve |
| 01 | [Arquitectura](01-arquitectura.md) | Qué componentes hay y cómo se conectan |
| 02 | [Requerimientos](02-requerimientos.md) | Qué hace falta (hardware, software, red) |
| 03 | [Instalación y montaje](03-instalacion-y-montaje.md) | Cómo se despliega el stack paso a paso |
| 04 | [Uso y ejecución](04-uso-y-ejecucion.md) | Cómo se corre el pipeline y el dashboard |
| 05 | [Simulaciones de ataque](05-simulaciones-de-ataque.md) | Cómo se generan SSH brute force, port scan y phishing |
| 06 | [Flujo de datos](06-flujo-de-datos.md) | Recorrido completo de un evento: del ataque a la acción |
| 07 | [Reglas de detección](07-reglas-de-deteccion.md) | Cómo configurar la regla en Elastic para que capte la alerta |
| 08 | [Puesta en marcha paso a paso](08-puesta-en-marcha-paso-a-paso.md) | Runbook completo para levantar todo desde cero |
| 09 | [El dashboard, en detalle](09-dashboard.md) | Cada panel explicado con capturas reales: eventos activos, registro de eventos, campañas, contexto histórico, explicabilidad |
| 10 | [Plan de acción](10-plan-de-accion.md) | Auditoría del código, SAST, estrategia de pruebas, camino a la v1.0 y garantía de no-autonomía |
| 11 | [Reporte de la Fase 0](11-reporte-fase-0.md) | Red de seguridad: pruebas de caracterización, certificación de no-autonomía por AST y linters configurados |
| 12 | [Registro de pruebas](12-registro-de-pruebas.md) | Qué se verifica y qué dio: SAST, pruebas de servicio, cobertura y deuda de pruebas |
| 15 | [Autenticación y roles](15-autenticacion-y-roles.md) | Login, sesiones, los tres roles y por qué ninguno puede ejecutar acciones |
| 16 | [Demostración desde cero](16-demostracion-desde-cero.md) | El guion completo de la defensa: qué correr, qué decir y qué contestar |

## Carpeta de auditoría

La carpeta [`auditoria/`](auditoria/README.md) es la **entrega para la materia**:
la auditoría integral del proyecto (objetivo, estado real verificado, qué falla,
qué falta y trazabilidad contra la ERS), el prompt de trabajo para continuarlo
tarea por tarea, y el guion de demostración para la defensa.

## Guía de alertas

La carpeta [`alertas/`](alertas/README.md) responde una pregunta distinta a la `07`: no *cómo* se
crea una regla, sino **cuáles vale la pena tener activas** para no caer en alert fatigue, y por qué.
El catálogo técnico completo (13 reglas listas para pegar en Kibana) vive en
[`../rules/rules.md`](../rules/rules.md).

## Resumen en una frase

> Un ataque genera logs → Elastic los ingiere y dispara alertas → un Agente 1
> determinístico clasifica → un Agente 2 (LLM con fallback) explica en lenguaje
> claro → un analista humano aprueba o descarta cada acción sugerida desde un
> dashboard, y cada decisión queda registrada de forma inmutable.

## El principio rector

**La IA sugiere, el humano decide.** El sistema nunca ejecuta una acción de
contención por su cuenta: siempre hay un analista que aprueba. Los falsos
positivos en seguridad tienen consecuencias reales (cortar un servicio legítimo),
así que la supervisión humana es una *feature*, no una limitación.
