# Auditoría SIEM-IA · carpeta de entrega

Carpeta de **entrega para la materia**. Contiene la auditoría completa del
proyecto y el prompt de trabajo para continuarlo.

> **Por qué acá y no en la raíz.** El pilar 6 del
> [plan de acción](../10-plan-de-accion.md) fija que toda la documentación vive
> en `/docs`. Esta carpeta es un subdirectorio de `docs/` para no romper esa
> regla, y aun así queda separada de la documentación del sistema: son
> artefactos de auditoría y de gestión, no manuales de operación.

| Documento | Qué contiene | Para quién |
|-----------|--------------|------------|
| [`01-auditoria-integral.md`](01-auditoria-integral.md) | Objetivo del proyecto, estado real verificado, qué falla, qué falta, y la matriz de trazabilidad contra la ERS | Cátedra · equipo · quien retome el proyecto |
| [`02-prompt-de-trabajo.md`](02-prompt-de-trabajo.md) | Prompt completo y reutilizable para ir cumpliendo las tareas pendientes de a una | Quien continúe el desarrollo con asistencia de IA |
| [`03-evidencia-para-la-catedra.md`](03-evidencia-para-la-catedra.md) | Guion de demostración: qué comando corre qué, qué tiene que verse, y dónde está cada evidencia | Defensa oral · informe |

## Los tres objetivos de la materia, en una línea cada uno

| Objetivo | Estado | Dónde se demuestra |
|----------|:------:|--------------------|
| **Pruebas de código estático** | ✅ Cumplido | 4 herramientas configuradas, 0 hallazgos, verificado por mutación |
| **Pruebas de servicio** | ✅ Cumplido | 111 pruebas de integración sobre API, auditoría y scripts reales |
| **Desarrollo e implementación en entorno de simulación** | ⚠️ Parcial | El stack corre y el pipeline funciona; faltan login, reglas como código y E2E de navegador |

El detalle de cada uno, con evidencia reproducible, está en
[`01-auditoria-integral.md`](01-auditoria-integral.md) §5.
