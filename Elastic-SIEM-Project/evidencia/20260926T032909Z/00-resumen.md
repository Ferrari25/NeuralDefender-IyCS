# Evidencia de pruebas — SIEM-IA

Generado: 2026-09-26T03:31:18Z · Rama de trabajo: local

Esta carpeta la produce `./scripts/evidencia.sh`. Son salidas **crudas** de cada
herramienta: no están editadas ni resumidas.

## Objetivo 1 · Pruebas de código estático

| Archivo | Qué prueba |
|---------|------------|
| `01-analisis-estatico.txt` | Las cuatro herramientas corriendo sobre el código: **ruff** (reglas de seguridad, bugs, complejidad), **pylint + pylint-secure-coding-standard**, **bandit** y **ESLint + eslint-plugin-security + no-unsanitized**. |
| `02-la-puerta-atrapa.txt` | **Lo que hace que esto sea una prueba y no una captura de pantalla.** Se inyecta una vulnerabilidad real (`hashlib.md5`) en `siem_lib.py`, se corre el análisis, se muestra que aparece el hallazgo, y se revierte verificando con SHA-256 que el archivo quedó idéntico. |

Las líneas de base están en **cero**: la puerta falla ante cualquier hallazgo nuevo.

## Objetivo 2 · Pruebas de servicio

| Archivo | Qué prueba |
|---------|------------|
| `03-pruebas-de-servicio.txt` | Nueve peticiones HTTP reales contra el panel corriendo, con su respuesta textual y su código. Incluye autenticación, CSRF, validación de entrada y control de acceso por rol en los dos sentidos. |
| `04-suite-y-cobertura.txt` | La suite completa con medición de cobertura. |

Los rechazos (401, 403) **no son fallas**: son el control funcionando. Las dos
peticiones que conviene mirar juntas son la 7 y la 9 — el analista decide y no
audita; el auditor audita y no decide.

## Transversal · No-autonomía

| Archivo | Qué prueba |
|---------|------------|
| `05-no-autonomia.txt` | La certificación de que ningún componente puede ejecutar acciones de contención. Recorre el **AST** de todo el código, no el texto: una llamada disfrazada como `getattr(os, "sys"+"tem")` también se detecta. |

## Números de esta corrida

- Suite: 1053 passed, 7 skipped in 109.02s (0:01:49)
- Cobertura (alcance declarado): 95%
- Verificaciones de no-autonomía: 36
- Hallazgos nuevos de análisis estático: **0** (líneas de base en cero)

## Cómo reproducirlo

```bash
./scripts/check.sh        # la puerta de calidad completa, en pantalla
./scripts/evidencia.sh    # la misma corrida, guardada en una carpeta
```

El detalle de qué se verifica y por qué está en
[`../../docs/12-registro-de-pruebas.md`](../../docs/12-registro-de-pruebas.md).
