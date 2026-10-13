# Pruebas de penetración y alternativas de respuesta

Dos capacidades nuevas para probar el sistema de forma más realista y que la IA
ofrezca más de una salida ante cada problema:

1. **Pentest simulado** (`simulation/pentest.py`): un catálogo de ataques
   realistas —no solo el de manual, sino las variantes evasivas que un atacante
   usa para no ser detectado— que corre por el clasificador **real** y, para
   cada ataque que pasa sin detectarse, propone cómo cerrar el hueco.
2. **Alternativas de remediación** en el playbook: cada acción sugerida ahora
   trae otras formas de lograr lo mismo (otro firewall, otra fuente de logs,
   una contención más o menos drástica), cada una con sus ventajas y desventajas.

Ninguna de las dos ejecuta nada sobre la infraestructura: el pentest genera los
logs que el ataque dejaría, y las alternativas son comandos sugeridos para que
una persona decida. Sigue valiendo el principio rector: **la IA sugiere, el
humano decide** — certificado por `tests/test_no_autonomy.py`.

---

## 1. Pentest simulado

### Cómo correrlo

```bash
# Offline, reproducible, sin Docker ni el stack:
python3 simulation/pentest.py            # reporte en la terminal
python3 simulation/pentest.py --json     # salida JSON (para CI o el panel)

# Mismo pentest + variantes evasivas con herramientas reales (hydra/nmap):
./simulation/run-pentest.sh              # offline (igual que arriba)
./simulation/run-pentest.sh --real       # + ataques reales contra el laboratorio
```

El modo `--real` necesita los contenedores de simulación arriba
(`docker compose --profile simulation up -d ssh-target hydra-attacker`); si no
están, avisa y se queda solo con el offline.

### Qué prueba

Cada escenario reproduce cómo ataca alguien de verdad, dentro de las tres
técnicas que cubre el sistema. La gracia está en las **variantes evasivas**:

| Técnica | Escenarios |
|---------|-----------|
| **T1110 · Fuerza bruta** | clásica ruidosa · low-and-slow (bajo umbral por ventana) · password spraying (muchos usuarios) · botnet distribuida · enumeración de usuarios · fuerza bruta con login exitoso |
| **T1046 · Escaneo** | vertical ruidoso · lento y sigiloso · horizontal rápido · horizontal lento · sondeo de puertos sensibles |
| **T1566 · Phishing** | captura clásica (visita+envío) · cosecha de varias víctimas · envío sin GET previo |

El motor:

1. Genera los eventos que el ataque dejaría en los logs.
2. Los evalúa contra una **emulación de las 14 reglas de Kibana**
   (`simulation/pentest/kibana_simulado.py`) → alertas con la misma forma que
   las reales. La severidad, el umbral, la técnica y la ventana salen de los
   `rules/ndjson/`: si cambiás una regla, el pentest lo ve.
3. Le pasa todo al **clasificador real** (`services/classifier/classifier.py`),
   el mismo código del producto.
4. Compara lo detectado con lo esperado.

### Cómo leer el resultado

| Estado | Significado |
|--------|-------------|
| `✔ DETECTADO` | El ataque generó un incidente que llega al panel |
| `○ HUECO CONOCIDO` | No se detecta, y ya lo sabíamos (trae alternativas) |
| `✘ NO DETECTADO (inesperado)` | **Regresión**: debía detectarse y no |
| `▲ DETECTADO (distinto a lo esperado)` | Detecta algo que no esperábamos — revisar |

El resumen distingue:

- **Ataques detectados**: llegan al panel del analista.
- **Huecos abiertos**: ataques que no llegan al panel (conocidos o sorpresas);
  cada uno trae alternativas de detección. No rompen el build.
- **Regresiones**: resultado distinto al esperado. Esto **sí** rompe el build
  (lo cuida `tests/integration/test_pentest.py`).

### Huecos que encuentra hoy

El pentest documenta tres huecos reales, todos de la misma raíz: el clasificador
cuenta **puertos** distintos por IP, no **hosts**, y algunas alertas de Kibana no
se convierten en incidente visible en el panel.

| Escenario | Qué pasa | Alternativas que propone |
|-----------|----------|--------------------------|
| **PS-03** Horizontal rápido | B2 alerta en Kibana, pero el clasificador no crea incidente | Contar hosts distintos por IP en `detect_port_scans` |
| **PS-04** Horizontal lento | Ni B2 (por la ventana) ni el clasificador lo ven | Contar hosts + ampliar la ventana de B2 |
| **PS-05** Puertos sensibles | B3 alerta, pero 4 puertos < umbral 10 → sin incidente | Que una alerta B3 huérfana genere incidente, o bajar el umbral para puertos críticos |

Cada propuesta dice **qué** cambiar, **dónde** (archivo real) y su **trade-off**.
Son sugerencias para una persona, no cambios automáticos.

### Cómo verificar que el pentest es honesto

Que diga "detectado" no basta: también lo diría si la emulación de Kibana no
mirara nada. `tests/integration/test_pentest.py` lo cuida:

- Toda regla de `rules/ndjson/` tiene que tener su traducción en el simulador
  (si agregás una regla sin predicado, el test falla).
- Los roles de campo (atacante/víctima) del simulador tienen que coincidir con
  los del colector real.
- Los ataques "de manual" (BF-01, PS-01, PH-01) siempre se detectan.
- Todo hueco abierto trae al menos una alternativa, apuntando a un archivo real.

---

## 2. Alternativas de remediación en el playbook

Antes, cada acción sugerida tenía un único comando. Ahora cada acción trae
**alternativas**: otras formas de lograr lo mismo, que el analista elige según
su infraestructura.

Por ejemplo, para "Bloquear la IP atacante":

| Alternativa | Cuándo conviene |
|-------------|-----------------|
| `ufw deny from <ip>` (principal) | Hay UFW instalado |
| `iptables -I INPUT -s <ip> -j DROP` | No hay UFW |
| `nft add rule ...` | Debian 11+/Ubuntu 22.04+/RHEL 9 |
| `firewall-cmd --add-rich-rule ...` | Fedora/RHEL/CentOS |
| `fail2ban-client set sshd banip <ip>` | Se prefiere un bloqueo temporal que expira solo |

Cada alternativa declara sus **ventajas** y **desventajas** (el trade-off
concreto), tiene su propia simulación de qué pasaría, y se aprueba o descarta
por separado desde el panel — y queda en el registro de auditoría como cualquier
otra decisión.

### Dónde se ven

En el dashboard, debajo de cada acción, el enlace **"Otras formas de hacerlo
(N)"** las despliega. Cada una muestra su comando, qué hace, a favor / en contra,
y sus botones Aprobar / Descartar.

### Cómo están construidas (mismas garantías que las acciones)

- Los comandos son **plantillas fijas** de `classifier.py`, armadas con `_cmd`
  sobre datos ya validados (IP/usuario). Nunca salen del LLM ni de un log.
- El Agente 2 (LLM) **no las ve ni las modifica**: solo redacta sobre las
  acciones principales.
- Su catálogo está congelado por `tests/unit/test_classifier_caracterizacion.py`:
  agregar una alternativa es un cambio consciente en el código y en esa lista.

---

## 3. Dónde está cada cosa

```
simulation/
├── pentest.py                      punto de entrada (reporte / JSON)
├── run-pentest.sh                  wrapper: offline (--json) o real (--real)
└── pentest/
    ├── modelo.py                   un evento, visto por cada capa del SIEM
    ├── escenarios.py               el catálogo de ataques realistas
    ├── kibana_simulado.py          emulación de las 14 reglas de rules/ndjson/
    ├── remediacion_deteccion.py    alternativas para cerrar cada hueco
    └── motor.py                    corre cada escenario por el clasificador real

services/classifier/classifier.py   _alternativa() y el catálogo de alternativas de remediación
tests/integration/test_pentest.py   fija el comportamiento del pentest (sin regresiones)
```

Relacionado: `pruebas_de_linters.md` (análisis estático) y
`docs/04-auditoria-pruebas-y-demostracion.md` (estrategia general de pruebas).
