# nicotito.md — Levantar SIEM-IA desde cero en un equipo nuevo

Guía completa, de punta a punta, para clonar este repositorio en una máquina
que nunca lo vio y dejarlo corriendo igual que en el original: stack Elastic,
14 reglas de detección, capa de IA (con o sin Gemini) y el dashboard de
supervisión con autenticación.

No asume que leíste ningún otro documento del proyecto, pero todos los
`docs/0N-*.md` siguen siendo la referencia técnica detallada de cada tema si
hace falta profundizar.

---

## 1. Qué necesita tener instalado el equipo nuevo

| Herramienta | Para qué | Cómo verificar |
|---|---|---|
| **Docker** + **Docker Compose v2** | Todo el stack Elastic (Elasticsearch, Kibana, Logstash, Filebeat) y los contenedores de simulación de ataque | `docker --version` / `docker compose version` |
| **Python 3.11+** | Los scripts del pipeline (Agente 1, Agente 2), el dashboard Flask, los tests | `python3 --version` |
| **Node.js 18+** (opcional) | Solo para correr ESLint sobre `static/app.js` (análisis estático del frontend) | `node --version` |
| **openssl** | Generar contraseñas/claves aleatorias para `.env` | suele venir en el sistema |
| **git** | Clonar el repo y versionar los cambios | `git --version` |

En Linux, Elasticsearch además necesita:

```bash
sudo sysctl -w vm.max_map_count=262144
```

(si no lo hacés, Elasticsearch no arranca — lo pide él mismo en sus logs).

**No hace falta** tener Python "en el sistema" con permisos de instalar
paquetes globales: en Debian/Ubuntu modernos, `pip install` a secas falla
porque el intérprete está marcado como "externally managed" (PEP 668). Todo
este proyecto instala sus dependencias en una carpeta local del propio
proyecto (`.devtools/`), sin tocar nada del sistema — ver paso 4.

---

## 2. Clonar el repositorio

```bash
git clone https://github.com/Ferrari25/NeuralDefender-IyCS.git
cd NeuralDefender-IyCS/Elastic-SIEM-Project
```

Todo lo que sigue se corre parado en `Elastic-SIEM-Project/`.

---

## 3. Configurar `.env` (el paso que nadie puede saltear)

El repositorio **nunca** trae un `.env` real (está en `.gitignore` a
propósito: son credenciales). Trae `.env.example`, que es la plantilla:

```bash
cp .env.example .env
```

Abrí `.env` y completá cada valor. Ninguno de estos tiene un default seguro
a propósito — un default compartido en el código fuente no es un secreto.

### 3.1 Contraseñas y claves de Elastic/Kibana

```bash
# Elegí vos mismo una contraseña fuerte para estas dos, o generalas:
openssl rand -base64 24     # → ELASTIC_PASSWORD
openssl rand -base64 24     # → KIBANA_SYSTEM_PASSWORD

# Estas dos SÍ tienen que ser exactamente así de largas (Kibana las valida):
openssl rand -base64 32     # → KIBANA_ENCRYPTION_KEY
openssl rand -base64 32     # → KIBANA_SAVEDOBJECTS_KEY
```

Pegá cada resultado en su variable dentro de `.env`.

### 3.2 Clave de sesión del dashboard (`SECRET_KEY`)

El panel de supervisión **no arranca** sin esto (es a propósito: firma la
cookie de sesión, y un valor por defecto compartido entre instalaciones sería
un agujero de seguridad, no una comodidad).

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Pegá el resultado en `SECRET_KEY=` dentro de `.env`.

### 3.3 La API de Gemini (Agente 2 con IA)

El sistema **funciona completo sin esto** — el Agente 2 tiene un análisis
determinístico de respaldo (sin IA) que siempre está disponible. Gemini es
opcional, para tener análisis en lenguaje natural generados por un LLM en vez
del análisis por plantillas.

**Cómo conseguir una key gratis:**

1. Entrá a **https://aistudio.google.com/apikey** con una cuenta de Google.
2. "Create API key" → elegí o creá un proyecto de Google Cloud.
3. Copiá la key (empieza con `AI...` o similar).

**Dos variables, no una** — esto es a propósito, para poder guardar la key
sin gastar tokens hasta decidir usarla de verdad:

```bash
GEMINI_API_KEY=la-key-que-copiaste
SIEM_USE_LLM=false     # ← el interruptor real
```

Con `SIEM_USE_LLM=false` (el default), el Agente 2 usa el análisis
determinístico SIEMPRE, aunque la key esté puesta y sea válida. Para que
consuma la API de Gemini de verdad:

```bash
SIEM_USE_LLM=true
```

Modelo usado: `gemini-flash-lite-latest` (el alias más barato de la familia
Flash; Google lo reapunta solo cuando cambia de versión, así nunca queda fijo
a una versión discontinuada). Si no hay key, si `SIEM_USE_LLM` no es `true`,
o si la API falla (cuota, red), cada incidente cae solo al análisis
determinístico — nunca se corta el pipeline por esto.

**Nunca compartas ni subas a git tu `GEMINI_API_KEY` real** (ver §8).

### 3.4 El resto de `.env`

Los demás valores (`STACK_VERSION`, `CLUSTER_NAME`, `MEM_LIMIT`, `ES_HOST`,
`SIEM_USERS_FILE`, `SIEM_TLS`) ya vienen con valores razonables en
`.env.example` — no hace falta tocarlos para un uso normal. `SIEM_TLS=true`
solo si vas a servir el dashboard por HTTPS de verdad.

---

## 4. Instalar las dependencias de Python

```bash
python3 -m pip install --target=.devtools -r requirements.txt
export PYTHONPATH="$PWD/.devtools"
```

Esto instala Flask, el cliente de Gemini, Argon2, etc. **dentro de la carpeta
del proyecto**, no en el sistema. `export PYTHONPATH` hace falta en **cada
terminal nueva** antes de correr cualquier script Python del proyecto —
conviene agregarlo a tu `.bashrc`/`.zshrc` apuntando a esta carpeta, o
recordar exportarlo cada vez.

Si además vas a correr los tests o el análisis estático (ver §7), instalá
también las dependencias de desarrollo, en el mismo comando para que
`.devtools/bin/` termine con todos los ejecutables juntos:

```bash
python3 -m pip install --target=.devtools -r requirements.txt -r requirements-dev.txt
```

> **Importante:** si instalás con `pip install --target=.devtools` en
> llamadas SEPARADAS (una para cada paquete), cada llamada nueva puede pisar
> `.devtools/bin/` y dejarlo solo con los ejecutables de esa última llamada.
> Instalá siempre TODO junto, en un solo comando con `-r archivo.txt`.

### 4.1 Dependencias de Node (opcional, solo para ESLint)

```bash
npm install
```

---

## 5. Levantar el stack

### Opción A — con Docker (el flujo real, recomendado)

```bash
./scripts/start.sh
```

Este único comando:
1. Levanta Elasticsearch, Kibana, Logstash y Filebeat (`docker compose up -d`).
2. Espera a que Elasticsearch esté `healthy`.
3. Espera a que el servicio `setup` termine de fijar el password de
   `kibana_system`.
4. Espera a que Kibana responda `HTTP 200`.
5. Despliega las **14 reglas de detección** versionadas en `rules/ndjson/`
   (`./scripts/deploy-rules.sh`) — quedan **habilitadas** por defecto.

No devuelve la consola hasta que todo esté listo. Al final imprime la URL de
Kibana con las credenciales de `.env` y los próximos pasos.

Variantes:

```bash
./scripts/start.sh --simulation          # además levanta ssh-target + hydra-attacker
SIEM_SKIP_RULES=true ./scripts/start.sh  # levanta el stack sin tocar las reglas
```

Verificar a mano si hace falta:

```bash
curl -s -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200/_cluster/health
```

Abrí **http://127.0.0.1:5601** y entrá con usuario `elastic` y el
`ELASTIC_PASSWORD` que pusiste en `.env`.

### Opción B — demo sin Docker (sin Elasticsearch)

Sirve para ver detección + análisis + dashboard sin levantar nada de
infraestructura, usando datos sintéticos generados localmente:

```bash
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
python3 src/siem_pipeline.py
python3 src/dashboard.py
```

`src/prepare-for-ia.py` detecta que no hay Elasticsearch, no falla el pipeline, y
sigue con lo que ya haya en `network_logs/`.

---

## 6. Crear el primer usuario del panel

El dashboard **exige login** — sin usuarios, nadie entra, ni siquiera en modo
lectura:

```bash
export PYTHONPATH="$PWD/.devtools"
python3 src/manage_users.py crear ana --rol analyst
```

Te pide la contraseña **dos veces** (para confirmar) de forma interactiva —
no se muestra en pantalla ni se pasa por línea de comandos. Mínimo 12
caracteres. Roles disponibles:

| Rol | Puede |
|---|---|
| `analyst` | Ver incidentes y aprobar/descartar acciones sugeridas |
| `viewer` | Solo ver, no decide nada |
| `auditor` | Ver + verificar la cadena de hash del registro de auditoría, no decide |

Ningún rol ejecuta acciones de contención — el sistema **sugiere**, un humano
**decide**, y nada se ejecuta automáticamente (ver `tests/test_no_autonomy.py`).

---

## 7. Generar un ataque y correr la capa de IA

```bash
# SSH brute force (necesita el stack + los contenedores de simulación):
docker compose --profile simulation up -d ssh-target hydra-attacker
bash simulation/run-brute-force.sh

# Port scan y phishing — con --offline, que solo genera los logs: es el
# camino confiable (el modo "live" de run-phishing.sh depende de un
# contenedor, simulated-user, que este docker-compose.yml no define):
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline

# Clasificar + analizar (Agente 1 determinístico + Agente 2, con o sin Gemini
# según SIEM_USE_LLM en .env):
python3 src/siem_pipeline.py
```

**Qué esperar ver.** El pipeline imprime algo como:

```
  Incidentes detectados: 3
   • INC-AUTH-<ip>-...: ssh_brute_force [ALTA] — N eventos
   • INC-SCAN-<ip>-...: port_scan [ALTA] — 26 eventos
   • INC-PHISH-<ip>-...: credential_harvesting [ALTA] — 1 eventos
```

Con las reglas ya desplegadas (paso 5), Kibana tarda hasta su intervalo de
ejecución (`interval`, normalmente algunos minutos) en generar la alerta
real — si `src/siem_pipeline.py` corre antes de que la alerta exista, el
Agente 1 igual detecta el patrón por su cuenta desde los logs crudos (el
sistema no depende del SIEM para funcionar; en la columna "Regla disparada"
del panel vas a ver "Sin regla SIEM (detección propia)"). Esperá un par de
minutos y volvé a correr `python3 src/siem_pipeline.py` para ver la alerta
real de Kibana reflejada ahí en su lugar.

---

## 8. Abrir el dashboard

```bash
python3 src/dashboard.py
```

Abrí **http://127.0.0.1:5000/login**, entrá con el usuario que creaste en el
paso 6. Cada aprobación/descarte queda en `data/decisions.jsonl` (append-only,
encadenado por hash, firmado con el usuario de la sesión — nunca con una
variable de entorno).

Verificar en cualquier momento que el registro de auditoría no fue alterado:

```bash
python3 src/audit_verify.py
```

---

## 9. Verificar que nada se perdió entre el SIEM y el panel

Herramienta de este mismo proyecto para demostrar que todo lo que disparó una
alerta real en Elasticsearch tiene su incidente correspondiente en el panel,
con la regla más grave que corresponde (ver `src/verify-cobertura.py` para el
detalle de qué compara exactamente):

```bash
export PYTHONPATH="$PWD/.devtools"
python3 src/verify-cobertura.py
```

Sale `✅` si todo está cubierto, o lista exactamente qué (IP, técnica) disparó
en Kibana y no aparece todavía en `data/siem_incidents.json` (normalmente porque
falta volver a correr `python3 src/siem_pipeline.py` después de la última alerta).

---

## 10. Demostrar los linters, el SAST y las pruebas de servicio

Todo esto requiere haber instalado `requirements-dev.txt` (paso 4):

```bash
export PYTHONPATH="$PWD/.devtools"

./scripts/pruebas_de_codigo_estatico.sh   # linters + SAST (ruff, eslint, pylint, bandit)
./scripts/pruebas_de_servicio.sh          # estático (AST) + unitarias + servicio + cobertura
./scripts/pruebas_completas.sh            # los dos anteriores, uno atrás del otro
```

Cada script imprime cada etapa con `✔ OK`/`✘ FALLA`/`BASE` agrupada por
categoría con su propio color, y termina en `✅ Todo en verde.` o
`❌ N etapa(s) con fallos.` — es la misma puerta que correría un CI.

Qué es cada cosa, en el vocabulario del propio proyecto
(`docs/04-auditoria-pruebas-y-demostracion.md`):

- **Pruebas de código estático (SAST):** no ejecutan nada, leen el código.
  `ruff` (estilo/imports), `pylint` + `pylint-secure-coding-standard`
  (calidad + reglas de seguridad, umbral ≥ 9.0/10), `bandit` (vulnerabilidades
  conocidas en Python: `subprocess`, hashes débiles, etc.), `eslint` +
  `eslint-plugin-security` (mismo criterio para `static/app.js`).
- **Pruebas de servicio** (carpeta `tests/integration/`): ejercitan el
  contrato real de un componente — la API HTTP del dashboard, `deploy-rules.sh`
  contra un Kibana simulado, `reset.sh` contra un sandbox real, la
  autenticación completa (login, roles, CSRF, fuerza bruta). No son mocks de
  la lógica interna: prueban el servicio como lo usaría alguien de afuera.
  Se corren solas con:
  ```bash
  python3 -m pytest tests/integration -q
  ```
- **Pruebas unitarias** (`tests/unit/`): una función o módulo aislado.
  ```bash
  python3 -m pytest tests/unit -q
  ```

Para mostrar el resultado de una corrida real (no la promesa de que pasaría):
correr `./scripts/pruebas_completas.sh` y compartir esa salida, o pegar el
resumen que imprime al final cada bloque de `pytest`.

---

## 11. Apagar / reiniciar de cero

```bash
# Apagar todo (conserva los datos de Elasticsearch):
docker compose --profile simulation down

# Apagar Y borrar los datos + reiniciar limpio (archiva la auditoría, nunca la borra):
./scripts/reset.sh --yes
./scripts/start.sh
```

`reset.sh` **nunca** borra `data/decisions.jsonl`/`data/analysis_history.jsonl`: los
archiva en `audit/archive/<timestamp>/` con permisos de solo lectura.

---

## 12. Recordatorio de seguridad para quien clone esto

- **Nunca** subas tu `.env` real a git. Ya está en `.gitignore`, pero
  revisalo antes de cualquier `git add -A` en un repo nuevo.
- Lo mismo para `users.json` (hashes de contraseñas) y
  `elasticsearch/certs/` (claves TLS privadas) — también gitignored.
- Si en algún momento un `.env`, clave privada o `users.json` real llegó a
  quedar en un commit ya subido a un repo público: el archivo se puede borrar
  de un commit nuevo, pero **el valor sigue comprometido** — la única
  corrección real es **rotarlo** (generar uno nuevo, como en el paso 3) y
  recién después, si hace falta, reescribir el historial de git.

---

## 13. Resumen de un vistazo

| Quiero… | Comando |
|---|---|
| Configurar secretos | `cp .env.example .env` y completar (ver §3) |
| Instalar dependencias Python | `python3 -m pip install --target=.devtools -r requirements.txt -r requirements-dev.txt` |
| Levantar todo (stack + reglas) | `./scripts/start.sh` |
| Crear el primer usuario del panel | `python3 src/manage_users.py crear <nombre> --rol analyst` |
| Lanzar un ataque SSH | `docker compose --profile simulation up -d ssh-target hydra-attacker && bash simulation/run-brute-force.sh` |
| Correr la capa de IA | `python3 src/siem_pipeline.py` |
| Abrir el dashboard | `python3 src/dashboard.py` → http://127.0.0.1:5000/login |
| Verificar la auditoría | `python3 src/audit_verify.py` |
| Verificar cobertura SIEM ↔ panel | `python3 src/verify-cobertura.py` |
| Demostrar linters + SAST + pruebas | `./scripts/pruebas_completas.sh` |
| Reset completo | `./scripts/reset.sh --yes && ./scripts/start.sh` |
| Apagar todo | `docker compose --profile simulation down` |
