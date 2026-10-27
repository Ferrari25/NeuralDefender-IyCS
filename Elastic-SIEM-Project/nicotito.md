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
| **Python 3.10+** | Las pruebas, los linters y los scripts auxiliares (el sistema en sí corre en contenedores) | `python3 --version` |
| **Node.js 18+** (opcional) | Solo para correr ESLint sobre `services/gateway/static/app.js` (análisis estático del frontend) | `node --version` |
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

> ⚠️ **Este repositorio sí trae un `.env` versionado**, por decisión explícita
> del dueño (ver el comentario en `.gitignore`). Esos valores son compartidos
> con cualquiera que tenga acceso al repo: en un equipo nuevo, **generá valores
> propios** con los pasos de abajo antes de exponer nada.

La plantilla es `.env.example`. Si tu clon no trae `.env`, partí de ella:

```bash
cp .env.example .env
```

Abrí `.env` y completá (o reemplazá) cada valor. Ninguno de estos tiene un default seguro
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

Los demás valores (`STACK_VERSION`, `CLUSTER_NAME`, `ES_HOST`,
`SIEM_USERS_FILE`, `SIEM_TLS`, los umbrales `SIEM_UMBRAL_*`, `SIEM_VENTANA`,
`SIEM_RETENCION_DIAS` y los `SIEM_RESPALDO_*`) ya vienen con valores razonables en
`.env.example` — no hace falta tocarlos para un uso normal.

**Una sola excepción: `SIEM_RESPALDO_CLAVE`.** `start.sh` la genera si falta, pero
hay que copiarla a un gestor de contraseñas **fuera de este equipo**: sin ella
ningún respaldo se puede descifrar.

`SIEM_INTERNAL_TOKEN` es el token con el que se autentican entre sí los
microservicios de la capa IA. Ninguno arranca sin él, pero no hace falta
generarlo a mano: `./scripts/start.sh` lo agrega a `.env` si falta. `SIEM_TLS=true`
solo si vas a servir el dashboard por HTTPS de verdad.

---

## 4. Instalar las dependencias de Python (solo para pruebas y linters)

**Para correr el sistema no hace falta este paso.** La capa IA son ocho
microservicios en Docker, y cada imagen trae sus propias dependencias. Esto es
solo para correr la suite de pruebas y el análisis estático en el host:

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
python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt
```

> **Importante:** `pip install --target` NO toca `.devtools/bin/` si ya
> existe (solo avisa *"Target directory … already exists"*): los paquetes se
> instalan pero sus ejecutables (`ruff`, `pylint`, `pytest`…) no. Y con
> `--upgrade` hace lo contrario: reemplaza `bin/` entero con los de esa
> llamada. Por eso: instalá siempre TODO junto, en un solo comando con los dos
> `-r` y `--upgrade`.

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

### Opción B — demo sin el stack Elastic

Sirve para ver detección + análisis + dashboard sin levantar Elasticsearch,
Kibana ni Logstash. Solo arrancan los microservicios de la capa IA, con datos
sintéticos generados localmente:

```bash
mkdir -p data/auth data/audit data/collector data/pipeline data/knowledge   # (start.sh lo hace solo)
docker compose up -d --build gateway     # trae las dependencias del gateway
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline
./scripts/siem.sh pipeline
```

El collector detecta que no hay Elasticsearch y responde 503. El pipeline lo
informa (`collector sin_captura`) y sigue con lo que haya en `network_logs/`.

---

## 6. Crear el primer usuario del panel

El dashboard **exige login** — sin usuarios, nadie entra, ni siquiera en modo
lectura:

```bash
./scripts/siem.sh usuarios crear ana --rol analyst
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
./scripts/siem.sh pipeline
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
real — si `services/pipeline/siem_pipeline.py` corre antes de que la alerta exista, el
Agente 1 igual detecta el patrón por su cuenta desde los logs crudos (el
sistema no depende del SIEM para funcionar; en la columna "Regla disparada"
del panel vas a ver "Sin regla SIEM (detección propia)"). Esperá un par de
minutos y volvé a correr `./scripts/siem.sh pipeline` para ver la alerta
real de Kibana reflejada ahí en su lugar.

---

## 8. Abrir el dashboard

`./scripts/start.sh` ya lo dejó corriendo (servicio `gateway`). Si lo
levantaste por partes:

```bash
docker compose up -d gateway
```

Abrí **http://127.0.0.1:5000/login**, entrá con el usuario que creaste en el
paso 6. Cada aprobación/descarte queda en `data/audit/decisions.jsonl` (append-only,
encadenado por hash, firmado con el usuario de la sesión — nunca con una
variable de entorno).

Cada decisión además le enseña algo al Agente 2 (el "Gem"): se guarda como
caso en `data/knowledge/casos.json`, y cuando un patrón se repite el agente
propone una lección que aparece en la tarjeta **Memoria del agente** del panel
para que la apruebes o rechaces. Cómo funciona y dónde ver todo lo que guarda:
[`docs/05-gem-memoria-del-agente.md`](docs/05-gem-memoria-del-agente.md).

Verificar en cualquier momento que el registro de auditoría no fue alterado:

```bash
./scripts/siem.sh auditoria
```

---

## 9. Verificar que nada se perdió entre el SIEM y el panel

Herramienta de este mismo proyecto para demostrar que todo lo que disparó una
alerta real en Elasticsearch tiene su incidente correspondiente en el panel,
con la regla más grave que corresponde (ver `services/collector/verify-cobertura.py` para el
detalle de qué compara exactamente):

```bash
./scripts/siem.sh cobertura
```

Sale `✅` si todo está cubierto, o lista exactamente qué (IP, técnica) disparó
en Kibana y no aparece todavía en `data/pipeline/siem_incidents.json` (normalmente porque
falta volver a correr `./scripts/siem.sh pipeline` después de la última alerta).

---

## 10. Demostrar los linters, el SAST y las pruebas de servicio

Todo esto requiere haber instalado `requirements-dev.txt` (paso 4):

```bash
export PYTHONPATH="$PWD/.devtools"

./scripts/pruebas_de_codigo_estatico.sh   # linters + SAST (ruff, eslint, pylint, bandit)
./scripts/pruebas_de_servicio.sh          # estático (AST) + unitarias + servicio + cobertura
./scripts/pruebas_completas.sh            # los dos anteriores, uno atrás del otro
./scripts/pruebas_de_verificacion.sh      # 80/20: demuestra que las pruebas detectan errores
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
  `eslint-plugin-security` (mismo criterio para `services/gateway/static/app.js`).
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

**¿Cómo sé que esas pruebas detectan algo?** `./scripts/pruebas_de_verificacion.sh`
corre 25 casos sobre una copia temporal del proyecto: 20 con el código sano
(80 %, tienen que pasar) y 5 con un defecto inyectado a propósito (20 %, tienen
que fallar): una shell con `shell=True`, un XSS, un `os.system`, un permiso
borrado y una lección sin aprobar. Tiene que terminar en `✅ Verificación
correcta`. El repositorio real no se toca.

Dónde seguir leyendo:
- qué hace cada linter y cómo verlos en VS Code: [`pruebas_de_linters.md`](pruebas_de_linters.md);
- qué prueba cada archivo de `tests/`: [`docs/04` §Registro de pruebas](docs/04-auditoria-pruebas-y-demostracion.md#registro-de-pruebas);
- el pentest simulado: [`pruebas_de_penetracion.md`](pruebas_de_penetracion.md).

---

## 11. Apagar / reiniciar de cero

```bash
# Apagar todo (conserva los datos de Elasticsearch):
docker compose --profile simulation down

# Apagar Y borrar los datos + reiniciar limpio (archiva la auditoría, nunca la borra):
./scripts/reset.sh --yes
./scripts/start.sh
```

`reset.sh` **nunca** borra `data/audit/decisions.jsonl`/`data/audit/analysis_history.jsonl`: los
archiva en `data/audit/archivo/<timestamp>/` con permisos de solo lectura.

---

## 12. Recordatorio de seguridad para quien clone esto

- **En este repositorio, `.env`, `data/auth/users.json` (hashes de
  contraseñas) y `elasticsearch/certs/` (claves TLS privadas) están
  versionados** por decisión del dueño — el `.gitignore` lo dice
  explícitamente. En un repo propio o público, sacalos del control de
  versiones y agregalos a `.gitignore` antes de cualquier `git add -A`.
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
| Instalar dependencias Python | `python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt` |
| Levantar todo (stack + reglas) | `./scripts/start.sh` |
| Crear el primer usuario del panel | `./scripts/siem.sh usuarios crear <nombre> --rol analyst` |
| Lanzar un ataque SSH | `docker compose --profile simulation up -d ssh-target hydra-attacker && bash simulation/run-brute-force.sh` |
| Correr la capa de IA | `./scripts/siem.sh pipeline` |
| Abrir el dashboard | `docker compose up -d gateway` → http://127.0.0.1:5000/login |
| Verificar la auditoría | `./scripts/siem.sh auditoria` |
| Verificar cobertura SIEM ↔ panel | `./scripts/siem.sh cobertura` |
| Demostrar linters + SAST + pruebas | `./scripts/pruebas_completas.sh` |
| Demostrar que las pruebas detectan errores (80/20) | `./scripts/pruebas_de_verificacion.sh` |
| Ver lo que aprendió el agente (Gem) | Panel → tarjeta **Memoria del agente**, o `data/knowledge/*.json` (ver `docs/05`) |
| Reset completo | `./scripts/reset.sh --yes && ./scripts/start.sh` |
| Apagar todo | `docker compose --profile simulation down` |
