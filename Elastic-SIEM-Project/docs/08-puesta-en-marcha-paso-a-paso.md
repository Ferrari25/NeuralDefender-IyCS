# 08 · Puesta en marcha — paso a paso

Runbook completo para levantar **todo** desde cero. Dos caminos:

- **A) Completo (con Docker):** stack Elastic + reglas + simulación + IA + dashboard.
- **B) Demo offline (sin Docker):** solo la capa IA + dashboard, usando datos de muestra.

---

## A) Puesta en marcha completa (con Docker)

### Paso 1 — Preparar el host
```bash
sudo sysctl -w vm.max_map_count=262144      # Elasticsearch lo necesita
```

### Paso 2 — Configurar
```bash
cd Elastic-SIEM-Project
cp .env.example .env
$EDITOR .env                                 # poné passwords fuertes
openssl rand -base64 32                       # → KIBANA_ENCRYPTION_KEY
openssl rand -base64 32                       # → KIBANA_SAVEDOBJECTS_KEY
pip install -r requirements.txt
```
`GEMINI_API_KEY` es opcional (sin ella, el Agente 2 usa el fallback).

### Paso 3 — Certificados TLS
```bash
chmod +x generate_certs.sh && ./generate_certs.sh
sudo chown -R 1000:1000 elasticsearch/certs/
sudo chmod 644 elasticsearch/certs/*.crt
sudo chmod 600 elasticsearch/certs/*.key
```

### Paso 4 — Levantar el stack
```bash
docker compose up -d
docker compose ps                             # esperar a "healthy"/"running"
docker compose logs setup                     # debe decir: "kibana_system password set."
```
> El servicio `setup` fija el password de `kibana_system` solo. No hace falta el reset manual.

### Paso 5 — Verificar Elasticsearch y Kibana
```bash
curl -s -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200/_cluster/health
```
Abrí **http://127.0.0.1:5601** y entrá con `elastic` / `ELASTIC_PASSWORD`.

### Paso 6 — Crear la regla de detección
Seguí [07 · Reglas de detección](07-reglas-de-deteccion.md): data view `filebeat-*`, habilitar
detecciones, y crear la regla *Threshold* de fuerza bruta (T1110).

### Paso 7 — Lanzar la simulación de ataque
```bash
docker compose --profile simulation up -d ssh-target hydra-attacker
bash simulation/run-brute-force.sh
# opcional, los otros ataques:
bash simulation/run-port-scan.sh
bash simulation/run-phishing.sh
```

### Paso 8 — Esperar la alerta
Esperá 5–10 min y verificá en **Security → Alerts** (o por API):
```bash
curl -s -u elastic:$ELASTIC_PASSWORD \
  "http://127.0.0.1:9200/.alerts-security.alerts-default/_count"
```

### Paso 9 — Correr la capa IA
```bash
python3 siem_pipeline.py      # prepare → classifier (Agente 1) → siem_agent (Agente 2)
```

### Paso 10 — Preparar el acceso al panel (una sola vez)

El panel exige autenticación (hallazgo API-01). Dos cosas que hacer una vez:

```bash
# a) Clave de firma de la cookie. SIN ESTO EL PANEL NO ARRANCA.
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
#    → agregar a .env como  SECRET_KEY=<valor>

# b) Crear el primer usuario (la contraseña se pide sin mostrarla)
export PYTHONPATH="$PWD/.devtools"
python3 manage_users.py crear ana --rol analyst
```

Roles disponibles: `analyst` (decide), `viewer` (solo lectura), `auditor` (lee y
verifica la cadena de hash, pero no decide). Detalle en
[`15-autenticacion-y-roles.md`](15-autenticacion-y-roles.md).

> **Ningún rol ejecuta acciones de contención.** El control de acceso decide
> quién decide, no quién ejecuta: el sistema no ejecuta nada.

### Paso 11 — Supervisar en el dashboard
```bash
python3 dashboard.py          # abrir http://127.0.0.1:5000/login
```
Iniciá sesión, aprobá/descartá cada acción sugerida. Las decisiones quedan en
`decisions.jsonl`, **firmadas con el usuario de la sesión** y encadenadas por
hash. Verificá la integridad cuando quieras:

```bash
python3 audit_verify.py       # ✅ Cadena intacta · N registro(s)
```

### Apagar todo
```bash
docker compose --profile simulation down      # baja stack + simulación
docker compose down -v                          # además borra el volumen de datos de ES
```

---

## B) Demo offline (sin Docker, sin Elasticsearch)

Sirve para ver detección + análisis + supervisión de los tres ataques sin levantar el stack. Usa la
última captura `siem_clean.json` (fuerza bruta) y genera los logs de red/web localmente.

```bash
cd Elastic-SIEM-Project
pip install -r requirements.txt

# 1. Generar port scan y phishing como logs detectables
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline

# 2. Clasificar + analizar (Agente 1 + Agente 2 con fallback)
python3 classifier.py && python3 siem_agent.py
#   (o todo junto:)  python3 siem_pipeline.py

# 3. Supervisar
python3 dashboard.py          # http://127.0.0.1:5000  → 3 incidentes
```

> En modo offline, `prepare-for-ia.py` no puede hablar con ES: el pipeline lo informa y continúa con
> los datos existentes (no los pisa). El Agente 2 usa el fallback determinístico.

---

## Resumen de un vistazo

| Quiero… | Comando |
|---------|---------|
| Levantar el stack | `docker compose up -d` |
| Lanzar la simulación | `docker compose --profile simulation up -d && bash simulation/run-brute-force.sh` |
| Correr la capa IA | `python3 siem_pipeline.py` |
| Desplegar las reglas | `./scripts/deploy-rules.sh` (lo hace `start.sh`) |
| Verificar reglas vs. repo | `./scripts/export-rules.sh --check` |
| Crear un usuario | `python3 manage_users.py crear <nombre> --rol analyst` |
| Abrir el dashboard | `python3 dashboard.py` → http://127.0.0.1:5000/login |
| Verificar la auditoría | `python3 audit_verify.py` |
| Demo sin Docker | `bash simulation/run-port-scan.sh --offline && python3 siem_pipeline.py && python3 dashboard.py` |
| Apagar todo | `docker compose --profile simulation down -v` |
