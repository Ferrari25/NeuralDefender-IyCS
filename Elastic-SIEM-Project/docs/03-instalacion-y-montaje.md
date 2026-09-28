# 03 · Instalación y montaje

Pasos para levantar el sistema desde cero. Comandos pensados para Linux con
Docker Compose v2.

## Paso 0 — Preparar el host

```bash
# Elasticsearch necesita un vm.max_map_count alto
sudo sysctl -w vm.max_map_count=262144
```

## Paso 1 — Clonar y configurar

```bash
git clone <repo>
cd Elastic-SIEM-Project

# Configuración (NO commitear .env)
cp .env.example .env
$EDITOR .env            # completar passwords y, opcionalmente, GEMINI_API_KEY

# Dependencias de la capa IA
pip install -r requirements.txt
```

Generar claves de cifrado fuertes para Kibana:

```bash
openssl rand -base64 32   # pegar en KIBANA_ENCRYPTION_KEY
openssl rand -base64 32   # pegar en KIBANA_SAVEDOBJECTS_KEY
```

## Paso 2 — Generar certificados TLS

```bash
chmod +x generate_certs.sh
./generate_certs.sh

# Permisos correctos (Elasticsearch corre como uid 1000)
sudo chown -R 1000:1000 elasticsearch/certs/
sudo chmod 644 elasticsearch/certs/*.crt
sudo chmod 600 elasticsearch/certs/*.key
```

> Los certificados contienen claves privadas: **nunca** los subas a control de
> versiones. Ya están en `.gitignore`.

## Paso 3 — Levantar el stack

```bash
docker compose up -d
```

Esto arranca, en orden y respetando dependencias:

1. `elasticsearch` (espera a estar *healthy* — el healthcheck va autenticado).
2. `setup` (one-shot: fija el password de `kibana_system` vía API y termina).
3. `kibana`, `logstash`, `filebeat`.

> **Diferencia con versiones anteriores:** ya **no** hace falta entrar al
> contenedor a correr `elasticsearch-reset-password` a mano. El servicio `setup`
> lo hace automáticamente a partir de `KIBANA_SYSTEM_PASSWORD`.

## Paso 4 — Verificar

```bash
docker compose ps                  # todos los servicios "running"/"healthy"
docker compose logs setup          # debe decir "kibana_system password set"

# ¿ES responde autenticado?
curl -s -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200/_cluster/health
```

Abrir Kibana en **http://127.0.0.1:5601** y entrar con `elastic` / `ELASTIC_PASSWORD`.

## Paso 5 — Crear la regla de detección en Kibana

La capa SIEM dispara alertas a partir de **reglas de detección**. Para el brute
force, crear una regla de tipo *Threshold* (detalle paso a paso con capturas en
[`brute_force.md`](../brute_force.md)):

- Index pattern: `filebeat-*`
- Query: `tags:authentication_failure OR message:*Failed password*`
- Group by: `host.ip` · Threshold: `3` · Timeframe: `5m`
- MITRE: Credential Access → Brute Force (T1110) · Severidad: High · Risk: 73

> Próximo paso recomendado (detection-as-code): exportar estas reglas a archivos
> versionados en el repo en vez de tenerlas solo en la UI.

## Paso 6 — Listo

El stack queda esperando logs. Seguí con:

- [05 · Simulaciones de ataque](05-simulaciones-de-ataque.md) para generar tráfico malicioso.
- [04 · Uso y ejecución](04-uso-y-ejecucion.md) para correr el análisis IA y el dashboard.

## Apagar

```bash
docker compose --profile simulation down      # baja todo, incluida la simulación
docker compose down -v                         # además borra el volumen de datos de ES
```
