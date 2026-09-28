# 02 · Requerimientos

## Hardware mínimo

| Recurso | Mínimo | Recomendado | Por qué |
|---------|--------|-------------|---------|
| RAM | 4 GB libres | 8 GB | Elasticsearch + Kibana son los que más consumen. El heap de ES está fijado en 512 MB (`ES_JAVA_OPTS`). |
| CPU | 2 cores | 4 cores | Logstash usa 2 workers; ES/Kibana arrancan más rápido con más cores. |
| Disco | 5 GB | 20 GB+ | Imágenes Docker (~3 GB) + índices de Elasticsearch que crecen con los logs. |

> El stack Elastic suele necesitar `vm.max_map_count` alto en el host:
> `sudo sysctl -w vm.max_map_count=262144` (persistir en `/etc/sysctl.conf`).

## Software

| Software | Versión | Para qué |
|----------|---------|----------|
| Docker Engine | 20.10+ | Correr el stack. |
| Docker Compose | **v2** (`docker compose`) | Orquestación. La doc usa la sintaxis v2 (sin guion). |
| Python | 3.10+ (probado en 3.13) | Capa IA, scripts y dashboard. |
| `openssl` | cualquiera | Generar los certificados TLS (`generate_certs.sh`). |
| Navegador | cualquiera | Acceder a Kibana y al dashboard de supervisión. |

### Dependencias de Python

Instalar con:

```bash
pip install -r requirements.txt
```

| Paquete | Uso | ¿Obligatorio? |
|---------|-----|---------------|
| `requests` | Hablar con la API REST de Elasticsearch | Sí |
| `python-dotenv` | Leer la configuración de `.env` | Sí |
| `Flask` | Dashboard de supervisión | Sí (para la GUI) |
| `google-genai` | Agente 2 (LLM Gemini) | **No** — hay fallback determinístico |

## Configuración / secretos

El sistema se configura por variables de entorno en `.env` (gitignored). Partir de
la plantilla:

```bash
cp .env.example .env
```

| Variable | Para qué |
|----------|----------|
| `ELASTIC_PASSWORD` | Password del superusuario `elastic`. |
| `KIBANA_SYSTEM_PASSWORD` | Password del usuario `kibana_system` (lo aplica el servicio `setup`). |
| `KIBANA_ENCRYPTION_KEY`, `KIBANA_SAVEDOBJECTS_KEY` | Claves de cifrado de Kibana (32 bytes base64). |
| `ES_HOST` | Endpoint de ES para los scripts (por defecto `http://localhost:9200`). |
| `GEMINI_API_KEY` | Key del LLM. **Opcional**: sin ella, el Agente 2 usa el fallback. |
| `ANALYST_NAME` | Nombre que firma las decisiones en el dashboard. |

> **Seguridad:** nunca commitear `.env`. Generar claves nuevas con
> `openssl rand -base64 32`. Rotar cualquier credencial que haya quedado expuesta.

## Conectividad

- **Modo offline (sin nube):** el sistema funciona completo sin internet usando el
  fallback determinístico del Agente 2. Útil para demos y para entornos con
  requisitos de privacidad (los logs no salen del host).
- **Modo con LLM:** requiere salida HTTPS hacia la API de Gemini. Tener en cuenta
  que esto envía datos de los logs a un tercero (evaluar según la normativa
  aplicable, ej. Ley 25.326 de Protección de Datos Personales).
