#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# rotar-secretos.sh — Cambia las credenciales que quedaron en el historial de git.
#
# El `.env` estuvo versionado (commit 0ee27c6 y anteriores): todo lo que tenía hay
# que darlo por filtrado. Este script genera valores nuevos y los aplica:
#
#   ELASTIC_PASSWORD        → se cambia en Elasticsearch (usuario `elastic`)
#   KIBANA_SYSTEM_PASSWORD  → se cambia en Elasticsearch (usuario `kibana_system`)
#   KIBANA_ENCRYPTION_KEY   → sesiones de Kibana (cierra las abiertas)
#   SECRET_KEY              → firma de la cookie del panel (cierra las sesiones)
#   SIEM_INTERNAL_TOKEN     → token entre microservicios
#
# y quita USER_ANALISTA / PASSWORD_ANALISTA, que ningún componente usa.
#
# NO rota (hay que hacerlo a mano, ver el final): GEMINI_API_KEY (se revoca en
# Google AI Studio) ni KIBANA_SAVEDOBJECTS_KEY (cambiarla sin el procedimiento
# de rotación de Kibana deja ilegibles los objetos cifrados: conectores y las
# claves con que corren las reglas de detección).
#
# Antes de tocar nada guarda una copia del `.env` (0600) para volver atrás.
#
# Uso:  ./scripts/rotar-secretos.sh          (pide confirmación)
#       ./scripts/rotar-secretos.sh --yes
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -f .env ]] || { echo "[ERROR] No hay .env en $(pwd)."; exit 1; }
if [[ "${1:-}" != "--yes" ]]; then
  echo "⚠️  Esto cambia las contraseñas de Elasticsearch/Kibana y recrea los contenedores"
  echo "    afectados (unos minutos sin servicio). Las sesiones abiertas se cierran."
  read -r -p "¿Seguir? [y/N] " ans
  [[ "$ans" =~ ^[yY]$ ]] || { echo "Cancelado."; exit 0; }
fi

RESPALDO=".env.respaldo-$(date -u +%Y%m%dT%H%M%SZ)"
install -m 600 .env "$RESPALDO"
echo "💾 Copia del .env anterior: $RESPALDO (borrala cuando todo funcione)."

# Todo lo que maneja secretos va en Python: los valores nunca pasan por la línea
# de comandos (visibles en `ps`) ni se imprimen.
python3 - <<'PY'
import base64, json, os, re, secrets, string, urllib.request

env = open(".env", encoding="utf-8").read()

def valor(clave):
    m = re.search(rf"^{clave}=(.*)$", env, re.M)
    if not m:
        raise SystemExit(f"[ERROR] falta {clave} en .env")
    return m.group(1).strip()

alfabeto = string.ascii_letters + string.digits
nuevos = {
    "ELASTIC_PASSWORD": "".join(secrets.choice(alfabeto) for _ in range(32)),
    "KIBANA_SYSTEM_PASSWORD": "".join(secrets.choice(alfabeto) for _ in range(32)),
    "KIBANA_ENCRYPTION_KEY": secrets.token_hex(32),
    "SECRET_KEY": secrets.token_urlsafe(48),
    "SIEM_INTERNAL_TOKEN": secrets.token_urlsafe(48),
}
es = os.getenv("SIEM_ES_URL", "http://127.0.0.1:9200")
actual = valor("ELASTIC_PASSWORD")

def cambiar(usuario, nueva):
    cred = base64.b64encode(f"elastic:{actual}".encode()).decode()
    req = urllib.request.Request(
        f"{es}/_security/user/{usuario}/_password", method="POST",
        data=json.dumps({"password": nueva}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {cred}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise SystemExit(f"[ERROR] {usuario}: HTTP {r.status}")
    print(f"🔑 Contraseña de '{usuario}' cambiada en Elasticsearch.")

# kibana_system primero: si algo falla después, `elastic` sigue con la clave del .env.
cambiar("kibana_system", nuevos["KIBANA_SYSTEM_PASSWORD"])
cambiar("elastic", nuevos["ELASTIC_PASSWORD"])

for clave, nuevo in nuevos.items():
    env, n = re.subn(rf"^{clave}=.*$", lambda _m, c=clave, v=nuevo: f"{c}={v}", env, flags=re.M)
    if n != 1:
        raise SystemExit(f"[ERROR] {clave} aparece {n} veces en .env")
env = re.sub(r"^(USER_ANALISTA|PASSWORD_ANALISTA)=.*\n", "", env, flags=re.M)

fd = os.open(".env.tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(env)
os.replace(".env.tmp", ".env")
print("📝 .env actualizado (0600).")
PY

echo "🔄 Recreando los contenedores que usan los secretos nuevos..."
docker compose up -d --wait

echo "🔎 Verificando..."
python3 - <<'PY'
import base64, re, urllib.request
env = open(".env", encoding="utf-8").read()
pw = re.search(r"^ELASTIC_PASSWORD=(.*)$", env, re.M).group(1).strip()
cred = base64.b64encode(f"elastic:{pw}".encode()).decode()
for nombre, url in (("Elasticsearch", "http://127.0.0.1:9200/_cluster/health"),
                    ("Kibana", "http://127.0.0.1:5601/api/status")):
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {cred}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        print(f"   {nombre}: HTTP {r.status}")
PY
curl -sf -o /dev/null http://127.0.0.1:5000/api/v1/healthz && echo "   Panel: OK"

cat <<'FIN'

✅ Listo. Falta, a mano:
   1. Revocar la GEMINI_API_KEY vieja en https://aistudio.google.com/apikey y, si
      la usás, poner una nueva en .env.
   2. Cambiar tu contraseña del panel: ./scripts/siem.sh usuarios password <usuario>
   3. Si el repo es público o compartido, purgar .env del historial de git
      (git filter-repo) y forzar el push: reescribe el historial.
   4. Borrar la copia .env.respaldo-* cuando confirmes que todo anda.
FIN
