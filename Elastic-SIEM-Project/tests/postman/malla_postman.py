"""Levanta la malla aislada de NeuralDefender para correr la colección de Postman.

Reutiliza la `Malla` de la medición ISO/IEC 25023: los 8 servicios reales (gateway
+ 7 internos) en procesos HTTP locales, con datos y auditoría en un directorio
temporal. Así la colección puede ESCRIBIR (decisiones, documentos, lecciones,
registros de auditoría) sin tocar el registro real, que es inmutable (RF-AUD-03).

El collector lee el Elasticsearch real (solo lectura) para que /v1/snapshots y
/v1/cycles funcionen de punta a punta.

Uso:
    PYTHONPATH=.devtools python3 tests/postman/malla_postman.py --entorno /tmp/entorno.json
Escribe el entorno de Postman (URLs, token, usuarios) y queda corriendo hasta
recibir SIGTERM o Ctrl+C.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "tests" / "calidad"))

import medicion_iso25023 as med  # noqa: E402  pylint: disable=wrong-import-position

ROLES_EXTRA = {"auditor00": "auditor", "observador00": "viewer"}


def _entorno_es() -> None:
    """El collector de la malla consulta el Elasticsearch real del stack (solo lectura)."""
    env = med._leer_env(RAIZ / ".env")  # pylint: disable=protected-access
    os.environ.setdefault("ES_HOST", "http://127.0.0.1:9200")
    os.environ.setdefault("ES_ALLOW_INSECURE_HTTP", "true")
    if env.get("ELASTIC_PASSWORD"):
        os.environ.setdefault("ELASTIC_PASSWORD", env["ELASTIC_PASSWORD"])


class MallaPostman(med.Malla):
    def _preparar_datos(self, clientes: int) -> None:
        super()._preparar_datos(clientes)
        import siem_auth  # pylint: disable=import-outside-toplevel

        hash_ = siem_auth.hash_password(self.PASSWORD)
        ahora = datetime.now(timezone.utc).isoformat()
        with siem_auth.modificar_usuarios() as usuarios:
            for nombre, rol in ROLES_EXTRA.items():
                usuarios[nombre] = siem_auth.Usuario(username=nombre, rol=rol, password_hash=hash_,
                                                     activo=True, creado=ahora)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--entorno", required=True, help="archivo JSON de entorno de Postman a escribir")
    args = ap.parse_args()
    destino = Path(args.entorno).resolve()

    _entorno_es()
    malla = MallaPostman(clientes=1)
    valores = {
        **{f"url_{k}": v for k, v in malla.urls.items()},
        "token": malla.token, "password": malla.PASSWORD,
        "analista": "analista00", "dado_de_baja": "dadobaja00",
        "auditor": "auditor00", "observador": "observador00",
        "victima": "victima00x00",
    }
    destino.write_text(json.dumps({
        "name": "NeuralDefender · malla aislada",
        "values": [{"key": k, "value": v, "enabled": True,
                    **({"type": "secret"} if k in ("token", "password") else {})}
                   for k, v in valores.items()],
    }, indent=2), encoding="utf-8")
    print(f"malla lista · gateway {malla.urls['gateway']} · entorno en {destino}", flush=True)

    alto = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: alto.set())
    try:
        alto.wait()
    except KeyboardInterrupt:
        pass
    finally:
        malla.cerrar()
        destino.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
