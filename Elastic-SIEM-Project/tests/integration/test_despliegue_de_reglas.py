"""`deploy-rules.sh` y `export-rules.sh` contra un Kibana simulado (**F-02**).

Las pruebas de `tests/unit/test_reglas_como_codigo.py` verifican los archivos;
estas verifican **el comportamiento de los scripts**, que es donde está el
requisito que importa: que desplegar dos veces no duplique reglas.

Se levanta un servidor HTTP mínimo que imita los tres endpoints de Kibana que
usan los scripts. Probar contra el Kibana real ataría la suite a tener el stack
levantado, y además no permitiría provocar los casos de error.

> Como el resto del proyecto: esto despliega **reglas de detección**, no acciones
> sobre la infraestructura. Ningún script toca un host.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEPLOY = PROJECT_ROOT / "scripts" / "deploy-rules.sh"
EXPORT = PROJECT_ROOT / "scripts" / "export-rules.sh"


class KibanaSimulado:
    """Servidor mínimo que imita los endpoints de reglas de Elastic Security.

    Guarda las reglas en un diccionario por `rule_id`, que es exactamente la
    semántica de Kibana: importar una regla con un `rule_id` existente la
    reemplaza en vez de agregar otra. Si el script perdiera el `rule_id` o
    dejara de usar `overwrite`, acá se vería como duplicación o como error.
    """

    def __init__(self):
        self.reglas: dict[str, dict] = {}
        self.peticiones: list[tuple[str, str]] = []
        self.credenciales_vistas: list[str] = []
        self._servidor = HTTPServer(("127.0.0.1", 0), self._manejador())
        self._hilo = threading.Thread(target=self._servidor.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, puerto = self._servidor.server_address
        return f"http://{host}:{puerto}"

    def arrancar(self):
        self._hilo.start()
        return self

    def parar(self):
        self._servidor.shutdown()
        self._servidor.server_close()

    def _manejador(servidor_externo):  # noqa: N805 — closure sobre la instancia
        kibana = servidor_externo

        class Manejador(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass  # silencio: la salida del test ya es bastante

            def _responder(self, codigo: int, cuerpo: dict):
                datos = json.dumps(cuerpo).encode()
                self.send_response(codigo)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(datos)))
                self.end_headers()
                self.wfile.write(datos)

            def _registrar(self):
                kibana.peticiones.append((self.command, self.path.split("?")[0]))
                if self.headers.get("Authorization"):
                    kibana.credenciales_vistas.append(self.headers["Authorization"])

            def do_GET(self):  # noqa: N802
                self._registrar()
                if self.path.startswith("/api/status"):
                    return self._responder(200, {"status": {"overall": {"level": "available"}}})
                if self.path.startswith("/api/detection_engine/rules/_find"):
                    return self._responder(200, {
                        "total": len(kibana.reglas),
                        "data": list(kibana.reglas.values()),
                    })
                return self._responder(404, {"error": "no encontrado"})

            def do_POST(self):  # noqa: N802
                self._registrar()
                largo = int(self.headers.get("Content-Length", 0))
                cuerpo = self.rfile.read(largo)

                if self.path.startswith("/api/detection_engine/rules/_import"):
                    # El cuerpo es multipart; alcanza con extraer las líneas JSON.
                    importadas = 0
                    for linea in cuerpo.decode("utf-8", "replace").splitlines():
                        linea = linea.strip()
                        if not linea.startswith("{"):
                            continue
                        try:
                            regla = json.loads(linea)
                        except json.JSONDecodeError:
                            continue
                        if "rule_id" not in regla:
                            continue
                        # Semántica de Kibana: la identidad es el rule_id.
                        regla.setdefault("enabled", False)
                        kibana.reglas[regla["rule_id"]] = regla
                        importadas += 1
                    return self._responder(200, {
                        "success": True, "success_count": importadas,
                        "rules_count": importadas, "errors": [],
                    })

                if self.path.startswith("/api/detection_engine/rules/_export"):
                    lineas = [json.dumps(r) for r in kibana.reglas.values()]
                    lineas.append(json.dumps({"exported_count": len(kibana.reglas)}))
                    datos = ("\n".join(lineas) + "\n").encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/ndjson")
                    self.send_header("Content-Length", str(len(datos)))
                    self.end_headers()
                    self.wfile.write(datos)
                    return None

                return self._responder(404, {"error": "no encontrado"})

            def do_PATCH(self):  # noqa: N802
                self._registrar()
                largo = int(self.headers.get("Content-Length", 0))
                datos = json.loads(self.rfile.read(largo) or b"{}")
                regla = kibana.reglas.get(datos.get("rule_id"))
                if regla is None:
                    return self._responder(404, {"error": "regla inexistente"})
                regla.update({k: v for k, v in datos.items() if k != "rule_id"})
                return self._responder(200, regla)

        return Manejador


@pytest.fixture
def kibana():
    servidor = KibanaSimulado().arrancar()
    yield servidor
    servidor.parar()


@pytest.fixture
def proyecto(tmp_path):
    """Copia del proyecto con los scripts, las reglas reales y un .env propio."""
    (tmp_path / "scripts").mkdir()
    for script in ("deploy-rules.sh", "export-rules.sh"):
        destino = tmp_path / "scripts" / script
        destino.write_text((PROJECT_ROOT / "scripts" / script).read_text(encoding="utf-8"),
                           encoding="utf-8")
        destino.chmod(0o755)

    reglas = tmp_path / "rules" / "ndjson"
    reglas.mkdir(parents=True)
    for archivo in (PROJECT_ROOT / "rules" / "ndjson").glob("*.ndjson"):
        (reglas / archivo.name).write_text(archivo.read_text(encoding="utf-8"),
                                           encoding="utf-8")

    (tmp_path / ".env").write_text(
        "ELASTIC_PASSWORD=contrasena-de-prueba\n", encoding="utf-8")
    return tmp_path


def _correr(script: str, proyecto: Path, kibana_url: str, *args: str):
    entorno = {**os.environ, "KIBANA_URL": kibana_url}
    return subprocess.run(
        ["bash", f"scripts/{script}", *args],
        cwd=proyecto, capture_output=True, text=True, timeout=180,
        env=entorno, check=False)


# ─── Despliegue ──────────────────────────────────────────────────────────────

def test_el_despliegue_sube_las_catorce_reglas(proyecto, kibana):
    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode == 0, resultado.stderr
    assert len(kibana.reglas) == 14
    assert "14 regla(s) importada(s)" in resultado.stdout


def test_el_despliegue_habilita_las_reglas(proyecto, kibana):
    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert all(r["enabled"] for r in kibana.reglas.values())


def test_con_disabled_quedan_apagadas(proyecto, kibana):
    """`--disabled` tiene que APAGARLAS, no solo saltear el paso de habilitar.

    Lo encontró esta prueba: los archivos versionados traen `"enabled": true`
    (así salen de Kibana, donde están activas), así que el import las dejaba
    andando igual y el flag no hacía lo que prometía.
    """
    _correr("deploy-rules.sh", proyecto, kibana.url, "--disabled")

    assert len(kibana.reglas) == 14
    assert not any(r["enabled"] for r in kibana.reglas.values())


def test_se_puede_habilitar_despues_de_desplegar_apagadas(proyecto, kibana):
    """El flujo real: revisar primero, activar después."""
    _correr("deploy-rules.sh", proyecto, kibana.url, "--disabled")
    assert not any(r["enabled"] for r in kibana.reglas.values())

    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert all(r["enabled"] for r in kibana.reglas.values())
    assert len(kibana.reglas) == 14


# ─── Idempotencia: el requisito central ──────────────────────────────────────

def test_desplegar_dos_veces_no_duplica(proyecto, kibana):
    """Es lo que hace que esto sirva como despliegue reproducible.

    La identidad de cada regla es su `rule_id`, fijo en el archivo versionado.
    Si un archivo lo perdiera, o el script dejara de usar `overwrite=true`, la
    segunda corrida agregaría 14 reglas más.
    """
    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert len(kibana.reglas) == 14

    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert len(kibana.reglas) == 14, "la segunda corrida duplicó reglas"


def test_cinco_corridas_seguidas_siguen_dando_catorce(proyecto, kibana):
    for _ in range(5):
        assert _correr("deploy-rules.sh", proyecto, kibana.url).returncode == 0
    assert len(kibana.reglas) == 14


def test_desplegar_actualiza_una_regla_modificada(proyecto, kibana):
    """Idempotente no es "no hacer nada": reimportar aplica los cambios."""
    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert kibana.reglas["sensitive-port-probe"]["risk_score"] == 55

    archivo = proyecto / "rules" / "ndjson" / "B3-sensitive-port-probe.ndjson"
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    regla["risk_score"] = 80
    archivo.write_text(json.dumps(regla, ensure_ascii=False) + "\n", encoding="utf-8")

    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert len(kibana.reglas) == 14
    assert kibana.reglas["sensitive-port-probe"]["risk_score"] == 80


# ─── Validación antes de tocar nada ──────────────────────────────────────────

def test_dry_run_no_contacta_a_kibana(proyecto, kibana):
    resultado = _correr("deploy-rules.sh", proyecto, kibana.url, "--dry-run")

    assert resultado.returncode == 0
    assert kibana.peticiones == [], "el modo de prueba habló con Kibana"
    assert len(kibana.reglas) == 0


def test_un_archivo_corrupto_aborta_sin_desplegar(proyecto, kibana):
    """Falla antes del import: no se sube un catálogo a medias."""
    (proyecto / "rules" / "ndjson" / "roto.ndjson").write_text(
        "{esto no es json", encoding="utf-8")

    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode != 0
    assert len(kibana.reglas) == 0, "desplegó pese al archivo corrupto"
    assert "JSON inválido" in resultado.stderr


def test_un_rule_id_duplicado_aborta(proyecto, kibana):
    """Dos archivos con el mismo `rule_id`: uno pisaría al otro en silencio."""
    original = proyecto / "rules" / "ndjson" / "B3-sensitive-port-probe.ndjson"
    (proyecto / "rules" / "ndjson" / "ZZ-copia.ndjson").write_text(
        original.read_text(encoding="utf-8"), encoding="utf-8")

    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode != 0
    assert "duplicado" in resultado.stderr
    assert len(kibana.reglas) == 0


def test_una_regla_sin_campos_obligatorios_aborta(proyecto, kibana):
    (proyecto / "rules" / "ndjson" / "ZZ-incompleta.ndjson").write_text(
        json.dumps({"rule_id": "incompleta", "name": "X"}) + "\n", encoding="utf-8")

    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode != 0
    assert "faltan campos" in resultado.stderr
    assert len(kibana.reglas) == 0


def test_sin_env_no_despliega(proyecto, kibana):
    (proyecto / ".env").unlink()
    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode != 0
    assert len(kibana.reglas) == 0


def test_una_opcion_desconocida_aborta(proyecto, kibana):
    resultado = _correr("deploy-rules.sh", proyecto, kibana.url, "--borrar-todo")

    assert resultado.returncode == 2
    assert kibana.peticiones == []


# ─── Credenciales ────────────────────────────────────────────────────────────

def test_las_credenciales_no_aparecen_en_la_salida(proyecto, kibana):
    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)
    salida = resultado.stdout + resultado.stderr
    assert "contrasena-de-prueba" not in salida


def test_las_credenciales_si_llegan_a_kibana(proyecto, kibana):
    """No se imprimen, pero sí se usan: si no, el despliegue sería anónimo."""
    _correr("deploy-rules.sh", proyecto, kibana.url)
    assert kibana.credenciales_vistas, "no se envió autenticación"
    assert all(c.startswith("Basic ") for c in kibana.credenciales_vistas)


# ─── Exportación ─────────────────────────────────────────────────────────────

def test_exportar_trae_las_reglas_de_kibana(proyecto, kibana):
    _correr("deploy-rules.sh", proyecto, kibana.url)

    resultado = _correr("export-rules.sh", proyecto, kibana.url)
    assert resultado.returncode == 0
    assert "14 regla(s) en Kibana" in resultado.stdout


def test_check_pasa_cuando_coinciden(proyecto, kibana):
    _correr("deploy-rules.sh", proyecto, kibana.url)
    _correr("export-rules.sh", proyecto, kibana.url)

    resultado = _correr("export-rules.sh", proyecto, kibana.url, "--check")
    assert resultado.returncode == 0
    assert "coinciden" in resultado.stdout


def test_check_falla_si_alguien_tocó_una_regla_en_la_consola(proyecto, kibana):
    """El caso que este script previene: un ajuste hecho en Kibana y no versionado."""
    _correr("deploy-rules.sh", proyecto, kibana.url)
    _correr("export-rules.sh", proyecto, kibana.url)

    kibana.reglas["sensitive-port-probe"]["risk_score"] = 99

    resultado = _correr("export-rules.sh", proyecto, kibana.url, "--check")
    assert resultado.returncode != 0
    assert "divergen" in resultado.stderr


def test_check_no_escribe_nada(proyecto, kibana):
    _correr("deploy-rules.sh", proyecto, kibana.url)
    _correr("export-rules.sh", proyecto, kibana.url)

    archivo = proyecto / "rules" / "ndjson" / "B3-sensitive-port-probe.ndjson"
    antes = archivo.read_bytes()
    kibana.reglas["sensitive-port-probe"]["risk_score"] = 99

    _correr("export-rules.sh", proyecto, kibana.url, "--check")
    assert archivo.read_bytes() == antes


def test_exportar_no_versiona_campos_de_la_instalacion(proyecto, kibana):
    """Kibana devuelve `id`, `created_at`… y no pueden entrar al repositorio."""
    _correr("deploy-rules.sh", proyecto, kibana.url)
    for regla in kibana.reglas.values():
        regla.update({"id": "uuid-de-esta-instalacion",
                      "created_at": "2026-09-17T00:00:00.000Z",
                      "created_by": "elastic", "revision": 7})

    _correr("export-rules.sh", proyecto, kibana.url)

    for archivo in (proyecto / "rules" / "ndjson").glob("*.ndjson"):
        regla = json.loads(archivo.read_text(encoding="utf-8"))
        for volatil in ("id", "created_at", "created_by", "revision"):
            assert volatil not in regla, f"{archivo.name} versionó '{volatil}'"


def test_exportar_avisa_de_una_regla_huerfana(proyecto, kibana):
    """Versionada pero ausente de Kibana: se avisa, no se borra sola."""
    _correr("deploy-rules.sh", proyecto, kibana.url)
    del kibana.reglas["sensitive-port-probe"]

    resultado = _correr("export-rules.sh", proyecto, kibana.url)
    assert "ausentes de Kibana" in resultado.stdout
    assert (proyecto / "rules" / "ndjson" / "B3-sensitive-port-probe.ndjson").exists()


# ─── El ciclo completo ───────────────────────────────────────────────────────

def test_el_ida_y_vuelta_es_estable(proyecto, kibana):
    """Desplegar → exportar → desplegar → exportar no cambia ningún archivo.

    Sin esto, cada exportación produciría un diff espurio y nadie miraría el
    historial de las reglas.
    """
    _correr("deploy-rules.sh", proyecto, kibana.url)
    _correr("export-rules.sh", proyecto, kibana.url)

    primera = {p.name: p.read_bytes()
               for p in sorted((proyecto / "rules" / "ndjson").glob("*.ndjson"))}

    _correr("deploy-rules.sh", proyecto, kibana.url)
    _correr("export-rules.sh", proyecto, kibana.url)

    segunda = {p.name: p.read_bytes()
               for p in sorted((proyecto / "rules" / "ndjson").glob("*.ndjson"))}
    assert primera == segunda


def test_desde_cero_quedan_catorce_reglas_activas(proyecto, kibana):
    """El criterio de aceptación de la tarea, verificado de punta a punta."""
    assert len(kibana.reglas) == 0

    resultado = _correr("deploy-rules.sh", proyecto, kibana.url)

    assert resultado.returncode == 0
    assert len(kibana.reglas) == 14
    assert sum(1 for r in kibana.reglas.values() if r["enabled"]) == 14
    assert "14 regla(s) en Kibana · 14 habilitada(s)" in resultado.stdout
