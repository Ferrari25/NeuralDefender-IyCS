"""Respaldo cifrado (RQ-SEC-05, punto A1) y retención de datos personales
(RQ-SEC-17, punto A2) contra un Elasticsearch simulado.

Como en `test_despliegue_de_reglas.py`: probar contra el Elasticsearch real
ataría la suite al stack levantado y no permitiría provocar los errores (un
snapshot PARTIAL, una restauración rechazada).

Lo que se certifica del respaldo (`backup/respaldo.sh` / `restaurar.sh`):
  - deja un único archivo cifrado (no se lee la auditoría en claro) y su SHA-256;
  - incluye el snapshot de Elasticsearch y la auditoría, y lo restaura igual;
  - un snapshot que no termina en SUCCESS hace fallar el respaldo;
  - conserva solo los N más recientes;
  - la restauración rechaza un archivo alterado o una clave equivocada, y nunca
    pisa data/audit/.
Y de la retención (`scripts/deploy-ilm.sh`):
  - política con borrado a los N días, contados desde la fecha de los datos;
  - plantilla para los índices nuevos + asignación a los existentes;
  - alertas con fase de borrado sin perder su rollover;
  - idempotente; `--dry-run` no toca nada; un valor inválido aborta.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent.parent
RESPALDO = RAIZ / "backup" / "respaldo.sh"
RESTAURAR = RAIZ / "backup" / "restaurar.sh"
DEPLOY_ILM = RAIZ / "scripts" / "deploy-ilm.sh"

CLAVE = "clave-de-prueba-de-al-menos-32-caracteres-xyz"
PASSWORD_ES = "password-de-prueba"


class ElasticsearchSimulado:
    """Los endpoints de snapshots, ILM y plantillas que usan los scripts."""

    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir            # lo que en ES sería path.repo/diario
        self.estado_snapshot = "SUCCESS"
        self.restaurar_falla = False
        self.indices = ["filebeat-8.12.2-2020.01.01", "filebeat-8.12.2-2099.01.01"]
        self.peticiones: list[tuple[str, str, dict | None]] = []
        self.politicas: dict[str, dict] = {}
        self.plantillas: dict[str, dict] = {}
        self.settings: dict[str, dict] = {}
        self._servidor = HTTPServer(("127.0.0.1", 0), self._manejador())
        threading.Thread(target=self._servidor.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        host, puerto = self._servidor.server_address
        return f"http://{host}:{puerto}"

    def cerrar(self):
        self._servidor.shutdown()
        self._servidor.server_close()

    def _manejador(self):
        es = self

        class Manejador(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _responder(self, codigo: int, cuerpo, tipo="application/json"):
                datos = cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo).encode()
                self.send_response(codigo)
                self.send_header("Content-Type", tipo)
                self.send_header("Content-Length", str(len(datos)))
                self.end_headers()
                self.wfile.write(datos)

            def _atender(self):
                esperado = "Basic " + base64.b64encode(f"elastic:{PASSWORD_ES}".encode()).decode()
                largo = int(self.headers.get("Content-Length") or 0)
                cuerpo = json.loads(self.rfile.read(largo)) if largo else None
                ruta = self.path.split("?")[0]
                es.peticiones.append((self.command, ruta, cuerpo))
                if self.headers.get("Authorization") != esperado:
                    return self._responder(401, {"error": "sin credenciales"})
                partes = ruta.strip("/").split("/")

                if partes[0] == "_snapshot":
                    if self.command == "PUT" and len(partes) == 2:
                        return self._responder(200, {"acknowledged": True})
                    if self.command == "PUT" and len(partes) == 3:
                        # Lo que haría ES: escribir el snapshot en el repositorio.
                        es.repo_dir.mkdir(parents=True, exist_ok=True)
                        (es.repo_dir / f"snap-{partes[2]}.dat").write_text("datos de índices")
                        return self._responder(200, {"snapshot": {"snapshot": partes[2],
                                                                  "state": es.estado_snapshot}})
                    if self.command == "POST" and partes[-1] == "_restore":
                        if es.restaurar_falla:
                            return self._responder(500, {"error": "index already exists"})
                        return self._responder(200, {"snapshot": {"shards": {"successful": 3}}})
                    if self.command == "DELETE":
                        return self._responder(200, {"acknowledged": True})

                if partes[0] == "_cat" and self.command == "GET":
                    return self._responder(200, ("\n".join(es.indices) + "\n").encode(), "text/plain")
                if partes[0] == "_ilm" and self.command == "PUT":
                    es.politicas[partes[2]] = cuerpo
                    return self._responder(200, {"acknowledged": True})
                if partes[0] == "_index_template" and self.command == "PUT":
                    es.plantillas[partes[1]] = cuerpo
                    return self._responder(200, {"acknowledged": True})
                if len(partes) == 2 and partes[1] == "_settings" and self.command == "PUT":
                    es.settings[partes[0]] = cuerpo
                    return self._responder(200, {"acknowledged": True})
                return self._responder(404, {"error": f"{self.command} {ruta}"})

            do_GET = do_PUT = do_POST = do_DELETE = _atender

        return Manejador


@pytest.fixture
def entorno(tmp_path: Path):
    snapshots = tmp_path / "snapshots"
    es = ElasticsearchSimulado(snapshots / "diario")
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "decisions.jsonl").write_text('{"decision":"aprobada","ip":"203.0.113.5"}\n')
    (audit / "analysis_history.jsonl").write_text('{"run":1}\n')
    # Como reset.sh: la auditoría archivada queda de solo lectura.
    archivada = audit / "archivo" / "20261013T023226Z"
    archivada.mkdir(parents=True)
    (archivada / "decisions.jsonl").write_text('{"viejo":true}\n')
    (archivada / "decisions.jsonl").chmod(0o400)
    archivada.chmod(0o500)
    variables = {
        "PATH": os.environ["PATH"], "HOME": str(tmp_path),
        "SIEM_RESPALDO_CLAVE": CLAVE, "ELASTIC_PASSWORD": PASSWORD_ES,
        "ES_HOST": es.url, "ES_URL": es.url,
        "AUDIT_DIR": str(audit), "SNAPSHOT_DIR": str(snapshots),
        "RESPALDO_DIR": str(tmp_path / "respaldos"),
        "AUDIT_RESTAURADA": str(tmp_path / "restaurados"),
    }
    yield es, variables, tmp_path
    es.cerrar()
    for directorio in tmp_path.rglob("*"):
        if directorio.is_dir():
            directorio.chmod(0o700)


def _correr(script: Path, variables: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(script), *args], env=variables, capture_output=True,
                          text=True, timeout=60, check=False)


def _respaldos(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "respaldos").glob("siem-respaldo-*.tar.gz.enc"))


# ─── Respaldo ────────────────────────────────────────────────────────────────

def test_el_respaldo_queda_cifrado_y_con_su_sha256(entorno):
    es, variables, tmp = entorno
    r = _correr(RESPALDO, variables)
    assert r.returncode == 0, r.stderr
    assert "Permission denied" not in r.stderr, "no pudo limpiar su directorio temporal"

    [archivo] = _respaldos(tmp)
    contenido = archivo.read_bytes()
    assert contenido.startswith(b"Salted__"), "no es un archivo cifrado por openssl"
    assert b"203.0.113.5" not in contenido and b"decisions" not in contenido
    assert oct(archivo.stat().st_mode & 0o777) == "0o600"
    suma = (archivo.parent / (archivo.name + ".sha256")).read_text()
    assert subprocess.run(["sha256sum", "-c", "-"], input=suma, cwd=archivo.parent,
                          text=True, capture_output=True, check=False).returncode == 0
    # El snapshot del día no queda en el repositorio: el próximo vuelve a ser completo.
    assert ("DELETE", f"/_snapshot/siem-respaldo/{archivo.name[14:30]}", None) in es.peticiones


def test_el_snapshot_pide_los_indices_del_siem_sin_estado_global(entorno):
    es, variables, _ = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    [cuerpo] = [c for m, ruta, c in es.peticiones if m == "PUT" and ruta.count("/") == 3]
    assert cuerpo["indices"] == "filebeat-*,.internal.alerts-security.alerts-*"
    assert cuerpo["include_global_state"] is False


def test_un_snapshot_incompleto_hace_fallar_el_respaldo(entorno):
    es, variables, tmp = entorno
    es.estado_snapshot = "PARTIAL"
    r = _correr(RESPALDO, variables)
    assert r.returncode != 0
    assert "SUCCESS" in r.stderr
    assert _respaldos(tmp) == [], "un respaldo incompleto no puede quedar como si fuera bueno"


def test_sin_clave_no_se_respalda(entorno):
    _, variables, tmp = entorno
    for clave in ("", "corta"):
        r = _correr(RESPALDO, {**variables, "SIEM_RESPALDO_CLAVE": clave})
        assert r.returncode != 0
        assert "SIEM_RESPALDO_CLAVE" in r.stderr
    assert _respaldos(tmp) == []


def test_conserva_solo_los_mas_recientes(entorno):
    _, variables, tmp = entorno
    viejos = tmp / "respaldos"
    viejos.mkdir()
    for dia in ("20260101", "20260102", "20260103"):
        (viejos / f"siem-respaldo-{dia}T030000Z.tar.gz.enc").write_bytes(b"x")
        (viejos / f"siem-respaldo-{dia}T030000Z.tar.gz.enc.sha256").write_text("x")

    assert _correr(RESPALDO, {**variables, "SIEM_RESPALDO_RETENCION": "2"}).returncode == 0
    nombres = [p.name for p in _respaldos(tmp)]
    assert len(nombres) == 2
    assert nombres[0] == "siem-respaldo-20260103T030000Z.tar.gz.enc"
    assert not (viejos / "siem-respaldo-20260101T030000Z.tar.gz.enc.sha256").exists()


# ─── Restauración ────────────────────────────────────────────────────────────

def test_restaura_indices_y_auditoria_sin_pisar_la_actual(entorno):
    es, variables, tmp = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    [archivo] = _respaldos(tmp)
    (tmp / "audit" / "decisions.jsonl").write_text("lo de hoy\n")

    r = _correr(RESTAURAR, variables, archivo.name)
    assert r.returncode == 0, r.stderr

    restaurada = tmp / "restaurados" / archivo.name.removesuffix(".tar.gz.enc")
    assert "203.0.113.5" in (restaurada / "decisions.jsonl").read_text()
    assert (restaurada / "archivo" / "20261013T023226Z" / "decisions.jsonl").exists(), \
        "la auditoría archivada (de solo lectura) también viaja en el respaldo"
    # Restaurar dos veces el mismo respaldo no choca con la copia de solo lectura.
    assert _correr(RESTAURAR, variables, archivo.name).returncode == 0
    assert (tmp / "audit" / "decisions.jsonl").read_text() == "lo de hoy\n", "pisó data/audit/"
    # Repositorio aparte y de solo lectura, dado de baja al terminar.
    registro = [c for m, ruta, c in es.peticiones if m == "PUT" and ruta == "/_snapshot/siem-restauracion"]
    assert registro and registro[0]["settings"]["readonly"] is True
    assert any(m == "POST" and ruta.endswith("/_restore") for m, ruta, _ in es.peticiones)
    assert ("DELETE", "/_snapshot/siem-restauracion", None) in es.peticiones
    assert not (tmp / "snapshots" / "restauracion").exists()


def test_renombrar_restaura_al_lado_de_los_indices_actuales(entorno):
    es, variables, tmp = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    assert _correr(RESTAURAR, variables, _respaldos(tmp)[0].name, "--renombrar").returncode == 0
    [cuerpo] = [c for m, ruta, c in es.peticiones if ruta.endswith("/_restore")]
    assert cuerpo["rename_replacement"] == "restaurado-$1"


def test_un_respaldo_alterado_no_se_restaura(entorno):
    es, variables, tmp = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    [archivo] = _respaldos(tmp)
    with archivo.open("ab") as f:
        f.write(b"x")

    r = _correr(RESTAURAR, variables, archivo.name)
    assert r.returncode != 0
    assert "SHA-256" in r.stderr
    assert not any(ruta.endswith("/_restore") for _, ruta, _ in es.peticiones)


def test_con_otra_clave_no_se_restaura(entorno):
    _, variables, tmp = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    r = _correr(RESTAURAR, {**variables, "SIEM_RESPALDO_CLAVE": "otra-clave-otra-clave-otra-clave-xx"},
                _respaldos(tmp)[0].name)
    assert r.returncode != 0
    assert not (tmp / "restaurados").exists()


def test_si_elasticsearch_rechaza_la_restauracion_falla(entorno):
    es, variables, tmp = entorno
    assert _correr(RESPALDO, variables).returncode == 0
    es.restaurar_falla = True
    r = _correr(RESTAURAR, variables, _respaldos(tmp)[0].name)
    assert r.returncode != 0
    assert "--renombrar" in r.stderr


def test_sin_elasticsearch_respalda_solo_la_auditoria_y_lo_dice(entorno):
    es, variables, tmp = entorno
    r = _correr(RESPALDO, {**variables, "SIEM_RESPALDO_ES": "false"})
    assert r.returncode == 0, r.stderr
    assert "NO incluye los índices" in r.stdout
    assert es.peticiones == []
    assert _correr(RESTAURAR, {**variables, "SIEM_RESPALDO_ES": "false"},
                   _respaldos(tmp)[0].name).returncode == 0


# ─── Retención (ILM) ─────────────────────────────────────────────────────────

def test_la_retencion_borra_por_la_fecha_de_los_datos(entorno):
    es, variables, _ = entorno
    r = _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": "45"})
    assert r.returncode == 0, r.stderr

    assert es.politicas["siem-retencion"]["policy"]["phases"]["delete"] == {
        "min_age": "45d", "actions": {"delete": {}}}
    ajustes = {"index.lifecycle.name": "siem-retencion",
               "index.lifecycle.parse_origination_date": True}
    plantilla = es.plantillas["siem-filebeat-retencion"]
    assert plantilla["index_patterns"] == ["filebeat-*"]
    assert plantilla["template"] == {"settings": ajustes}, "solo settings: el mapeo sigue dinámico"
    assert es.settings["filebeat-*"] == ajustes, "los índices que ya existen también"
    assert "filebeat-8.12.2-2020.01.01" in r.stdout, "avisa qué se va a borrar"
    assert "2099" not in r.stdout


def test_las_alertas_ganan_borrado_sin_perder_el_rollover(entorno):
    es, variables, _ = entorno
    assert _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": "30"}).returncode == 0
    fases = es.politicas[".alerts-ilm-policy"]["policy"]["phases"]
    assert fases["hot"]["actions"]["rollover"] == {"max_age": "30d", "max_primary_shard_size": "50gb"}
    assert fases["delete"]["min_age"] == "30d"


def test_desplegar_la_retencion_dos_veces_deja_lo_mismo(entorno):
    es, variables, _ = entorno
    assert _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": "30"}).returncode == 0
    primera = (dict(es.politicas), dict(es.plantillas), dict(es.settings))
    assert _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": "30"}).returncode == 0
    assert (es.politicas, es.plantillas, es.settings) == primera


def test_dry_run_no_modifica_nada(entorno):
    es, variables, _ = entorno
    r = _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": "30"}, "--dry-run")
    assert r.returncode == 0, r.stderr
    assert {m for m, _, _ in es.peticiones} <= {"GET"}
    assert "filebeat-8.12.2-2020.01.01" in r.stdout


@pytest.mark.parametrize("dias", ["0", "treinta", "-5", "30d"])
def test_una_retencion_invalida_aborta(entorno, dias):
    es, variables, _ = entorno
    r = _correr(DEPLOY_ILM, {**variables, "SIEM_RETENCION_DIAS": dias})
    assert r.returncode == 2
    assert es.peticiones == []
