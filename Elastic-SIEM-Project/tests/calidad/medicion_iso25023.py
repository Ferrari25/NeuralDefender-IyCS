#!/usr/bin/env python3
"""Medición ISO/IEC 25023 de NeuralDefender: Compatibilidad y Seguridad.

Mide, en una corrida de `--duracion` segundos con `--clientes` clientes
concurrentes, las medidas base de cuatro subcaracterísticas de ISO/IEC 25010:

  Compatibilidad · Coexistencia       CCo-1-G  productos que comparten el host sin impacto adverso
  Compatibilidad · Interoperabilidad  CIn-1-G / CIn-3-S  intercambios recibidos y usados correctamente
  Seguridad      · Trazabilidad       SAc-1-G  accesos registrados de forma atribuible en la auditoría
  Seguridad      · Autenticidad       SAu-2-S  intentos de acceso resueltos según la regla de autenticación

Dónde se mide cada cosa (y por qué):

* **Stack Docker en marcha (solo lectura).** Coexistencia (se observa a
  Elasticsearch, Kibana, Logstash, Filebeat, Ollama, backup y autoheal mientras
  la capa IA trabaja), interoperabilidad con los productos reales y los
  rechazos de autenticación de las APIs reales. Nunca se escribe nada en ese
  stack: ningún login, ninguna decisión.
* **Malla aislada.** Los 8 microservicios del proyecto (el mismo código) se
  levantan en este proceso, cada uno con su servidor HTTP en 127.0.0.1, sobre
  un directorio temporal. Ahí van las operaciones que escriben: logins,
  decisiones, documentos. Así la auditoría real (append-only, inmutable) no
  recibe ni un registro de prueba.

Uso (desde Elastic-SIEM-Project/):

    PYTHONPATH=.devtools python3 tests/calidad/medicion_iso25023.py \\
        --corrida RUN-001 --clientes 1 --duracion 60 \\
        --condicion "Operación nominal (1 cliente)" --esperar ocioso

Cada corrida agrega una línea a `reportes/calidad/mediciones.jsonl` (o a `--salida`).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import secrets
import shutil
import statistics
import subprocess  # nosec B404 - solo `docker inspect/stats` con argumentos fijos
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests

RAIZ = Path(__file__).resolve().parents[2]
SALIDA_POR_DEFECTO = RAIZ / "reportes" / "calidad" / "mediciones.jsonl"

# ─── Productos que comparten el host con la capa IA (CCo-1-G, B) ─────────────
PRODUCTOS = ["elasticsearch", "kibana", "logstash", "filebeat",
             "siem-ollama", "siem-backup", "siem-autoheal"]
SERVICIOS_IA = ["siem-gateway", "siem-auth", "siem-audit", "siem-collector",
                "siem-classifier", "siem-analyst", "siem-knowledge", "siem-pipeline"]
LATENCIA_MAXIMA_SONDEO = 2.0   # s: un sondeo más lento cuenta como impacto adverso
INTERVALO_MUESTREO = 5.0       # s


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _leer_env(ruta: Path) -> dict[str, str]:
    valores: dict[str, str] = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        valor = valor.split(" #", 1)[0].strip().strip('"').strip("'")
        valores[clave.strip()] = valor
    return valores


def _docker(*args: str, timeout: float = 20) -> str:
    resultado = subprocess.run(["docker", *args], capture_output=True, text=True,  # nosec B603 B607
                               timeout=timeout, check=False)
    return resultado.stdout


def _ip(contenedor: str) -> str:
    salida = _docker("inspect", contenedor, "--format",
                     "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}")
    return salida.split()[0]


class Contador:
    """Intentos (B) y aciertos (A) por categoría, seguro entre hilos."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total: Counter = Counter()
        self.ok: Counter = Counter()

    def anotar(self, categoria: str, acierto: bool) -> None:
        with self._lock:
            self.total[categoria] += 1
            if acierto:
                self.ok[categoria] += 1

    def resumen(self) -> dict:
        return {"total": sum(self.total.values()), "ok": sum(self.ok.values()),
                "por_categoria": {k: {"total": self.total[k], "ok": self.ok[k]}
                                  for k in sorted(self.total)}}


# ─── Stack real: coexistencia (CCo-1-G) ──────────────────────────────────────

def _memoria_disponible_mb() -> float | None:
    """`MemAvailable` del host: lo que el kernel puede dar sin matar procesos."""
    try:
        for linea in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if linea.startswith("MemAvailable:"):
                return int(linea.split()[1]) / 1024
    except OSError:
        return None
    return None


def _oom_del_kernel(desde: float) -> list[str]:
    """Contenedores (por id) en los que el kernel mató un proceso por falta de memoria.

    El incidente del 2026-11-09: con el stack completo y la batería de pruebas en
    paralelo, el kernel mató el modelo de Ollama. Ese impacto sobre otro producto
    pasó entre corridas, así que la coexistencia nunca lo vio: ahora se mira el
    registro del kernel durante la ventana de cada corrida.
    """
    try:
        salida = subprocess.run(  # nosec B603 B607 - argumentos fijos, solo lectura
            ["journalctl", "-k", "-q", "--no-pager", "--since", f"@{int(desde)}"],
            capture_output=True, text=True, timeout=20, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return re.findall(r"oom-kill:.*task_memcg=/system\.slice/docker-([0-9a-f]{12})", salida)


class ObservadorDeCoexistencia(threading.Thread):
    """Muestrea salud, reinicios, sondeos funcionales, CPU y memoria de cada producto."""

    def __init__(self, entorno: dict[str, str]) -> None:
        super().__init__(daemon=True)
        self.alto = threading.Event()
        self.auth_es = ("elastic", entorno.get("ELASTIC_PASSWORD", ""))
        self.ollama = f"http://{_ip('siem-ollama')}:11434"
        self.muestras: list[dict] = []
        self.inicial = self._estado()
        self.desde = time.time()
        self.ids = {n: _docker("inspect", n, "--format", "{{.Id}}").strip()[:12] for n in PRODUCTOS}

    def _estado(self) -> dict[str, dict]:
        salida = _docker("inspect", *PRODUCTOS, "--format",
                         "{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}"
                         "{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}")
        estado = {}
        for linea in salida.splitlines():
            nombre, status, salud, reinicios, inicio = linea.lstrip("/").split("|")
            estado[nombre] = {"status": status, "salud": salud,
                              "reinicios": int(reinicios), "inicio": inicio}
        return estado

    def _sondeos(self) -> dict[str, tuple[bool, float]]:
        def medir(url: str, auth=None, validar=lambda r: r.ok) -> tuple[bool, float]:
            t0 = time.perf_counter()
            try:
                r = requests.get(url, auth=auth, timeout=5)
                ok = validar(r)
            except requests.RequestException:
                ok = False
            return ok, time.perf_counter() - t0

        return {
            "elasticsearch": medir("http://127.0.0.1:9200/_cluster/health", self.auth_es,
                                   lambda r: r.ok and r.json().get("status") in ("green", "yellow")),
            "kibana": medir("http://127.0.0.1:5601/api/status", self.auth_es,
                            lambda r: r.ok and r.json()["status"]["overall"]["level"] == "available"),
            "logstash": medir("http://127.0.0.1:9600/"),
            "siem-ollama": medir(f"{self.ollama}/api/tags"),
        }

    def _cpu(self) -> dict[str, float]:
        salida = _docker("stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}")
        cpu = {}
        for linea in salida.splitlines():
            nombre, porcentaje, _mem = linea.split("|")
            cpu[nombre] = float(porcentaje.rstrip("%") or 0)
        return cpu

    def run(self) -> None:
        while not self.alto.is_set():
            self.muestras.append({"t": time.time(), "estado": self._estado(),
                                  "sondeos": self._sondeos(), "cpu": self._cpu(),
                                  "mem_disponible_mb": _memoria_disponible_mb()})
            self.alto.wait(INTERVALO_MUESTREO)

    def resultado(self) -> dict:
        final = self._estado()
        matados = _oom_del_kernel(self.desde)
        por_producto = {}
        for p in PRODUCTOS:
            motivos = []
            if self.ids.get(p) and self.ids[p] in matados:
                motivos.append("el kernel mató un proceso suyo por falta de memoria (OOM)")
            if final[p]["reinicios"] != self.inicial[p]["reinicios"] \
                    or final[p]["inicio"] != self.inicial[p]["inicio"]:
                motivos.append("se reinició durante la corrida")
            estados = [m["estado"][p] for m in self.muestras] + [final[p]]
            if any(e["status"] != "running" for e in estados):
                motivos.append("dejó de estar en ejecución")
            if any(e["salud"] not in ("healthy", "none") for e in estados):
                motivos.append("healthcheck no saludable")
            sondeos = [m["sondeos"][p] for m in self.muestras if p in m["sondeos"]]
            fallidos = sum(1 for ok, _ in sondeos if not ok)
            lentos = sum(1 for ok, seg in sondeos if ok and seg > LATENCIA_MAXIMA_SONDEO)
            if fallidos:
                motivos.append(f"{fallidos} sondeo(s) fallido(s)")
            if lentos:
                motivos.append(f"{lentos} sondeo(s) más lentos que {LATENCIA_MAXIMA_SONDEO:g} s")
            latencias = sorted(seg * 1000 for _, seg in sondeos)
            cpus = [m["cpu"].get(p, 0.0) / (os.cpu_count() or 1) for m in self.muestras]
            por_producto[p] = {
                "sin_impacto": not motivos, "motivos": motivos,
                "sondeos": len(sondeos),
                "latencia_media_ms": round(statistics.fmean(latencias), 1) if latencias else None,
                "latencia_max_ms": round(latencias[-1], 1) if latencias else None,
                "cpu_media_pct": round(statistics.fmean(cpus), 2) if cpus else None,
            }
        # `docker stats` da el % de UN núcleo; se lleva a % de la capacidad del host.
        nucleos = os.cpu_count() or 1
        cpu_ia = [sum(m["cpu"].get(s, 0.0) for s in SERVICIOS_IA) / nucleos for m in self.muestras]
        cpu_total = [sum(m["cpu"].values()) / nucleos for m in self.muestras]
        return {
            "prod_esp": len(PRODUCTOS),
            "prod_ok": sum(1 for v in por_producto.values() if v["sin_impacto"]),
            "por_producto": por_producto,
            "muestras": len(self.muestras),
            "cpu_capa_ia_media_pct": round(statistics.fmean(cpu_ia), 2) if cpu_ia else None,
            "cpu_contenedores_media_pct": round(statistics.fmean(cpu_total), 2) if cpu_total else None,
            "cpu_ollama_media_pct": por_producto["siem-ollama"]["cpu_media_pct"],
            "nucleos_host": nucleos,
            "oom_en_la_ventana": len(matados),
            "mem_disponible_min_mb": round(min(memorias)) if (memorias := [
                m["mem_disponible_mb"] for m in self.muestras if m.get("mem_disponible_mb")]) else None,
            "mem_disponible_media_mb": round(statistics.fmean(memorias)) if memorias else None,
        }


# ─── Stack real: interoperabilidad y autenticidad (solo lectura) ─────────────

class StackReal:
    """Intercambios y rechazos contra el despliegue real. Nada escribe."""

    def __init__(self, entorno: dict[str, str]) -> None:
        self.token = entorno["SIEM_INTERNAL_TOKEN"]
        self.auth_es = ("elastic", entorno.get("ELASTIC_PASSWORD", ""))
        self.url = {s: f"http://{_ip('siem-' + s)}:8000"
                    for s in ("audit", "pipeline", "collector", "classifier")}
        self.ollama = f"http://{_ip('siem-ollama')}:11434"
        self.gateway = "http://127.0.0.1:5000"
        self._snapshot: dict | None = None

    def _get(self, servicio: str, ruta: str, token: str | None = None, **kw):
        cabeceras = {"X-Internal-Token": token} if token is not None else {}
        return requests.get(self.url[servicio] + ruta, headers=cabeceras, timeout=30, **kw)

    # Interoperabilidad: cada función devuelve True si el dato llegó Y se pudo usar.
    def int_elasticsearch_ecs(self) -> bool:
        r = requests.post("http://127.0.0.1:9200/filebeat-*/_search", auth=self.auth_es,
                          json={"size": 20, "sort": [{"@timestamp": "desc"}]}, timeout=30)
        hits = r.json()["hits"]["hits"]
        return r.ok and bool(hits) and all("@timestamp" in h["_source"] for h in hits)

    def int_kibana_reglas(self) -> bool:
        r = requests.get("http://127.0.0.1:5601/api/detection_engine/rules/_find?per_page=100",
                         auth=self.auth_es, headers={"kbn-xsrf": "medicion"}, timeout=30)
        reglas = r.json().get("data", [])
        return r.ok and len(reglas) >= 14 and all({"rule_id", "query", "risk_score"} <= set(x)
                                                  for x in reglas if x.get("type") == "query")

    def int_logstash(self) -> bool:
        r = requests.get("http://127.0.0.1:9600/_node/stats/pipelines", timeout=30)
        return r.ok and "pipelines" in r.json()

    def int_ollama(self) -> bool:
        r = requests.get(f"{self.ollama}/api/tags", timeout=30)
        return r.ok and any(m["name"].startswith("gemma3") for m in r.json().get("models", []))

    def int_collector_snapshot(self) -> bool:
        r = self._get("collector", "/v1/snapshots/latest", self.token)
        datos = r.json().get("snapshot") if r.ok else None
        if isinstance(datos, dict) and {"alerts", "auth_failure_logs", "summary"} <= set(datos):
            self._snapshot = datos
            return True
        return False

    def int_classifier(self) -> bool:
        if self._snapshot is None and not self.int_collector_snapshot():
            return False
        r = requests.post(self.url["classifier"] + "/v1/classify", json={"siem_data": self._snapshot},
                          headers={"X-Internal-Token": self.token}, timeout=60)
        incs = r.json().get("incidents") if r.ok else None
        return isinstance(incs, list) and all({"incident_id", "classification", "recommended_actions"}
                                              <= set(i) for i in incs)

    def int_pipeline_incidentes(self) -> bool:
        r = self._get("pipeline", "/v1/incidents", self.token)
        incs = r.json().get("incidents") if r.ok else None
        return isinstance(incs, list) and all("analysis" in i and "mitre" in i for i in incs)

    def int_reporte_csv(self) -> bool:
        r = self._get("audit", "/v1/reports", self.token, params={"formato": "csv"})
        if not r.ok:
            return False
        texto = r.json()["csv"] if "json" in r.headers.get("Content-Type", "") else r.text
        filas = list(csv.reader(io.StringIO(texto)))
        return len(filas) >= 1 and len(filas[0]) >= 3

    def int_reporte_json(self) -> bool:
        r = self._get("audit", "/v1/reports", self.token, params={"formato": "json"})
        return r.ok and isinstance(r.json(), dict)

    def int_network_logs(self) -> bool:
        archivos = sorted((RAIZ / "network_logs").glob("*.json"))
        for archivo in archivos:
            for linea in archivo.read_text(encoding="utf-8").splitlines():
                if linea.strip():
                    evento = json.loads(linea)
                    if "@timestamp" not in evento and "timestamp" not in evento:
                        return False
        return bool(archivos)

    # Autenticidad: cada función devuelve True si el resultado es el que exige la regla.
    def aut_gateway_sin_sesion(self) -> bool:
        return requests.get(self.gateway + "/api/v1/incidents", timeout=30).status_code == 401

    def aut_interna_sin_token(self) -> bool:
        return self._get("audit", "/v1/decisions").status_code == 401

    def aut_interna_token_falso(self) -> bool:
        return self._get("audit", "/v1/decisions", "token-falso-" + secrets.token_hex(8)).status_code == 401

    def aut_interna_token_valido(self) -> bool:
        return self._get("pipeline", "/v1/incidents", self.token).status_code == 200

    def verificaciones(self) -> dict:
        """Integridad de las tres cadenas de la auditoría REAL (solo lectura)."""
        res = {}
        for nombre, ruta in (("decisiones", "/v1/decisions/verify"),
                             ("corridas", "/v1/analysis-history/verify"),
                             ("actividad", "/v1/activity/verify")):
            r = self._get("audit", ruta, self.token)
            res[nombre] = r.json() if r.ok else {"error": r.status_code}
        return res


INTERCAMBIOS = ["int_elasticsearch_ecs", "int_kibana_reglas", "int_logstash", "int_ollama",
                "int_collector_snapshot", "int_classifier", "int_pipeline_incidentes",
                "int_reporte_csv", "int_reporte_json", "int_network_logs"]
LEGITIMOS = {"login_valido_aceptado", "sesion_identifica_al_usuario",
             "malla_token_valido_aceptado", "real_interna_token_valido", "error_de_transporte"}
REGLAS_REALES = ["aut_gateway_sin_sesion", "aut_interna_sin_token",
                 "aut_interna_token_falso", "aut_interna_token_valido"]


# ─── Malla aislada: los 8 microservicios, por HTTP, en un directorio temporal ──

class Malla:
    """Levanta gateway + 7 servicios internos con servidores HTTP reales."""

    PASSWORD = "medicion-" + secrets.token_hex(8)

    def __init__(self, clientes: int) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="siem-medicion-"))
        (self.dir / "data").mkdir()
        (self.dir / "network_logs").mkdir()
        os.chdir(self.dir)
        self.token = secrets.token_hex(32)
        os.environ.update({
            "SIEM_INTERNAL_TOKEN": self.token,
            "SECRET_KEY": secrets.token_urlsafe(48),
            "SIEM_USERS_FILE": str(self.dir / "data" / "users.json"),
            "SIEM_USE_LLM": "false",
        })
        sys.path[:0] = [str(RAIZ / "libs"), *[str(d) for d in sorted((RAIZ / "services").iterdir())
                                               if d.is_dir()], str(RAIZ)]
        self._preparar_datos(clientes)
        self.urls = self._levantar()
        # Las versiones anteriores al registro de accesos no tienen /v1/access.
        self.tiene_registro_de_accesos = requests.get(
            self.urls["audit"] + "/v1/access/verify", headers={"X-Internal-Token": self.token},
            timeout=30).status_code == 200

    def _preparar_datos(self, clientes: int) -> None:
        import classifier  # pylint: disable=import-outside-toplevel
        import siem_auth  # pylint: disable=import-outside-toplevel
        import siem_lib  # pylint: disable=import-outside-toplevel

        fixtures = RAIZ / "tests" / "fixtures"
        siem_clean = json.loads((fixtures / "siem_clean.min.json").read_text(encoding="utf-8"))
        eventos = siem_lib.read_network_logs(fixtures / "network_logs", window_hours=None)
        incs = classifier.classify(siem_clean, eventos)
        siem_lib.write_json(self.dir / "data" / "siem_incidents.json", {
            "generated_at": _ahora(), "source": "medicion", "incident_count": len(incs),
            "incidents": incs})
        self.acciones = [(i["incident_id"], a["action_id"]) for i in incs
                         for a in i["recommended_actions"]]

        hash_ = siem_auth.hash_password(self.PASSWORD)
        usuarios = {}
        for i in range(clientes):
            usuarios[f"analista{i:02d}"] = ("analyst", True)
            usuarios[f"dadobaja{i:02d}"] = ("analyst", False)
            for k in range(12):
                usuarios[f"victima{i:02d}x{k:02d}"] = ("viewer", True)
        siem_auth.guardar_usuarios({
            n: siem_auth.Usuario(username=n, rol=rol, password_hash=hash_, activo=activo,
                                 creado=_ahora())
            for n, (rol, activo) in usuarios.items()})

    def _levantar(self) -> dict[str, str]:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        import importlib  # pylint: disable=import-outside-toplevel

        from werkzeug.serving import make_server  # pylint: disable=import-outside-toplevel

        urls = {}
        for servicio in ("auth", "audit", "collector", "classifier", "analyst",
                         "pipeline", "knowledge"):
            app = importlib.import_module(f"{servicio}_service").app
            urls[servicio] = self._servir(make_server, app)
            os.environ[f"SIEM_{servicio.upper()}_URL"] = urls[servicio]
        dashboard = importlib.import_module("dashboard")
        urls["gateway"] = self._servir(make_server, dashboard.app)
        return urls

    @staticmethod
    def _servir(make_server, app) -> str:
        servidor = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{servidor.server_port}"

    def audit(self, ruta: str):
        return requests.get(self.urls["audit"] + ruta, headers={"X-Internal-Token": self.token},
                            timeout=60).json()

    def cerrar(self) -> None:
        os.chdir(RAIZ)
        shutil.rmtree(self.dir, ignore_errors=True)


class Cliente(threading.Thread):
    """Un analista simulado: repite el ciclo de pruebas hasta que se acaba el tiempo."""

    def __init__(self, n: int, malla: Malla, real: StackReal, fin: float,
                 aut: Contador, regla: Contador, inter: Contador, intentos: list, corrida: str) -> None:
        super().__init__(daemon=True)
        self.n, self.malla, self.real, self.fin = n, malla, real, fin
        self.aut, self.regla, self.inter = aut, regla, inter
        self.intentos, self.corrida = intentos, corrida
        self.gw = malla.urls["gateway"]
        self.victimas = [f"victima{n:02d}x{k:02d}" for k in range(12)]

    def _post(self, s, ruta, cuerpo, csrf=None):
        cab = {"X-CSRFToken": csrf} if csrf else {}
        return s.post(self.gw + ruta, json=cuerpo, headers=cab, timeout=60)

    def _accesos(self, tipo: str, usuario: str, ok: bool, marca: str) -> None:
        self.intentos.append({"tipo": tipo, "usuario": usuario, "aceptado": ok,
                              "marca": marca, "ts": time.time()})

    def _legitimo(self, categoria: str, ok: bool) -> None:
        """Un intento legítimo: la regla exige aceptarlo y probar su identidad."""
        self.aut.anotar(categoria, ok)
        self.regla.anotar(categoria, ok)

    def _ilegitimo(self, categoria: str, codigos: list[int], esperados: tuple[int, ...],
                   extra: bool = True) -> None:
        """Un intento que la regla exige rechazar.

        Para la autenticidad (SAu) alcanza con que no entre: cualquier código >= 400.
        La conformidad exacta (el código y el mensaje que dice la especificación) se
        anota aparte, en `regla`.
        """
        self.aut.anotar(categoria, all(c >= 400 for c in codigos))
        self.regla.anotar(categoria, extra and all(c in esperados for c in codigos))

    def _ciclo(self, k: int) -> None:  # pylint: disable=too-many-locals
        analista, pw = f"analista{self.n:02d}", Malla.PASSWORD
        marca = f"MED-{self.corrida}-{self.n:02d}-{k:04d}"

        # SAu: login válido → 200 y la identidad probada es la declarada.
        s = requests.Session()
        r = self._post(s, "/api/v1/login", {"username": analista, "password": pw})
        ok_login = r.status_code == 200 and r.json().get("usuario") == analista
        self._legitimo("login_valido_aceptado", ok_login)
        self._accesos("login_exitoso", analista, ok_login, marca)
        csrf = r.json().get("csrf_token") if ok_login else None
        if ok_login:
            me = s.get(self.gw + "/api/v1/me", timeout=60)
            self._legitimo("sesion_identifica_al_usuario",
                           me.status_code == 200 and me.json().get("usuario") == analista)

        # SAu: credenciales falsas, usuario inexistente, usuario dado de baja.
        anonimo = requests.Session()
        malo = self._post(anonimo, "/api/v1/login", {"username": analista, "password": pw + "x"})
        self._ilegitimo("password_incorrecta_rechazada", [malo.status_code], (401, 429))
        self._accesos("login_fallido", analista, False, marca)
        inex = self._post(anonimo, "/api/v1/login",
                          {"username": f"noexiste{self.n:02d}x{k}", "password": pw})
        mismo_mensaje = (malo.status_code != 401 or inex.status_code != 401
                         or inex.json().get("error") == malo.json().get("error"))
        self._ilegitimo("usuario_inexistente_rechazado_sin_enumerar", [inex.status_code], (401,),
                        mismo_mensaje)
        baja = self._post(anonimo, "/api/v1/login", {"username": f"dadobaja{self.n:02d}", "password": pw})
        self._ilegitimo("usuario_dado_de_baja_rechazado", [baja.status_code], (401, 429))

        # SAu: bloqueo por intentos (5 fallos → la contraseña correcta tampoco entra,
        # ni falseando X-Forwarded-For). Una víctima nueva por ciclo.
        fallos: list[int] | None = None
        v = self.victimas[k] if k < len(self.victimas) else ""
        if v:
            fallos = [self._post(anonimo, "/api/v1/login", {"username": v, "password": "mala"}).status_code
                      for _ in range(5)]
            self._ilegitimo("cinco_fallos_rechazados", fallos, (401,))
            if fallos != [401] * 5:
                # Algún "fallo" fue un error del servidor (no llegó a verificar la
                # contraseña, así que no cuenta para el bloqueo): la precondición de
                # la regla no se cumplió y probarla acá daría un falso hallazgo.
                self.regla.anotar("bloqueo_no_evaluable_por_error", False)
                fallos = None
        if fallos is not None:
            bloqueada = self._post(anonimo, "/api/v1/login", {"username": v, "password": pw})
            self._ilegitimo("bloqueo_alcanza_password_correcta", [bloqueada.status_code], (429,))
            xff = anonimo.post(self.gw + "/api/v1/login", json={"username": v, "password": pw},
                               headers={"X-Forwarded-For": f"10.9.{self.n}.{k % 250}"}, timeout=60)
            self._ilegitimo("x_forwarded_for_no_esquiva_bloqueo", [xff.status_code], (429,))

        # SAu: sin sesión, cookie adulterada, POST sin token CSRF.
        self._ilegitimo("sin_sesion_rechazado",
                        [requests.get(self.gw + "/api/v1/incidents", timeout=60).status_code], (401,))
        if ok_login:
            cookie = s.cookies.get("session") or ""
            falsa = cookie[:-4] + ("AAAA" if not cookie.endswith("AAAA") else "BBBB")
            adulterada = requests.get(self.gw + "/api/v1/me", timeout=60, cookies={"session": falsa})
            self._ilegitimo("cookie_adulterada_rechazada", [adulterada.status_code], (401,))
            sin_csrf = self._post(s, "/api/v1/decision", {"incident_id": "x", "action_id": "y",
                                                          "decision": "approved"})
            self._ilegitimo("post_sin_csrf_rechazado", [sin_csrf.status_code], (403,))

        # SAu: API interna de la malla, sin token / token falso / token válido.
        audit = self.malla.urls["audit"] + "/v1/decisions"
        self._ilegitimo("malla_sin_token_rechazado", [requests.get(audit, timeout=60).status_code], (401,))
        self._ilegitimo("malla_token_falso_rechazado", [requests.get(
            audit, headers={"X-Internal-Token": "x" * 64}, timeout=60).status_code], (401,))
        self._legitimo("malla_token_valido_aceptado", requests.get(
            audit, headers={"X-Internal-Token": self.malla.token}, timeout=60).status_code == 200)

        # SAc: acciones que la auditoría tiene que atribuir a quien las hizo.
        if not ok_login:
            # Sin sesión no hay decisión ni documento posibles: se sigue con el
            # stack real, que no depende de la malla.
            self._probar_stack_real(k)
            return
        incidente, accion = self.malla.acciones[(self.n + k) % len(self.malla.acciones)]
        d = self._post(s, "/api/v1/decision", {"incident_id": incidente, "action_id": accion,
                                               "decision": "approved" if k % 2 else "dismissed",
                                               "note": marca}, csrf)
        self._accesos("decision", analista, d.status_code in (200, 201), marca)
        doc = self._post(s, "/api/v1/memoria/documentos",
                         {"titulo": marca, "contenido": f"Documento de medición {marca}."}, csrf)
        self._accesos("documento", analista, doc.status_code == 201, marca)

        self._probar_stack_real(k)

    def _probar_stack_real(self, k: int) -> None:
        """Stack real (solo lectura): un intercambio y las reglas de autenticación."""
        nombre = INTERCAMBIOS[(self.n + k) % len(INTERCAMBIOS)]
        try:
            exito = getattr(self.real, nombre)()
        except (requests.RequestException, ValueError, KeyError, TypeError):
            exito = False
        self.inter.anotar(nombre, exito)
        for regla in REGLAS_REALES:
            try:
                ok = getattr(self.real, regla)()
            except requests.RequestException:
                ok = False
            self.aut.anotar("real_" + regla[4:], ok)
            self.regla.anotar("real_" + regla[4:], ok)

    def run(self) -> None:
        k = 0
        while time.time() < self.fin:
            try:
                self._ciclo(k)
            except requests.RequestException as e:
                self.aut.anotar("error_de_transporte", False)
                self.regla.anotar("error_de_transporte", False)
                print(f"[WARN] cliente {self.n}: {e}", file=sys.stderr)
            k += 1


def _trazabilidad(malla: Malla, intentos: list) -> dict:
    """SAc-1-G: cuántos accesos ejecutados quedaron registrados y atribuidos."""
    decisiones = malla.audit("/v1/decisions")
    actividad = malla.audit("/v1/activity")
    accesos = malla.audit("/v1/access") if malla.tiene_registro_de_accesos else []
    por_nota = {d.get("note"): d for d in decisiones if isinstance(d, dict)}
    docs = defaultdict(list)
    for a in actividad:
        docs[a.get("detalle")].append(a)
    # Eventos de acceso registrados, por (usuario, tipo): cada intento de login
    # tiene que encontrar SU evento (se van consumiendo de a uno).
    equivalentes = {"login_exitoso": ("login_exitoso",),
                    "login_fallido": ("login_fallido", "login_bloqueado")}
    disponibles = Counter((a.get("usuario"), a.get("evento")) for a in accesos
                          if a.get("ts") and a.get("ip"))

    cuenta = Contador()
    for it in intentos:
        if it["tipo"] in ("decision", "documento") and not it["aceptado"]:
            continue  # una operación rechazada no es un acceso ejecutado
        if it["tipo"] == "decision":
            rec = por_nota.get(it["marca"])
            cuenta.anotar("decision", bool(rec) and rec.get("analyst") == it["usuario"]
                          and bool(rec.get("session_id")) and bool(rec.get("ts")))
        elif it["tipo"] == "documento":
            recs = docs.get(it["marca"], [])
            cuenta.anotar("documento", any(r.get("actor") == it["usuario"] and r.get("ts")
                                           for r in recs))
        else:
            # Un inicio de sesión (exitoso o fallido) es un acceso de usuario al
            # sistema: cuenta si la auditoría tiene un evento suyo todavía sin asignar.
            encontrado = next((e for e in equivalentes[it["tipo"]]
                               if disponibles[(it["usuario"], e)] > 0), None)
            if encontrado:
                disponibles[(it["usuario"], encontrado)] -= 1
            cuenta.anotar(it["tipo"], encontrado is not None)
    rutas = [("decisiones", "/v1/decisions/verify"), ("actividad", "/v1/activity/verify")]
    if malla.tiene_registro_de_accesos:
        rutas.append(("accesos", "/v1/access/verify"))
    verif = {n: malla.audit(r) for n, r in rutas}
    cadena_ok = all(v.get("chain_ok") for v in verif.values())
    res = cuenta.resumen()
    res.update({"cadena_integra": cadena_ok, "verificacion": verif,
                "registros_decisiones": len(decisiones), "registros_actividad": len(actividad),
        "registros_accesos": len(accesos)})
    if not cadena_ok:
        res["ok"] = 0
    return res


def _esperar(modo: str) -> None:
    """`ocioso`: Ollama sin trabajo. `gemma`: Gemma analizando (CPU de Ollama alta)."""
    if modo == "no":
        return
    limite = time.time() + 900
    while time.time() < limite:
        salida = _docker("stats", "--no-stream", "--format", "{{.CPUPerc}}", "siem-ollama")
        cpu = float(salida.strip().rstrip("%") or 0)
        if (modo == "ocioso" and cpu < 5) or (modo == "gemma" and cpu > 50):
            print(f"[INFO] Condición '{modo}' alcanzada (CPU de Ollama {cpu:.1f}%).")
            return
        time.sleep(3)
    print(f"[WARN] No se alcanzó la condición '{modo}' en 15 min; se mide igual.")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--corrida", required=True)
    p.add_argument("--condicion", required=True)
    p.add_argument("--clientes", type=int, default=1)
    p.add_argument("--duracion", type=int, default=60)
    p.add_argument("--esperar", choices=("no", "ocioso", "gemma"), default="no")
    p.add_argument("--salida", type=Path, default=SALIDA_POR_DEFECTO)
    args = p.parse_args()

    entorno = _leer_env(RAIZ / ".env")
    build = subprocess.run(["git", "-C", str(RAIZ), "describe", "--always", "--dirty"],  # nosec B603 B607
                           capture_output=True, text=True, check=False).stdout.strip()
    real = StackReal(entorno)
    malla = Malla(args.clientes)
    try:
        _esperar(args.esperar)
        aut, regla, inter, intentos = Contador(), Contador(), Contador(), []
        observador = ObservadorDeCoexistencia(entorno)
        inicio = time.time()
        observador.start()
        fin = inicio + args.duracion
        hilos = [Cliente(n, malla, real, fin, aut, regla, inter, intentos, args.corrida)
                 for n in range(args.clientes)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        observador.alto.set()
        observador.join()
        t_obs = round(time.time() - inicio, 1)

        registro = {
            "corrida": args.corrida, "fecha": _ahora(), "build": build,
            "condicion": args.condicion, "clientes": args.clientes, "t_obs_s": t_obs,
            "herramienta": "tests/calidad/medicion_iso25023.py (Python requests + docker CLI)",
            "coexistencia": observador.resultado(),
            "interoperabilidad": inter.resumen(),
            "trazabilidad": _trazabilidad(malla, intentos),
            "autenticidad": aut.resumen(),
            "autenticidad_conformidad_exacta": regla.resumen(),
            "falsos_aceptados": sum(aut.total[c] - aut.ok[c] for c in aut.total
                                    if c not in LEGITIMOS),
            "auditoria_real": real.verificaciones(),
        }
    finally:
        malla.cerrar()
    args.salida.parent.mkdir(parents=True, exist_ok=True)
    with args.salida.open("a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")
    c, i, t, a = (registro[k] for k in ("coexistencia", "interoperabilidad", "trazabilidad", "autenticidad"))
    print(f"[OK] {args.corrida}: COE {c['prod_ok']}/{c['prod_esp']} · INT {i['ok']}/{i['total']} · "
          f"TRA {t['ok']}/{t['total']} · AUT {a['ok']}/{a['total']} · T_Obs {t_obs} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
