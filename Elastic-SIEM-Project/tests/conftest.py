"""Fixtures compartidas de la suite.

Regla de oro de esta suite: **ningún test toca los datos reales del proyecto.**
Los servicios usan rutas relativas al CWD (`data/siem_incidents.json`,
`data/decisions.jsonl`, `network_logs/`), así que cada test que escriba algo
corre dentro de un `tmp_path` con el CWD cambiado (ver `sandbox`).

**La malla de microservicios corre en proceso.** En Docker, cada servicio es un
contenedor y se hablan por HTTP. Acá, `malla_en_proceso` reemplaza el
transporte HTTP de `siem_servicios.llamar` por uno que entrega cada petición al
cliente de prueba de Flask del servicio destino. Las rutas, los códigos, el
token interno y los cuerpos JSON son los mismos; lo único que no hay es red.
Como en las pruebas todos los servicios comparten el CWD, todos ven el mismo
`data/` — en Docker, cada uno tiene el suyo.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LIBS = PROJECT_ROOT / "libs"
SERVICES = PROJECT_ROOT / "services"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Cada microservicio es su propia raíz de imports, más la librería compartida:
# es el mismo PYTHONPATH que tiene cada contenedor (ver sus Dockerfile).
for _directorio in [LIBS, *sorted(d for d in SERVICES.iterdir() if d.is_dir())]:
    sys.path.insert(0, str(_directorio))

# Token interno fijo para las pruebas. Los servicios se niegan a construirse
# sin él, y se construyen al importarse, así que tiene que estar en el entorno
# antes del primer import de cualquier servicio.
TOKEN_INTERNO_DE_PRUEBA = "token-interno-de-prueba-no-usar-0123456789abcdef"
os.environ.setdefault("SIEM_INTERNAL_TOKEN", TOKEN_INTERNO_DE_PRUEBA)

# Módulo con la aplicación Flask de cada servicio interno.
MODULOS_DE_SERVICIO = {
    "auth": "auth_service",
    "audit": "audit_service",
    "collector": "collector_service",
    "classifier": "classifier_service",
    "analyst": "analyst_service",
    "pipeline": "pipeline_service",
    "knowledge": "knowledge_service",
}


# ─── Malla de microservicios en proceso ──────────────────────────────────────

def transporte_en_proceso(servicio: str, metodo: str, ruta: str, cuerpo, timeout: float):
    """Entrega la petición al cliente de prueba Flask del servicio destino."""
    del timeout
    import importlib

    import siem_servicios

    modulo = importlib.import_module(MODULOS_DE_SERVICIO[servicio])
    respuesta = modulo.app.test_client().open(
        ruta, method=metodo, json=cuerpo,
        headers={siem_servicios.ENCABEZADO_TOKEN: siem_servicios.token_interno()})
    return respuesta.status_code, respuesta.get_json(silent=True)


@pytest.fixture(autouse=True)
def malla_en_proceso():
    """Todas las pruebas hablan con los servicios en proceso, nunca por red."""
    import siem_servicios

    siem_servicios.instalar_transporte(transporte_en_proceso)
    yield
    siem_servicios.instalar_transporte(None)


@pytest.fixture
def servicio_caido(monkeypatch):
    """Simula que uno o más servicios no responden (como un contenedor caído).

        def test_x(servicio_caido):
            servicio_caido("audit")
    """
    import siem_servicios

    caidos: set[str] = set()

    def _transporte(servicio, metodo, ruta, cuerpo, timeout):
        if servicio in caidos:
            raise siem_servicios.ServicioNoDisponible(
                f"no se pudo conectar con el servicio '{servicio}'")
        return transporte_en_proceso(servicio, metodo, ruta, cuerpo, timeout)

    siem_servicios.instalar_transporte(_transporte)

    def _caer(*servicios: str):
        caidos.update(servicios)

    return _caer


# ─── Datos ───────────────────────────────────────────────────────────────────

@pytest.fixture
def siem_clean() -> dict:
    """Captura real del stack (7 alertas + 12 logs de auth fallida)."""
    return json.loads((FIXTURES / "siem_clean.min.json").read_text(encoding="utf-8"))


@pytest.fixture
def auth_25_sin_alerta() -> dict:
    """25 fallos de auth reales y ninguna alerta de Kibana (escenario de L-01)."""
    return json.loads((FIXTURES / "auth_25_sin_alerta.json").read_text(encoding="utf-8"))


@pytest.fixture
def network_logs_dir() -> Path:
    """Directorio con los NDJSON de port scan (26 puertos) y phishing (2 eventos)."""
    return FIXTURES / "network_logs"


@pytest.fixture
def malicious_dir() -> Path:
    """Eventos con payloads hostiles: inyección de comando y XSS vía incident_id."""
    return FIXTURES / "malicious"


@pytest.fixture
def incidents(siem_clean, network_logs_dir) -> list[dict]:
    """La salida completa del clasificador sobre los datos reales.

    Es el insumo de la mayoría de las pruebas de caracterización: se calcula una
    vez por test y se afirma sobre ella.
    """
    import classifier

    return classifier.classify(siem_clean, eventos_de_red(network_logs_dir))


def eventos_de_red(directorio) -> list[dict]:
    """Lee un fixture de `network_logs/` SIN aplicar la ventana de retención.

    **Todo test que lea un fixture con fecha fija tiene que pasar por acá.**

    Los fixtures son capturas congeladas en el tiempo (agosto/septiembre de
    2026). La ventana de 24 h que agregó B-05 los descarta en cuanto pasa un día,
    así que un `read_network_logs()` directo sobre un fixture es una prueba que
    funciona hoy y falla mañana — pasó exactamente eso: cuatro pruebas de S-01 y
    S-02 se rompieron al cambiar la fecha, sin que nadie tocara el código.

    El filtro temporal tiene sus propias pruebas, que generan eventos relativos a
    `datetime.now()` en vez de depender de fixtures
    (`test_b0x_robustez_y_formatos.py`).
    """
    import siem_lib
    return siem_lib.read_network_logs(directorio, window_hours=None)


# ─── Aislamiento del sistema de archivos ─────────────────────────────────────

@pytest.fixture
def sandbox(tmp_path, monkeypatch) -> Path:
    """CWD temporal con la estructura mínima del proyecto.

    Los scripts abren `data/decisions.jsonl` y `data/siem_incidents.json` por
    ruta relativa; sin esto, un test de escritura corrompería los datos reales.
    """
    (tmp_path / "network_logs").mkdir()
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def sandbox_con_incidentes(sandbox, siem_clean, network_logs_dir) -> Path:
    """Sandbox con un `data/siem_incidents.json` ya generado por el clasificador."""
    import classifier
    import siem_lib

    incs = classifier.classify(siem_clean, eventos_de_red(network_logs_dir))
    siem_lib.write_json(sandbox / "data" / "siem_incidents.json", {
        "generated_at": "2026-09-16T00:00:00+00:00",
        "source": "tests",
        "incident_count": len(incs),
        "incidents": incs,
    })
    return sandbox


# ─── Autenticación (API-01) ──────────────────────────────────────────────────

# Clave de firma fija para las pruebas. El servidor se niega a arrancar sin
# SECRET_KEY, así que la suite tiene que proveer una; que sea fija y evidente
# evita confundirla con una de verdad.
SECRET_KEY_DE_PRUEBA = "clave-de-prueba-no-usar-en-produccion-0123456789abcdef"

# Contraseña de los usuarios de prueba. Supera el mínimo de 12 caracteres.
PASSWORD_DE_PRUEBA = "contrasena-de-prueba-1"

USUARIOS_DE_PRUEBA = {
    "ana":  "analyst",   # decide
    "beto": "viewer",    # solo lectura
    "cata": "auditor",   # lee y verifica la cadena, pero no decide
}


@pytest.fixture
def entorno_auth(sandbox, monkeypatch):
    """Almacén de usuarios en el sandbox, con un usuario por rol.

    Crear los tres cuesta ~1 s por el costo de Argon2id (que es el punto de
    Argon2id), así que la fixture es por test pero el hash se calcula una sola
    vez y se reutiliza para los tres.
    """
    import siem_auth

    monkeypatch.setenv("SECRET_KEY", SECRET_KEY_DE_PRUEBA)
    monkeypatch.setenv("SIEM_USERS_FILE", str(sandbox / "users.json"))
    siem_auth.control_intentos.reset()

    hash_compartido = siem_auth.hash_password(PASSWORD_DE_PRUEBA)
    usuarios = {
        nombre: siem_auth.Usuario(
            username=nombre, rol=rol, password_hash=hash_compartido,
            activo=True, creado="2026-09-17T00:00:00+00:00")
        for nombre, rol in USUARIOS_DE_PRUEBA.items()
    }
    siem_auth.guardar_usuarios(usuarios)
    return sandbox


# ─── Dashboard Flask ─────────────────────────────────────────────────────────

@pytest.fixture
def app_dashboard(sandbox_con_incidentes, entorno_auth):
    """Recarga `dashboard` (el gateway) dentro del sandbox, con autenticación configurada.

    El módulo construye la aplicación al importarse, así que hay que recargarlo
    DESPUÉS del `chdir` y de tener SECRET_KEY en el entorno. Los servicios a los
    que llama (pipeline, audit, auth) los atiende `malla_en_proceso`.
    """
    import importlib

    import dashboard as dashboard_mod

    importlib.reload(dashboard_mod)
    dashboard_mod.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return dashboard_mod


# ⚠️  Los clientes de prueba NO se crean con `with app.test_client() as c:`.
#
# `with` activa la preservación del contexto de petición de Flask, y Flask-Login
# cachea el usuario autenticado en `g`. Con el contexto preservado en la pila, una
# petición hecha por OTRO cliente resuelve `current_user` desde ese `g` heredado:
# un cliente autenticado como `cata` (auditor) empezaba a verse como `ana`
# (analyst) apenas ana hacía una petición, y los permisos salían mal.
#
# Es un artefacto del cliente de prueba, no una fuga real de sesión — se verificó
# que sin `with` el aislamiento es perfecto, y `test_api01_autenticacion.py`
# incluye una prueba que lo vigila. Para inspeccionar la sesión de un cliente,
# usar `with cliente.session_transaction() as sesion:`.

@pytest.fixture
def client_anonimo(app_dashboard, sandbox_con_incidentes):
    """Cliente SIN sesión. Para probar que los endpoints exigen autenticación."""
    c = app_dashboard.app.test_client()
    c.sandbox = sandbox_con_incidentes  # type: ignore[attr-defined]
    return c


@pytest.fixture
def login(app_dashboard):
    """Devuelve una función que abre sesión con el usuario indicado."""

    def _login(cliente, usuario: str = "ana", password: str = PASSWORD_DE_PRUEBA):
        return cliente.post("/api/v1/login",
                            json={"username": usuario, "password": password})

    return _login


@pytest.fixture
def client(app_dashboard, sandbox_con_incidentes, login):
    """Cliente autenticado como `ana` (rol analyst): el caso de uso habitual.

    La mayoría de las pruebas verifican el comportamiento del panel, no el
    control de acceso, así que vienen con sesión iniciada. Las que prueban la
    autenticación usan `client_anonimo` o `client_como`.
    """
    c = app_dashboard.app.test_client()
    respuesta = login(c)
    assert respuesta.status_code == 200, f"no se pudo autenticar: {respuesta.data}"
    c.sandbox = sandbox_con_incidentes  # type: ignore[attr-defined]
    return c


@pytest.fixture
def client_como(app_dashboard, sandbox_con_incidentes, login):
    """Fábrica de clientes autenticados con un rol concreto.

        def test_x(client_como):
            viewer = client_como("beto")
    """

    def _cliente(usuario: str):
        c = app_dashboard.app.test_client()
        respuesta = login(c, usuario)
        assert respuesta.status_code == 200, f"no se pudo autenticar {usuario}"
        c.sandbox = sandbox_con_incidentes  # type: ignore[attr-defined]
        return c

    return _cliente


# ─── Utilidades ──────────────────────────────────────────────────────────────

@pytest.fixture
def copiar_fixture():
    """Copia un fixture NDJSON a un directorio destino (normalmente el sandbox)."""

    def _copiar(origen: Path, destino: Path) -> Path:
        destino.mkdir(parents=True, exist_ok=True)
        final = destino / origen.name
        shutil.copy(origen, final)
        return final

    return _copiar


def pytest_report_header(config) -> str:
    """Deja constancia en la salida de que la suite corre aislada."""
    del config
    return f"SIEM-IA · raíz del proyecto: {PROJECT_ROOT} · CWD real: {os.getcwd()}"
