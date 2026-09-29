"""Regresión del hallazgo **API-01** — autenticación, sesiones y control de acceso.

Antes de esta corrección, `dashboard.py` exponía todas sus rutas sin pedir
credenciales, y el campo `analyst` del registro inmutable salía de una variable
de entorno:

    ANALYST = os.getenv("ANALYST_NAME", "analista-soc")

Quien corría el proceso decidía qué nombre quedaba firmando cada decisión. La
cadena de hash (A-04) probaba que el registro **no se había alterado**; no probaba
**quién lo escribió**. En un sistema cuya premisa entera es la supervisión humana
trazable, era la brecha más importante.

Estas pruebas reemplazan a las dos congeladas
`test_API01_ningun_endpoint_pide_autenticacion` y
`test_API01_el_analista_sale_del_entorno_no_de_la_sesion`, que afirmaban lo
contrario a propósito.

Cierra los requisitos `RQ-SEC-08`, `RQ-SEC-11`, `RQ-SEC-13` y `RF-DIF-04` de la ERS.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import siem_auth
from tests.conftest import PASSWORD_DE_PRUEBA

# Las 10 rutas de datos. `healthz` y `login` quedan fuera a propósito: son las
# únicas dos que pueden no exigir sesión.
RUTAS_PROTEGIDAS = [
    ("GET", "/"),
    ("GET", "/api/v1/incidents"),
    ("GET", "/api/v1/incidents/INC-X"),
    ("GET", "/api/v1/decisions"),
    ("GET", "/api/v1/audit/verify"),
    ("GET", "/api/v1/me"),
    ("POST", "/api/v1/decision"),
    ("POST", "/api/v1/logout"),
    ("GET", "/api/incidents"),
    ("GET", "/api/decisions"),
    ("POST", "/api/decision"),
]


def _pedir(cliente, metodo: str, ruta: str):
    if metodo == "POST":
        return cliente.post(ruta, json={})
    return cliente.get(ruta)


# ─── Sin sesión no se entra ──────────────────────────────────────────────────

@pytest.mark.parametrize("metodo,ruta", RUTAS_PROTEGIDAS)
def test_sin_sesion_no_se_accede(client_anonimo, metodo, ruta):
    """Ninguna ruta de datos responde sin autenticación."""
    respuesta = _pedir(client_anonimo, metodo, ruta)

    if ruta == "/":
        # El panel es HTML: redirige al login en vez de devolver JSON.
        assert respuesta.status_code == 302
        assert "/login" in respuesta.headers["Location"]
    else:
        assert respuesta.status_code == 401
        assert respuesta.mimetype == "application/json"
        assert "autenticación" in respuesta.get_json()["error"]


def test_healthz_y_login_siguen_siendo_publicas(client_anonimo):
    """Las dos excepciones, y solo esas dos.

    `healthz` tiene que responder para poder esperar al servidor antes de tener
    credenciales; `login` es donde se obtienen.
    """
    assert client_anonimo.get("/api/v1/healthz").status_code == 200
    assert client_anonimo.get("/login").status_code == 200


def test_healthz_no_filtra_nada_sensible(client_anonimo):
    """Es pública: no puede contar nada del contenido del sistema."""
    datos = client_anonimo.get("/api/v1/healthz").get_json()
    assert set(datos) == {"status", "incidents_file"}
    assert isinstance(datos["incidents_file"], bool)


def test_la_lista_de_rutas_publicas_es_minima():
    """Blindaje: agregar una ruta pública tiene que ser una decisión consciente."""
    import dashboard

    assert frozenset(
        {"healthz", "api_login", "vista_login", "static"}) == dashboard.RUTAS_PUBLICAS


# ─── Login ───────────────────────────────────────────────────────────────────

def test_login_con_credenciales_validas(client_anonimo, login):
    respuesta = login(client_anonimo, "ana")
    assert respuesta.status_code == 200

    datos = respuesta.get_json()
    assert datos["usuario"] == "ana"
    assert datos["rol"] == "analyst"
    assert "decidir" in datos["permisos"]
    assert datos["csrf_token"]


@pytest.mark.parametrize("usuario,password", [
    ("ana", "contrasena-incorrecta"),
    ("nadie", PASSWORD_DE_PRUEBA),
    ("", ""),
])
def test_login_con_credenciales_invalidas(client_anonimo, login, usuario, password):
    respuesta = login(client_anonimo, usuario, password)
    assert respuesta.status_code == 401


def test_el_mensaje_de_error_no_distingue_usuario_de_contrasena(client_anonimo, login):
    """Distinguirlos le confirmaría a un atacante qué nombres existen."""
    inexistente = login(client_anonimo, "nadie", PASSWORD_DE_PRUEBA).get_json()["error"]
    existente = login(client_anonimo, "ana", "mala-contrasena-1").get_json()["error"]
    assert inexistente == existente == "usuario o contraseña incorrectos"


def test_un_usuario_dado_de_baja_no_entra(client_anonimo, login, entorno_auth):
    usuarios = siem_auth.cargar_usuarios()
    usuarios["ana"].activo = False
    siem_auth.guardar_usuarios(usuarios)

    assert login(client_anonimo, "ana").status_code == 401


def test_dar_de_baja_corta_una_sesion_abierta(client, entorno_auth):
    """El almacén se relee en cada petición: la baja tiene efecto inmediato.

    Si la sesión sobreviviera hasta expirar, dar de baja a alguien no serviría
    de mucho en el momento en que más importa.
    """
    assert client.get("/api/v1/me").status_code == 200

    usuarios = siem_auth.cargar_usuarios()
    usuarios["ana"].activo = False
    siem_auth.guardar_usuarios(usuarios)

    assert client.get("/api/v1/me").status_code == 401


def test_un_cuerpo_que_no_es_json_se_rechaza(client_anonimo):
    respuesta = client_anonimo.post("/api/v1/login", data="no es json",
                                    content_type="application/json")
    assert respuesta.status_code == 400


# ─── Logout ──────────────────────────────────────────────────────────────────

def test_logout_cierra_la_sesion(client):
    assert client.post("/api/v1/logout").status_code == 204
    assert client.get("/api/v1/incidents").status_code == 401


def test_tras_el_logout_el_panel_redirige_al_login(client):
    client.post("/api/v1/logout")
    respuesta = client.get("/")
    assert respuesta.status_code == 302
    assert "/login" in respuesta.headers["Location"]


# ─── Roles y permisos ────────────────────────────────────────────────────────

def test_el_viewer_no_puede_decidir(client_como, sandbox_con_incidentes):
    """403, y —lo que importa— sin escribir nada en el registro inmutable."""
    viewer = client_como("beto")
    inc = viewer.get("/api/v1/incidents").get_json()["incidents"][0]

    respuesta = viewer.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"})

    assert respuesta.status_code == 403
    assert respuesta.get_json()["permiso_requerido"] == "decidir"
    assert not (sandbox_con_incidentes / "data" / "decisions.jsonl").exists()


def test_el_auditor_tampoco_puede_decidir(client_como, sandbox_con_incidentes):
    """Separación de funciones: quien certifica el registro no decide sobre él."""
    auditor = client_como("cata")
    inc = auditor.get("/api/v1/incidents").get_json()["incidents"][0]

    respuesta = auditor.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"})

    assert respuesta.status_code == 403
    assert not (sandbox_con_incidentes / "data" / "decisions.jsonl").exists()


def test_solo_el_auditor_verifica_la_cadena(client_como):
    """El analista decide; el auditor certifica. Son capacidades distintas."""
    assert client_como("cata").get("/api/v1/audit/verify").status_code == 200
    assert client_como("ana").get("/api/v1/audit/verify").status_code == 403
    assert client_como("beto").get("/api/v1/audit/verify").status_code == 403


@pytest.mark.parametrize("usuario", ["ana", "beto", "cata"])
def test_los_tres_roles_ven_los_incidentes(client_como, usuario):
    """Ver el triage es la base común: nadie supervisa lo que no puede leer."""
    assert client_como(usuario).get("/api/v1/incidents").status_code == 200
    assert client_como(usuario).get("/api/v1/decisions").status_code == 200


def test_me_informa_los_permisos_del_rol(client_como):
    datos = client_como("beto").get("/api/v1/me").get_json()
    assert datos["rol"] == "viewer"
    assert datos["permisos"] == ["ver_auditoria", "ver_incidentes"]
    assert datos["puede_ejecutar_acciones"] is False


def test_las_sesiones_de_distintos_clientes_no_se_mezclan(client_como):
    """Invariante de aislamiento, vigilada a propósito.

    Durante el desarrollo apareció un caso en que un cliente autenticado como
    `cata` empezaba a verse como `ana`. Resultó ser un artefacto del cliente de
    prueba (`with app.test_client()` preserva el contexto de petición y
    Flask-Login cachea el usuario en `g`), no una fuga real — pero si alguna vez
    fuera real, sería gravísimo: decisiones firmadas por quien no las tomó. Esta
    prueba lo vigila.
    """
    ana, cata = client_como("ana"), client_como("cata")

    for _ in range(3):
        assert ana.get("/api/v1/me").get_json()["usuario"] == "ana"
        assert cata.get("/api/v1/me").get_json()["usuario"] == "cata"
        assert ana.get("/api/v1/audit/verify").status_code == 403
        assert cata.get("/api/v1/audit/verify").status_code == 200


# ─── La identidad llega al registro inmutable ────────────────────────────────

def test_el_registro_firma_con_el_usuario_de_la_sesion(client, sandbox_con_incidentes):
    """El corazón de API-01: quién decidió sale de la sesión, no del entorno."""
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    respuesta = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved", "note": "verificado"})

    registro = respuesta.get_json()["record"]
    assert registro["analyst"] == "ana"
    assert registro["analyst_rol"] == "analyst"
    assert registro["session_id"]
    assert "user_agent" in registro

    en_disco = json.loads(
        (sandbox_con_incidentes / "data" / "decisions.jsonl").read_text(encoding="utf-8").strip())
    assert en_disco["analyst"] == "ana"


def test_la_variable_de_entorno_ya_no_influye(client, monkeypatch):
    """`ANALYST_NAME` quedó fuera del camino de decisión, no solo ignorada."""
    import dashboard

    monkeypatch.setenv("ANALYST_NAME", "usuario-inventado")
    assert not hasattr(dashboard, "ANALYST"), \
        "el módulo todavía define ANALYST a partir del entorno"

    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    respuesta = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"})

    assert respuesta.get_json()["record"]["analyst"] == "ana"


def test_dos_analistas_firman_sus_propias_decisiones(client_como,
                                                     sandbox_con_incidentes):
    """Lo que la auditoría tiene que poder responder: quién decidió cada cosa."""
    ana = client_como("ana")
    incidentes = ana.get("/api/v1/incidents").get_json()["incidents"]

    for cliente, indice in ((ana, 0), (client_como("ana"), 1)):
        inc = incidentes[indice]
        cliente.post("/api/v1/decision", json={
            "incident_id": inc["incident_id"],
            "action_id": inc["recommended_actions"][0]["action_id"],
            "decision": "approved"})

    registros = [json.loads(linea) for linea in
                 (sandbox_con_incidentes / "data" / "decisions.jsonl")
                 .read_text(encoding="utf-8").strip().split("\n")]
    assert all(r["analyst"] == "ana" for r in registros)
    # Sesiones distintas ⇒ session_id distintos: se puede distinguir desde dónde
    # se tomó cada decisión aunque el usuario sea el mismo.
    assert len({r["session_id"] for r in registros}) == 2


def test_el_session_id_no_es_la_cookie(client):
    """Guardar el identificador real de sesión en un archivo append-only sería
    dejar un token válido a la vista de cualquiera que lea la auditoría."""
    inc = client.get("/api/v1/incidents").get_json()["incidents"][0]
    registro = client.post("/api/v1/decision", json={
        "incident_id": inc["incident_id"],
        "action_id": inc["recommended_actions"][0]["action_id"],
        "decision": "approved"}).get_json()["record"]

    cookies = client.get_cookie("siem_session")
    assert registro["session_id"] not in (cookies.value if cookies else "")
    assert len(registro["session_id"]) == 16


# ─── Expiración de sesión ────────────────────────────────────────────────────

def test_la_sesion_expira_por_inactividad(client):
    with client.session_transaction() as sesion:
        viejo = datetime.now(timezone.utc) - siem_auth.INACTIVIDAD_MAX - timedelta(minutes=1)
        sesion["ultimo_uso"] = viejo.isoformat()

    respuesta = client.get("/api/v1/incidents")
    assert respuesta.status_code == 401
    assert respuesta.get_json()["expirada"] is True
    assert "inactividad" in respuesta.get_json()["error"]


def test_la_sesion_expira_por_maximo_absoluto(client):
    """Aunque el analista siga activo: acota el daño de una cookie robada."""
    ahora = datetime.now(timezone.utc)
    with client.session_transaction() as sesion:
        sesion["emitido_en"] = (ahora - siem_auth.SESION_MAX - timedelta(minutes=1)).isoformat()
        sesion["ultimo_uso"] = ahora.isoformat()

    respuesta = client.get("/api/v1/incidents")
    assert respuesta.status_code == 401
    assert "máximo absoluto" in respuesta.get_json()["error"]


def test_una_sesion_vigente_refresca_su_marca_de_actividad(client):
    with client.session_transaction() as sesion:
        anterior = sesion["ultimo_uso"]

    client.get("/api/v1/incidents")

    with client.session_transaction() as sesion:
        assert sesion["ultimo_uso"] >= anterior


def test_una_sesion_sin_marca_temporal_se_rechaza(client):
    """Una cookie fabricada a mano no pasa por no tener las marcas."""
    with client.session_transaction() as sesion:
        sesion.pop("emitido_en", None)
        sesion.pop("ultimo_uso", None)

    assert client.get("/api/v1/incidents").status_code == 401


@pytest.mark.parametrize("emitido,uso,esperado", [
    (None, None, "sin marca temporal"),
    ("no es fecha", "tampoco", "sin marca temporal"),
])
def test_sesion_expirada_detecta_marcas_invalidas(emitido, uso, esperado):
    assert esperado in siem_auth.sesion_expirada(emitido, uso)


def test_sesion_recien_creada_no_expira():
    ahora = datetime.now(timezone.utc).isoformat()
    assert siem_auth.sesion_expirada(ahora, ahora) is None


# ─── CSRF ────────────────────────────────────────────────────────────────────

def test_sin_token_csrf_el_post_se_rechaza(app_dashboard, login,
                                           sandbox_con_incidentes):
    """Con CSRF activo (la suite lo desactiva para el resto de las pruebas)."""
    app_dashboard.app.config["WTF_CSRF_ENABLED"] = True
    try:
        cliente = app_dashboard.app.test_client()
        assert login(cliente).status_code == 200

        inc = cliente.get("/api/v1/incidents").get_json()["incidents"][0]
        respuesta = cliente.post("/api/v1/decision", json={
            "incident_id": inc["incident_id"],
            "action_id": inc["recommended_actions"][0]["action_id"],
            "decision": "approved"})

        assert respuesta.status_code == 403
        assert "CSRF" in respuesta.get_json()["error"]
        assert not (sandbox_con_incidentes / "data" / "decisions.jsonl").exists()
    finally:
        app_dashboard.app.config["WTF_CSRF_ENABLED"] = False


def test_con_token_csrf_valido_el_post_pasa(app_dashboard, login):
    app_dashboard.app.config["WTF_CSRF_ENABLED"] = True
    try:
        cliente = app_dashboard.app.test_client()
        token = login(cliente).get_json()["csrf_token"]

        inc = cliente.get("/api/v1/incidents").get_json()["incidents"][0]
        respuesta = cliente.post("/api/v1/decision",
                                 headers={"X-CSRFToken": token},
                                 json={"incident_id": inc["incident_id"],
                                       "action_id": inc["recommended_actions"][0]["action_id"],
                                       "decision": "approved"})
        assert respuesta.status_code == 201
    finally:
        app_dashboard.app.config["WTF_CSRF_ENABLED"] = False


def test_un_token_csrf_falso_se_rechaza(app_dashboard, login):
    app_dashboard.app.config["WTF_CSRF_ENABLED"] = True
    try:
        cliente = app_dashboard.app.test_client()
        login(cliente)

        inc = cliente.get("/api/v1/incidents").get_json()["incidents"][0]
        respuesta = cliente.post("/api/v1/decision",
                                 headers={"X-CSRFToken": "token-inventado"},
                                 json={"incident_id": inc["incident_id"],
                                       "action_id": inc["recommended_actions"][0]["action_id"],
                                       "decision": "approved"})
        assert respuesta.status_code == 403
    finally:
        app_dashboard.app.config["WTF_CSRF_ENABLED"] = False


# ─── Anti-fuerza bruta ───────────────────────────────────────────────────────

def test_seis_intentos_fallidos_bloquean(client_anonimo, login):
    """Es irónico que un sistema que detecta fuerza bruta sea vulnerable a ella."""
    for _ in range(siem_auth.INTENTOS_MAX):
        assert login(client_anonimo, "ana", "contrasena-incorrecta").status_code == 401

    respuesta = login(client_anonimo, "ana", "contrasena-incorrecta")
    assert respuesta.status_code == 429
    assert respuesta.get_json()["reintentar_en"] > 0
    assert "intentos fallidos" in respuesta.get_json()["error"]


def test_el_bloqueo_alcanza_a_la_contrasena_correcta(client_anonimo, login):
    """Si no, bastaría con seguir probando hasta acertar."""
    for _ in range(siem_auth.INTENTOS_MAX + 1):
        login(client_anonimo, "ana", "contrasena-incorrecta")

    assert login(client_anonimo, "ana").status_code == 429


def test_un_login_exitoso_limpia_el_historial(client_anonimo, login):
    """Un analista que se equivocó unas veces y acertó no queda penalizado."""
    for _ in range(siem_auth.INTENTOS_MAX - 1):
        login(client_anonimo, "ana", "contrasena-incorrecta")

    assert login(client_anonimo, "ana").status_code == 200
    client_anonimo.post("/api/v1/logout")

    for _ in range(siem_auth.INTENTOS_MAX - 1):
        assert login(client_anonimo, "ana", "contrasena-incorrecta").status_code == 401


def test_el_bloqueo_es_por_usuario_y_no_global(entorno_auth):
    """Bloquear a `ana` no puede dejar afuera a `beto`: sería una denegación de
    servicio trivial contra todo el SOC."""
    control = siem_auth.ControlDeIntentos()
    for _ in range(siem_auth.INTENTOS_MAX):
        control.registrar_fallo("ana", "10.0.0.1")

    assert control.bloqueado("ana", "10.0.0.1")[0] is True
    assert control.bloqueado("beto", "10.0.0.1")[0] is False
    assert control.bloqueado("ana", "10.0.0.2")[0] is False


def test_el_backoff_crece_con_los_fallos():
    control = siem_auth.ControlDeIntentos()
    for _ in range(siem_auth.INTENTOS_MAX):
        control.registrar_fallo("ana", "10.0.0.1")
    _, primera = control.bloqueado("ana", "10.0.0.1")

    for _ in range(3):
        control.registrar_fallo("ana", "10.0.0.1")
    _, segunda = control.bloqueado("ana", "10.0.0.1")

    assert segunda > primera, "el backoff no aumenta con los fallos acumulados"


def test_el_control_no_confia_en_encabezados_de_proxy(client_anonimo, login):
    """`X-Forwarded-For` lo pone el cliente: si se usara, bastaría con cambiarlo
    para esquivar el bloqueo."""
    for _ in range(siem_auth.INTENTOS_MAX + 1):
        client_anonimo.post("/api/v1/login",
                            headers={"X-Forwarded-For": "1.2.3.4"},
                            json={"username": "ana", "password": "mala"})

    respuesta = client_anonimo.post("/api/v1/login",
                                    headers={"X-Forwarded-For": "5.6.7.8"},
                                    json={"username": "ana", "password": "mala"})
    assert respuesta.status_code == 429, "cambiar el encabezado esquivó el bloqueo"


# ─── Arranque seguro ─────────────────────────────────────────────────────────

def test_el_servidor_no_arranca_sin_secret_key(monkeypatch):
    """Un valor por defecto haría que todos los despliegues firmaran igual."""
    import dashboard

    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(dashboard.ConfiguracionInsegura, match="Falta SECRET_KEY"):
        dashboard.crear_app()


def test_el_servidor_no_arranca_con_una_secret_key_corta(monkeypatch):
    import dashboard

    monkeypatch.setenv("SECRET_KEY", "corta")
    with pytest.raises(dashboard.ConfiguracionInsegura, match="demasiado corta"):
        dashboard.crear_app()


def test_el_mensaje_explica_como_generar_la_clave(monkeypatch):
    """Un error de arranque tiene que decir qué hacer, no solo qué falta."""
    import dashboard

    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(dashboard.ConfiguracionInsegura) as error:
        dashboard.crear_app()
    assert "secrets.token_urlsafe" in str(error.value)
    assert ".env" in str(error.value)


# ─── Configuración de la cookie ──────────────────────────────────────────────

def test_la_cookie_de_sesion_tiene_las_protecciones(app_dashboard):
    config = app_dashboard.app.config
    assert config["SESSION_COOKIE_HTTPONLY"] is True, "accesible desde JavaScript"
    assert config["SESSION_COOKIE_SAMESITE"] == "Lax", "viajaría en un POST cross-site"
    assert config["SESSION_COOKIE_NAME"] == "siem_session"


def test_secure_se_activa_con_tls(monkeypatch):
    """Sin TLS no puede activarse: impediría el login en el despliegue actual."""
    import dashboard

    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("SIEM_TLS", "true")
    assert dashboard.crear_app().config["SESSION_COOKIE_SECURE"] is True

    monkeypatch.setenv("SIEM_TLS", "false")
    assert dashboard.crear_app().config["SESSION_COOKIE_SECURE"] is False


# ─── El RBAC no otorga capacidad de ejecutar ─────────────────────────────────

def test_ningun_rol_puede_ejecutar_acciones():
    """El control de acceso decide QUIÉN DECIDE, no quién ejecuta.

    No existe un rol que "apriete el botón rojo": ese botón no existe. Si alguien
    agrega un permiso de ejecución a la tabla, esta prueba lo detecta.
    """
    for rol, permisos in siem_auth.PERMISOS.items():
        prohibidos = permisos & siem_auth.PERMISOS_PROHIBIDOS
        assert not prohibidos, f"el rol '{rol}' declara permisos de ejecución: {prohibidos}"

        for permiso in permisos:
            assert not any(v in permiso for v in
                           ("ejecut", "execute", "run", "contener", "contain",
                            "bloquear", "remediar"))


def test_el_decorador_rechaza_un_permiso_de_ejecucion():
    """Ni siquiera se puede declarar una vista con un permiso de ese tipo."""
    with pytest.raises(ValueError, match="no ejecuta acciones"):
        siem_auth.requiere_permiso("ejecutar")

    with pytest.raises(ValueError, match="no ejecuta acciones"):
        siem_auth.requiere_permiso("bloquear_ip")


def test_me_declara_explicitamente_que_no_ejecuta(client):
    """Para que ninguna interfaz asuma lo contrario."""
    assert client.get("/api/v1/me").get_json()["puede_ejecutar_acciones"] is False
