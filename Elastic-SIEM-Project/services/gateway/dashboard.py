#!/usr/bin/env python3
"""
Gateway: dashboard de supervisión humana (Flask).

Es el único servicio publicado al host (127.0.0.1:5000) y la única puerta del
navegador al sistema. Maneja la sesión, el CSRF y los permisos, y compone sus
respuestas pidiéndole los datos a los servicios internos:

  - `pipeline` — los incidentes ya analizados;
  - `audit`    — el registro append-only de decisiones (y su verificación);
  - `auth`     — quién es el usuario y qué puede hacer;
  - `knowledge` — la memoria del Agente 2 (documentos, casos y lecciones).

Cada acción recomendada tiene botones Aprobar / Descartar. La decisión se
registra en el servicio de auditoría — la IA sugiere, el humano decide, y todo
queda auditado e inmutable.

Estado de cada acción = última decisión registrada para su action_id (replay
del log append-only). Reiniciar cualquier servicio no pierde el estado.

**El dashboard nunca ejecuta nada.** Aprobar una acción registra una intención;
la ejecución la hace una persona, a mano, fuera del sistema. Certificado en
`tests/test_no_autonomy.py`.

En Docker corre con gunicorn (ver su Dockerfile). Para desarrollo:
    python3 dashboard.py     # con SIEM_<SERVICIO>_URL apuntando a cada servicio
    # luego abrir http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from werkzeug.exceptions import HTTPException

from sesion_web import (
    INACTIVIDAD_MAX,
    SESION_MAX,
    autenticar,
    cargar_usuario_de_sesion,
    ip_del_cliente,
    requiere_permiso,
    requiere_sesion,
    sesion_expirada,
    session_id_de,
)
from siem_servicios import Respuesta, ServicioNoDisponible, llamar

# API-02: tope al texto libre que entra al registro inmutable. Una nota no se
# puede corregir después, así que conviene que entre acotada.
MAX_NOTE_LEN = 500
MAX_BODY_BYTES = 64 * 1024

DECISIONES_VALIDAS = ("approved", "dismissed")

LECCION_ID_RE = re.compile(r"^LEC-[0-9a-f]{10}$")

# Rutas que no exigen sesión. Son las dos únicas que pueden no exigirla:
# `healthz` para poder esperar al servidor antes de tener credenciales, y
# `login` porque es donde se obtienen.
RUTAS_PUBLICAS = frozenset({"healthz", "api_login", "vista_login", "static"})


class ConfiguracionInsegura(RuntimeError):
    """El servidor no puede arrancar con esta configuración."""


def _secret_key() -> str:
    """Clave de firma de la cookie de sesión. Sin valor por defecto, a propósito.

    Un default haría que todos los despliegues firmaran sus cookies con la misma
    clave: cualquiera que conozca el repositorio podría fabricar una sesión
    válida. Preferimos que el servidor no arranque a que arranque inseguro.
    """
    clave = os.getenv("SECRET_KEY", "").strip()
    if not clave:
        raise ConfiguracionInsegura(
            "Falta SECRET_KEY. El panel no arranca sin una clave de firma de sesión.\n"
            "Generá una con:  python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
            "y agregala a .env como SECRET_KEY=<valor>.")
    if len(clave) < 32:
        raise ConfiguracionInsegura(
            f"SECRET_KEY es demasiado corta ({len(clave)} caracteres; mínimo 32).")
    return clave


def crear_app(secret_key: str | None = None) -> Flask:
    """Construye la aplicación. Separado para que las pruebas la instancien."""
    # `templates/` y `static/` viven al lado de este módulo, dentro del propio
    # servicio. Se pasan como rutas absolutas para no depender del CWD.
    raiz_servicio = Path(__file__).resolve().parent
    aplicacion = Flask(
        __name__,
        template_folder=str(raiz_servicio / "templates"),
        static_folder=str(raiz_servicio / "static"),
    )
    aplicacion.config.update(
        SECRET_KEY=secret_key or _secret_key(),
        MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
        # Flags de la cookie de sesión:
        SESSION_COOKIE_HTTPONLY=True,      # inaccesible desde JavaScript
        SESSION_COOKIE_SAMESITE="Lax",     # no viaja en un POST de otro sitio
        # `Secure` solo con TLS: activarlo sobre HTTP impediría el login en el
        # despliegue actual, que es loopback sin TLS (ver docs/15 §Limitaciones).
        SESSION_COOKIE_SECURE=os.getenv("SIEM_TLS", "false").lower() == "true",
        SESSION_COOKIE_NAME="siem_session",
        WTF_CSRF_TIME_LIMIT=None,          # la sesión ya tiene su propia expiración
    )
    return aplicacion


# La aplicación se construye al importar el módulo: si falta SECRET_KEY, el
# import falla con un mensaje claro en vez de arrancar con una configuración
# insegura. Es intencional que ni siquiera se pueda importar sin clave.
app = crear_app()

csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "vista_login"
login_manager.session_protection = "strong"


@login_manager.user_loader
def _cargar_usuario(username: str):
    return cargar_usuario_de_sesion(username)


@login_manager.unauthorized_handler
def _no_autenticado():
    """Sin sesión: JSON 401 para la API, redirección al login para el navegador."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "se requiere autenticación"}), 401
    return redirect(url_for("vista_login"))


@app.errorhandler(CSRFError)
def _csrf_invalido(e: CSRFError):
    """Token CSRF ausente o inválido.

    `SameSite=Lax` ya impide que un POST desde otro sitio lleve la cookie, pero
    el token es la defensa que no depende del navegador del analista.
    """
    return jsonify({"error": f"token CSRF inválido o ausente: {e.description}"}), 403


# ─── Vigencia de la sesión ───────────────────────────────────────────────────

@app.before_request
def _controlar_sesion():
    """Aplica los dos límites de expiración y refresca la marca de actividad.

    Flask-Login no expira sesiones por sí solo: la cookie vale hasta que el
    navegador la descarte. Los dos límites se llevan acá, en el propio servidor,
    para que no dependan de nada del lado del cliente.
    """
    if request.endpoint in RUTAS_PUBLICAS or not current_user.is_authenticated:
        return None

    motivo = sesion_expirada(session.get("emitido_en"), session.get("ultimo_uso"))
    if motivo:
        logout_user()
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"error": motivo, "expirada": True}), 401
        return redirect(url_for("vista_login"))

    session["ultimo_uso"] = datetime.now(timezone.utc).isoformat()
    return None


# ─── Errores: siempre JSON en la API ─────────────────────────────────────────

@app.errorhandler(HTTPException)
def _error_json(e: HTTPException):
    """API-02: un cliente que pide JSON no puede recibir el HTML de Werkzeug.

    Antes, un cuerpo malformado devolvía una página de error de 400 con
    `Content-Type: text/html` a un `fetch()` que iba a hacerle `.json()`.
    """
    if request.path.startswith("/api/"):
        return jsonify({"error": e.description, "status": e.code}), e.code
    return e


@app.errorhandler(ServicioNoDisponible)
def _servicio_caido(e: ServicioNoDisponible):
    """Un servicio interno no respondió: 503 explícito, nunca datos a medias.

    Mostrar los incidentes sin el estado de las decisiones (porque la auditoría
    no respondió) haría que acciones ya aprobadas aparezcan como pendientes.
    """
    return jsonify({"error": str(e), "status": 503}), 503


# ─── Datos de los servicios internos ─────────────────────────────────────────

def _verificada(respuesta: Respuesta, origen: str, esperados: tuple[int, ...] = (200,)) -> Respuesta:
    """Cualquier respuesta inesperada de un servicio interno es un 503.

    Recibe la respuesta ya pedida, no el destino: cada `llamar()` del gateway
    queda escrito con su servicio y su ruta literales, a la vista
    (`tests/test_no_autonomy.py` lo exige).
    """
    if respuesta.status not in esperados:
        raise ServicioNoDisponible(f"{origen} respondió {respuesta.status}")
    return respuesta


def _decisiones() -> list[dict]:
    """El registro completo de decisiones, tal como lo devuelve el servicio audit.

    Ese servicio lo lee en modo tolerante: una línea corrupta marca ese registro
    pero no deja al panel sin datos. La integridad se comprueba aparte, en
    /api/v1/audit/verify.
    """
    datos = _verificada(llamar("audit", "GET", "/v1/decisions"), "el servicio audit").datos
    return datos if isinstance(datos, list) else []


def _decision_state() -> dict[str, dict]:
    """Replay del log append-only: última decisión por action_id gana."""
    state: dict[str, dict] = {}
    for rec in _decisiones():
        aid = rec.get("action_id")
        if aid:
            state[aid] = rec
    return state


def _load_incidents() -> dict:
    """R-03: única función que trae los incidentes y les aplica el estado.

    El reporte viene del servicio pipeline y el estado de cada acción del
    servicio audit; la composición es responsabilidad del gateway.
    """
    r = _verificada(llamar("pipeline", "GET", "/v1/incidents"), "el servicio pipeline",
                    esperados=(200, 404))
    if r.status == 404:
        return {"incidents": [], "analyst_mode": None, "missing": True}

    report = r.datos
    state = _decision_state()
    for inc in report.get("incidents", []):
        for act in inc.get("recommended_actions", []):
            rec = state.get(act["action_id"])
            act["status"] = rec["decision"] if rec else "pending"
            act["decided_by"] = rec.get("analyst") if rec else None
            act["decided_at"] = rec.get("ts") if rec else None
            act["note"] = rec.get("note") if rec else None
    return report


def _indice_de_acciones(report: dict) -> dict[tuple[str, str], dict]:
    """Mapa (incident_id, action_id) → incidente, para validar un POST.

    API-04: permite rechazar una decisión sobre una acción que no existe, en vez
    de escribirla en un registro que después no se puede corregir.
    """
    return {
        (inc["incident_id"], act["action_id"]): inc
        for inc in report.get("incidents", [])
        for act in inc.get("recommended_actions", [])
    }


# ─── Sesión: login y logout ──────────────────────────────────────────────────

@app.route("/login")
def vista_login():
    """Pantalla de inicio de sesión."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("login.html", csrf_token=generate_csrf())


@app.route("/api/v1/login", methods=["POST"])
@csrf.exempt
def api_login():
    """Autentica al analista y abre la sesión.

    Exenta de CSRF a propósito: todavía no hay sesión que falsificar, y exigir un
    token antes de tener una obligaría a una petición previa solo para eso. El
    riesgo residual (forzar a alguien a iniciar sesión como otro) es bajo para un
    panel local y está documentado en docs/15 §Limitaciones.
    """
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict):
        return jsonify({"error": "se esperaba un cuerpo JSON"}), 400

    resultado = autenticar(datos.get("username"), datos.get("password"), ip_del_cliente())
    if not resultado.ok:
        respuesta = {"error": resultado.motivo}
        if resultado.no_disponible:
            return jsonify(respuesta), 503
        # 429 cuando el rechazo viene del control de intentos, no de las
        # credenciales: le dice al cliente legítimo que espere, no que se
        # equivocó de contraseña.
        if resultado.espera_segundos:
            respuesta["reintentar_en"] = resultado.espera_segundos
            return jsonify(respuesta), 429
        return jsonify(respuesta), 401

    login_user(resultado.usuario)
    ahora = datetime.now(timezone.utc).isoformat()
    session["emitido_en"] = ahora
    session["ultimo_uso"] = ahora
    session["session_id"] = session_id_de(resultado.usuario.username, ahora)

    return jsonify({
        "ok": True,
        "usuario": resultado.usuario.username,
        "rol": resultado.usuario.rol,
        "permisos": sorted(resultado.usuario.permisos),
        "csrf_token": generate_csrf(),
        "expira_por_inactividad_en_minutos": int(INACTIVIDAD_MAX.total_seconds() // 60),
        "expira_como_maximo_en_horas": int(SESION_MAX.total_seconds() // 3600),
    }), 200


@app.route("/api/v1/logout", methods=["POST"])
@login_required
def api_logout():
    logout_user()
    session.clear()
    return "", 204


@app.route("/api/v1/me")
@requiere_sesion
def api_me():
    """Quién está conectado y qué puede hacer. Lo usa el panel para la cabecera."""
    return jsonify({
        "usuario": current_user.username,
        "rol": current_user.rol,
        "permisos": sorted(current_user.permisos),
        "csrf_token": generate_csrf(),
        # Se dice explícitamente, para que ninguna interfaz asuma lo contrario.
        "puede_ejecutar_acciones": False,
    })


# ─── Vistas ──────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/v1/healthz")
def healthz():
    """Sonda de arranque, sin datos sensibles.

    La usan el runbook y las pruebas de UI para saber cuándo el server está
    listo, sin depender de que `/` renderice. El gateway responde aunque los
    servicios internos estén caídos (es su propia sonda); `incidents_file` dice
    si el pipeline ya tiene un reporte, y `false` también si no respondió.
    """
    try:
        hay_reporte = llamar("pipeline", "GET", "/v1/incidents").status == 200
    except ServicioNoDisponible:
        hay_reporte = False
    return jsonify({"status": "ok", "incidents_file": hay_reporte})


@app.route("/api/v1/incidents")
@requiere_permiso("ver_incidentes")
def api_incidents():
    respuesta = jsonify(_load_incidents())
    # API-05: datos de incidentes en vivo; que ningún proxy los cachee.
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.route("/api/v1/incidents/<incident_id>")
@requiere_permiso("ver_incidentes")
def api_incident(incident_id: str):
    report = _load_incidents()
    for inc in report.get("incidents", []):
        if inc["incident_id"] == incident_id:
            respuesta = jsonify(inc)
            respuesta.headers["Cache-Control"] = "no-store"
            return respuesta
    return jsonify({"error": f"incidente '{incident_id}' no encontrado"}), 404


@app.route("/api/v1/decision", methods=["POST"])
@requiere_permiso("decidir")
def api_decision():
    """Registra la decisión de un analista sobre una acción sugerida.

    No ejecuta nada: le pide al servicio audit que agregue una línea al
    registro append-only. Ese es todo el efecto que tiene aprobar una acción.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "se esperaba un cuerpo JSON"}), 400

    decision = data.get("decision")
    if decision not in DECISIONES_VALIDAS:
        return jsonify({"error": "decision inválida (approved|dismissed)"}), 400

    incident_id, action_id = data.get("incident_id"), data.get("action_id")
    if not isinstance(incident_id, str) or not isinstance(action_id, str) \
            or not incident_id or not action_id:
        return jsonify({"error": "faltan incident_id / action_id"}), 400

    # El chequeo de tipo va ANTES de cualquier coerción: `data.get("note") or ""`
    # convertía `[]` y `{}` en cadena vacía por ser falsy, y se colaban sin avisar.
    note = data.get("note")
    if note is None:
        note = ""
    if not isinstance(note, str):
        return jsonify({"error": "note debe ser texto"}), 400
    note = note.strip()
    if len(note) > MAX_NOTE_LEN:
        return jsonify({"error": f"note supera {MAX_NOTE_LEN} caracteres "
                                 f"({len(note)})"}), 400

    # API-04: la acción tiene que existir. Una decisión sobre un action_id
    # inventado contaminaría de forma permanente un registro inmutable.
    report = _load_incidents()
    incidente = _indice_de_acciones(report).get((incident_id, action_id))
    if incidente is None:
        return jsonify({"error": f"no existe la acción '{action_id}' en el "
                                 f"incidente '{incident_id}'"}), 404

    # Guardamos también las IPs del incidente al momento de decidir (no solo el ID).
    # El registro es append-only e inmutable, así que esto queda fijo aunque el incidente
    # ya no exista en corridas futuras — es lo que le permite al Agente 2 responder
    # "¿ya decidimos algo sobre esta IP antes?" mirando solo el registro de decisiones.
    #
    # El sello de tiempo (`ts`) lo pone el servicio audit al escribir, no el gateway.
    record = {
        "incident_id": incident_id,
        "action_id": action_id,
        "decision": decision,
        # API-01: la identidad sale de la SESIÓN AUTENTICADA, no de una variable
        # de entorno. Antes, quien corría el proceso decidía qué nombre firmaba
        # cada decisión; la cadena de hash probaba que el registro no se había
        # alterado, pero no quién lo había escrito.
        "analyst": current_user.username,
        "analyst_rol": current_user.rol,
        # Identificador DERIVADO de la sesión, no la cookie: agrupa las
        # decisiones de una misma sesión sin que sirva para suplantarla.
        "session_id": session.get("session_id"),
        "user_agent": (request.headers.get("User-Agent") or "")[:200],
        "note": note,
        "source_ip": incidente.get("source_ip"),
        "attacker_ips": incidente.get("attacker_ips") or [],
        **_contexto_para_reportes(incidente, action_id),
    }
    r = llamar("audit", "POST", "/v1/decisions", record)
    if r.status != 201:
        # El gateway ya validó todo lo que el servicio audit valida: un rechazo
        # acá indica un desacuerdo entre los dos, no un error del analista.
        motivo = (r.datos or {}).get("error") if isinstance(r.datos, dict) else None
        raise ServicioNoDisponible(f"el servicio audit rechazó la decisión "
                                   f"(HTTP {r.status}): {motivo or 'sin detalle'}")
    respuesta = {"ok": True, "record": r.datos["record"]}
    respuesta.update(_recordar_caso(incidente, action_id, decision, note))
    return jsonify(respuesta), 201


def _contexto_para_reportes(incidente: dict, action_id: str) -> dict:
    """Lo que un reporte necesita saber de la decisión, fijado al momento de decidir.

    El incidente puede no existir en la próxima corrida; el registro de
    auditoría es lo único que queda. Va el texto de la acción, nunca el comando.
    """
    analisis = incidente.get("analysis") or {}
    accion = next((a.get("accion") for a in incidente.get("recommended_actions", [])
                   if a.get("action_id") == action_id), None)
    contexto = {
        "accion": accion,
        "attack_type": (incidente.get("classification") or {}).get("attack_type"),
        "severidad": analisis.get("severidad_ajustada") or incidente.get("severity_siem"),
        "falso_positivo": analisis.get("falso_positivo_probabilidad"),
        "detection_source": incidente.get("detection_source"),
    }
    return {k: str(v)[:300] for k, v in contexto.items() if v is not None}


def _recordar_caso(incidente: dict, action_id: str, decision: str, note: str) -> dict:
    """Le pasa la decisión a la memoria del Agente 2 como un caso resuelto.

    Va DESPUÉS de la auditoría y no la condiciona: la decisión ya quedó
    registrada, que es lo que importa. Si la memoria no responde, el agente
    simplemente no aprende de este caso, y el panel lo avisa.
    """
    accion = next((a.get("accion") for a in incidente.get("recommended_actions", [])
                   if a.get("action_id") == action_id), "")
    caso = {
        "incident_id": incidente["incident_id"], "action_id": action_id, "accion": accion,
        "decision": decision, "note": note, "analyst": current_user.username,
        "attack_type": (incidente.get("classification") or {}).get("attack_type") or "desconocido",
        "severity": (incidente.get("analysis") or {}).get("severidad_ajustada") or "",
        "source_ip": incidente.get("source_ip") or "",
        "attacker_ips": incidente.get("attacker_ips") or [],
        "target_users": incidente.get("target_users") or [],
    }
    try:
        r = llamar("knowledge", "POST", "/v1/cases", caso)
    except ServicioNoDisponible:
        return {"memoria": "no_disponible"}
    if r.status != 201 or not isinstance(r.datos, dict):
        return {"memoria": "no_disponible"}
    propuestas = r.datos.get("lecciones_propuestas") or []
    for leccion in propuestas:
        # Quien propone es el sistema, pero la propuesta la disparó esta
        # decisión: queda en la actividad para que el reporte lo muestre. Si la
        # auditoría no la acepta, la decisión (ya registrada) no se deshace.
        try:
            _registrar_actividad("leccion_propuesta", leccion, actor="sistema", actor_rol="sistema")
        except ServicioNoDisponible:
            break
    return {"memoria": "registrada", "lecciones_propuestas": len(propuestas)}


@app.route("/api/v1/decisions")
@requiere_permiso("ver_auditoria")
def api_decisions():
    """Historial completo de decisiones (auditoría)."""
    respuesta = jsonify(_decisiones())
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.route("/api/v1/audit/verify")
@requiere_permiso("verificar_cadena")
def api_audit_verify():
    """Estado de la cadena de hashes del registro de auditoría (A-04)."""
    respuesta = jsonify(_verificada(llamar("audit", "GET", "/v1/decisions/verify"),
                                    "el servicio audit").datos)
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


# ─── Memoria del Agente 2 ────────────────────────────────────────────────────
#
# Lo que el agente aprende: documentos que carga un analista, y lecciones que
# el sistema propone a partir de las decisiones (o que escribe un analista).
# Toda lección necesita la aprobación de alguien con permiso para decidir antes
# de que el agente la use: la IA sugiere qué aprender, el humano decide.

def _reenviar(r: Respuesta, origen: str, esperado: int):
    """Devuelve la respuesta del servicio interno tal cual, si es la esperada o un 4xx.

    Un 400/404 de knowledge es un error del analista (texto vacío, lección que
    no existe) y se le muestra; cualquier otra cosa es un 503.
    """
    if r.status == esperado or r.status in (400, 404):
        return jsonify(r.datos), r.status
    raise ServicioNoDisponible(f"{origen} respondió {r.status}")


def _registrar_actividad(evento: str, datos: dict, actor: str | None = None,
                         actor_rol: str | None = None) -> None:
    """Deja constancia de una acción sobre la memoria en `actividad.jsonl` (audit).

    Lanza `ServicioNoDisponible` si la auditoría no la aceptó: quien llama
    decide qué decirle al analista.
    """
    registro = {
        "evento": evento,
        "actor": actor or current_user.username,
        "actor_rol": actor_rol or current_user.rol,
        "leccion_id": datos.get("leccion_id"),
        "doc_id": datos.get("doc_id"),
        "detalle": (datos.get("texto") or datos.get("titulo") or "")[:500],
        "attack_type": datos.get("attack_type"),
        "ip": datos.get("ip"),
    }
    r = llamar("audit", "POST", "/v1/activity", {k: v for k, v in registro.items() if v})
    if r.status != 201:
        raise ServicioNoDisponible(f"el servicio audit no registró la actividad (HTTP {r.status})")


def _reenviar_y_registrar(r: Respuesta, esperado: int, evento: str, clave: str):
    """Como `_reenviar`, y si la operación salió bien, la registra en la auditoría.

    La operación ya ocurrió en knowledge cuando se registra. Si la auditoría
    falla, se dice exactamente eso — no se finge que no pasó nada.
    """
    if r.status == esperado and isinstance(r.datos, dict):
        try:
            _registrar_actividad(evento, r.datos.get(clave) or {})
        except ServicioNoDisponible as e:
            raise ServicioNoDisponible(
                f"la operación se guardó en la memoria, pero no quedó en el registro "
                f"de actividad: {e}") from e
    return _reenviar(r, "el servicio knowledge", esperado)


def _cuerpo_del_panel() -> dict:
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict):
        abort(400, description="se esperaba un cuerpo JSON")
    return datos


@app.route("/api/v1/memoria")
@requiere_permiso("ver_incidentes")
def api_memoria():
    """Lecciones (en cualquier estado) y documentos cargados."""
    lecciones = _verificada(llamar("knowledge", "GET", "/v1/lessons"), "el servicio knowledge").datos
    documentos = _verificada(llamar("knowledge", "GET", "/v1/documents"), "el servicio knowledge").datos
    respuesta = jsonify({"lecciones": lecciones, "documentos": documentos})
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.route("/api/v1/memoria/documentos", methods=["POST"])
@requiere_permiso("decidir")
def api_memoria_documento():
    datos = _cuerpo_del_panel()
    r = llamar("knowledge", "POST", "/v1/documents", {
        "titulo": datos.get("titulo"), "contenido": datos.get("contenido"),
        "subido_por": current_user.username})
    return _reenviar_y_registrar(r, 201, "documento_cargado", "documento")


@app.route("/api/v1/memoria/lecciones", methods=["POST"])
@requiere_permiso("decidir")
def api_memoria_leccion():
    datos = _cuerpo_del_panel()
    r = llamar("knowledge", "POST", "/v1/lessons", {
        "texto": datos.get("texto"), "attack_type": datos.get("attack_type"),
        "ip": datos.get("ip"), "propuesta_por": current_user.username})
    return _reenviar_y_registrar(r, 201, "leccion_propuesta", "leccion")


@app.route("/api/v1/memoria/lecciones/<leccion_id>/revision", methods=["POST"])
@requiere_permiso("decidir")
def api_memoria_revision(leccion_id: str):
    if not LECCION_ID_RE.match(leccion_id):
        return jsonify({"error": "identificador de lección inválido"}), 400
    datos = _cuerpo_del_panel()
    r = llamar("knowledge", "POST", f"/v1/lessons/{quote(leccion_id, safe='')}/review", {
        "decision": datos.get("decision"), "revisor": current_user.username})
    evento = "leccion_aprobada" if datos.get("decision") == "aprobar" else "leccion_rechazada"
    return _reenviar_y_registrar(r, 200, evento, "leccion")


# ─── Reportes ────────────────────────────────────────────────────────────────

@app.route("/api/v1/reportes")
@requiere_permiso("ver_auditoria")
def api_reportes():
    """Reporte de la supervisión humana (decisiones + actividad de memoria).

    `?desde=AAAA-MM-DD&hasta=AAAA-MM-DD&formato=json|csv`. El CSV se descarga
    como archivo. Lo arma el servicio audit desde sus registros, con la
    verificación de la cadena incluida.
    """
    formato = request.args.get("formato", "json")
    consulta = urlencode({
        "formato": formato,
        "desde": request.args.get("desde") or "",
        "hasta": request.args.get("hasta") or "",
    })
    r = llamar("audit", "GET", f"/v1/reports?{consulta}")
    if r.status == 400:
        return jsonify(r.datos), 400
    datos = _verificada(r, "el servicio audit").datos
    if formato == "csv":
        periodo = datos.get("periodo") or {}
        nombre = "reporte-siem-ia_{}_{}.csv".format(periodo.get("desde") or "inicio",
                                                    periodo.get("hasta") or "hoy")
        respuesta = Response(datos["csv"], mimetype="text/csv; charset=utf-8")
        respuesta.headers["Content-Disposition"] = f'attachment; filename="{nombre}"'
    else:
        respuesta = jsonify(datos)
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


# ─── Compatibilidad con las rutas sin versionar ──────────────────────────────
#
# El panel y cualquier script existente siguen funcionando. Se mantienen como
# alias de las `/api/v1/` hasta que la Fase 3 actualice el frontend; no hay dos
# implementaciones, solo dos nombres para la misma función.

app.add_url_rule("/api/incidents", "api_incidents_compat", api_incidents)
app.add_url_rule("/api/decision", "api_decision_compat", api_decision, methods=["POST"])
app.add_url_rule("/api/decisions", "api_decisions_compat", api_decisions)


def _resumen_de_arranque() -> str:
    try:
        r = llamar("auth", "GET", "/v1/users-summary")
    except ServicioNoDisponible as e:
        return f"    ⚠️  No se pudo consultar el servicio de autenticación: {e}"
    if r.status != 200 or not isinstance(r.datos, dict):
        return f"    ⚠️  El servicio de autenticación respondió {r.status}."

    if not r.datos.get("total"):
        return ("    ⚠️  No hay usuarios. Nadie puede entrar.\n"
                "       Creá el primero con:\n"
                "       ./scripts/siem.sh usuarios crear <nombre> --rol analyst")
    por_rol = r.datos.get("activos_por_rol") or {}
    detalle = ", ".join(f"{n} {rol}" for rol, n in sorted(por_rol.items()))
    return f"    Usuarios activos: {detalle or 'ninguno'}"


if __name__ == "__main__":
    print("🛡️  Dashboard de supervisión SIEM-IA  →  http://127.0.0.1:5000")
    print("    Decisiones → servicio audit (append-only, cadena SHA-256)")
    print(_resumen_de_arranque())
    print("    La IA sugiere, el humano decide. El sistema no ejecuta ninguna acción.")
    app.run(host="127.0.0.1", port=5000, debug=False)
