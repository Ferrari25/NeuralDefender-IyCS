#!/usr/bin/env python3
"""
Dashboard de supervisión humana (Flask).

Toma como entrada los incidentes ya analizados por el pipeline
(`siem_incidents.json`) y los muestra como cards al analista. Cada acción
recomendada tiene botones Aprobar / Descartar. La decisión se registra en un
log append-only (`decisions.jsonl`) — la IA sugiere, el humano decide, y todo
queda auditado e inmutable.

Estado de cada acción = última decisión registrada para su action_id (replay
del log append-only). Reiniciar el server no pierde el estado.

**El dashboard nunca ejecuta nada.** Aprobar una acción registra una intención;
la ejecución la hace una persona, a mano, fuera del sistema. Certificado en
`tests/test_no_autonomy.py`.

Uso:
    python3 dashboard.py
    # luego abrir http://127.0.0.1:5000
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from werkzeug.exceptions import HTTPException

from siem_auth import (
    INACTIVIDAD_MAX,
    PERMISOS,
    SESION_MAX,
    autenticar,
    cargar_usuario_de_sesion,
    ip_del_cliente,
    requiere_permiso,
    requiere_sesion,
    sesion_expirada,
    session_id_de,
)
from siem_lib import append_jsonl, load_json, now_iso, read_jsonl, verificar_cadena

INCIDENTS_FILE = "siem_incidents.json"
DECISIONS_FILE = "decisions.jsonl"

# API-02: tope al texto libre que entra al registro inmutable. Una nota no se
# puede corregir después, así que conviene que entre acotada.
MAX_NOTE_LEN = 500
MAX_BODY_BYTES = 64 * 1024

DECISIONES_VALIDAS = ("approved", "dismissed")

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
    aplicacion = Flask(__name__)
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


# ─── Carga de incidentes (una sola ruta de lectura) ──────────────────────────

def _decision_state() -> dict[str, dict]:
    """Replay del log append-only: última decisión por action_id gana."""
    state: dict[str, dict] = {}
    # `tolerante`: una línea corrupta marca ese registro pero no impide que el
    # panel arranque. La integridad se comprueba aparte, en /api/v1/audit/verify.
    for rec in read_jsonl(DECISIONS_FILE, tolerante=True):
        aid = rec.get("action_id")
        if aid:
            state[aid] = rec
    return state


def _load_incidents() -> dict:
    """R-03: única función que lee `siem_incidents.json` y le aplica el estado.

    Antes había dos lecturas distintas del mismo archivo con lógicas separadas:
    una acá y otra dentro de `api_decision`, que además reparseaba el archivo
    entero en cada POST solo para buscar las IPs de un incidente.
    """
    if not Path(INCIDENTS_FILE).exists():
        return {"incidents": [], "analyst_mode": None, "missing": True}

    report = load_json(INCIDENTS_FILE)
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
        "permisos": sorted(PERMISOS[resultado.usuario.rol]),
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
        "permisos": sorted(PERMISOS[current_user.rol]),
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
    listo, sin depender de que `/` renderice.
    """
    return jsonify({"status": "ok", "incidents_file": Path(INCIDENTS_FILE).exists()})


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

    No ejecuta nada: escribe una línea en el registro append-only. Ese es todo
    el efecto que tiene aprobar una acción.
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
    # "¿ya decidimos algo sobre esta IP antes?" mirando solo decisions.jsonl.
    record = {
        "ts": now_iso(),
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
    }
    escrito = append_jsonl(DECISIONS_FILE, record)
    return jsonify({"ok": True, "record": escrito}), 201


@app.route("/api/v1/decisions")
@requiere_permiso("ver_auditoria")
def api_decisions():
    """Historial completo de decisiones (auditoría)."""
    respuesta = jsonify(read_jsonl(DECISIONS_FILE, tolerante=True))
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.route("/api/v1/audit/verify")
@requiere_permiso("verificar_cadena")
def api_audit_verify():
    """Estado de la cadena de hashes del registro de auditoría (A-04)."""
    respuesta = jsonify(verificar_cadena(DECISIONS_FILE))
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
    from siem_auth import _ruta_usuarios, cargar_usuarios

    try:
        usuarios = cargar_usuarios()
    except Exception as e:  # noqa: BLE001 — cualquier problema del almacén se informa
        return f"    ⚠️  No se pudo leer el almacén de usuarios: {e}"

    if not usuarios:
        return (f"    ⚠️  No hay usuarios en '{_ruta_usuarios()}'. Nadie puede entrar.\n"
                f"       Creá el primero con:\n"
                f"       python3 manage_users.py crear <nombre> --rol analyst")
    por_rol: dict[str, int] = {}
    for u in usuarios.values():
        if u.activo:
            por_rol[u.rol] = por_rol.get(u.rol, 0) + 1
    detalle = ", ".join(f"{n} {rol}" for rol, n in sorted(por_rol.items()))
    return f"    Usuarios activos: {detalle or 'ninguno'}"


if __name__ == "__main__":
    print("🛡️  Dashboard de supervisión SIEM-IA  →  http://127.0.0.1:5000")
    print(f"    Decisiones → {DECISIONS_FILE} (append-only, cadena SHA-256)")
    print(_resumen_de_arranque())
    print("    La IA sugiere, el humano decide. El sistema no ejecuta ninguna acción.")
    app.run(host="127.0.0.1", port=5000, debug=False)
