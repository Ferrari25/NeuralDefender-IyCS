// Pruebas de performance del panel de supervisión (gateway) con k6.
//
// Qué se mide: lo que hace un analista con el panel abierto. El panel consulta
// incidentes, decisiones, memoria y su sesión; de vez en cuando alguien abre un
// incidente o verifica la cadena de auditoría. Cada pedido atraviesa el gateway
// y llega por HTTP al microservicio dueño del dato (pipeline, audit, knowledge),
// así que la prueba mide la malla entera, no solo Flask.
//
// Qué NO se hace, a propósito:
//   - No se registran decisiones (POST /api/v1/decision): el registro de
//     auditoría es inmutable y quedaría lleno de decisiones falsas.
//   - No se hace login en cada iteración: Argon2id es caro A PROPÓSITO y el
//     control anti fuerza bruta bloquea al usuario. Se inicia sesión una vez en
//     setup() y todos los usuarios virtuales usan esa sesión. Para medir el login
//     está el perfil `login`, a tasa baja.
//
// Uso (ver pruebas_de_performance.md): ./scripts/pruebas_de_performance.sh [perfil]
//   PERFIL=humo|carga|estres|pico|login   (default: humo)
//   BASE_URL=http://127.0.0.1:5000  K6_USUARIO=...  K6_CLAVE=...

import http from "k6/http";
import { check, fail, group, sleep } from "k6";
import { Trend } from "k6/metrics";

const BASE = (__ENV.BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");
const PERFIL = (__ENV.PERFIL || "humo").toLowerCase();
const USUARIO = __ENV.K6_USUARIO;
const CLAVE = __ENV.K6_CLAVE;

const COOKIE = "siem_session";  // SESSION_COOKIE_NAME de dashboard.py
const CABECERAS = { "User-Agent": "k6-pruebas-de-performance" };

// Una tendencia por endpoint, para ver en el resumen cuál es el cuello de botella.
const t = {
  incidentes: new Trend("t_incidentes", true),
  incidente: new Trend("t_incidente", true),
  decisiones: new Trend("t_decisiones", true),
  memoria: new Trend("t_memoria", true),
  me: new Trend("t_me", true),
  salud: new Trend("t_salud", true),
  verificar: new Trend("t_verificar_cadena", true),
  login: new Trend("t_login", true),
};

// ─── Perfiles ────────────────────────────────────────────────────────────────
// VUs = analistas con el panel abierto. Un SOC chico tiene 1-5; `carga` usa 20
// (4x lo esperado) y `estres` sube hasta encontrar el límite.
const PERFILES = {
  humo: {
    panel: { executor: "constant-vus", vus: 1, duration: "30s" },
  },
  carga: {
    panel: {
      executor: "ramping-vus", startVUs: 0,
      stages: [
        { duration: "30s", target: 20 },
        { duration: "3m", target: 20 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  estres: {
    panel: {
      executor: "ramping-vus", startVUs: 0,
      stages: [
        { duration: "1m", target: 20 },
        { duration: "1m", target: 50 },
        { duration: "1m", target: 100 },
        { duration: "1m", target: 150 },
        { duration: "1m", target: 0 },
      ],
    },
  },
  pico: {
    panel: {
      executor: "ramping-vus", startVUs: 0,
      stages: [
        { duration: "20s", target: 5 },
        { duration: "10s", target: 100 },   // el pico: todos abren el panel a la vez
        { duration: "1m", target: 100 },
        { duration: "10s", target: 5 },
        { duration: "1m", target: 5 },      // ¿se recupera?
        { duration: "10s", target: 0 },
      ],
    },
  },
  // Login real a 1 por segundo: mide el costo de Argon2id + el registro en la
  // auditoría. Cada uno deja una entrada `login_exitoso` en accesos.jsonl.
  login: {
    login: {
      executor: "constant-arrival-rate", rate: 1, timeUnit: "1s",
      duration: "1m", preAllocatedVUs: 5, maxVUs: 20, exec: "soloLogin",
    },
  },
};

const ESCENARIOS = new Map(Object.entries(PERFILES)).get(PERFIL);
if (!ESCENARIOS) {
  throw new Error(`PERFIL=${PERFIL} no existe. Opciones: ${Object.keys(PERFILES).join(", ")}`);
}

// Umbrales: si alguno no se cumple, k6 termina con código 99 y el script falla.
// Lecturas del panel bajo 500 ms (p95) es el objetivo de respuesta de la
// interfaz; la verificación de la cadena recorre todo el registro, por eso tiene
// su propio umbral. En `estres` y `pico` los umbrales sirven para ver DÓNDE se
// rompe: que fallen es un resultado, no un error de la prueba.
const UMBRALES = {
  http_req_failed: ["rate<0.01"],
  checks: ["rate>0.99"],
  t_incidentes: ["p(95)<500"],
  t_incidente: ["p(95)<500"],
  t_decisiones: ["p(95)<500"],
  t_memoria: ["p(95)<500"],
  t_me: ["p(95)<300"],
  t_salud: ["p(95)<300"],
  t_verificar_cadena: ["p(95)<2000"],
};

export const options = {
  scenarios: ESCENARIOS,
  thresholds: PERFIL === "login" ? { http_req_failed: ["rate<0.01"], t_login: ["p(95)<2000"] }
                                 : UMBRALES,
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
  // La sesión se reparte desde setup(); que k6 no la pise con la de cada respuesta.
  noCookiesReset: true,
};

// ─── Sesión ──────────────────────────────────────────────────────────────────

function iniciarSesion() {
  if (!USUARIO || !CLAVE) {
    fail("Faltan K6_USUARIO y K6_CLAVE (un usuario de rol auditor alcanza).");
  }
  const r = http.post(`${BASE}/api/v1/login`,
    JSON.stringify({ username: USUARIO, password: CLAVE }),
    { headers: { ...CABECERAS, "Content-Type": "application/json" }, tags: { name: "login" } });
  t.login.add(r.timings.duration);
  if (r.status !== 200) {
    fail(`login falló (HTTP ${r.status}): ${r.body}`);
  }
  const cookie = r.cookies.siem_session;
  if (!cookie || !cookie.length) fail("el login no devolvió la cookie de sesión");
  return cookie[0].value;
}

export function setup() {
  const salud = http.get(`${BASE}/api/v1/healthz`, { headers: CABECERAS });
  if (salud.status !== 200) fail(`el panel no responde en ${BASE} (HTTP ${salud.status})`);
  if (PERFIL === "login") return {};

  const sesion = iniciarSesion();
  // Un incidente real para abrir el detalle; si no hay reporte, se saltea.
  const jar = http.cookieJar();
  jar.set(BASE, COOKIE, sesion);
  const r = http.get(`${BASE}/api/v1/incidents`, { headers: CABECERAS });
  let ids = [];
  try {
    ids = (r.json("incidents") || []).map((i) => i.incident_id).filter(Boolean);
  } catch {
    // sin reporte todavía: no hay incidente para abrir
  }
  return { sesion, ids };
}

// ─── Lo que hace un analista con el panel abierto ────────────────────────────

function pedir(ruta, tendencia, nombre) {
  const r = http.get(`${BASE}${ruta}`, { headers: CABECERAS, tags: { name: nombre } });
  tendencia.add(r.timings.duration);
  check(r, { [`${nombre} 200`]: (x) => x.status === 200 });
  return r;
}

export default function (datos) {
  http.cookieJar().set(BASE, COOKIE, datos.sesion);

  group("abrir el panel", () => {
    pedir("/api/v1/me", t.me, "me");
    pedir("/api/v1/incidents", t.incidentes, "incidentes");
    pedir("/api/v1/decisions", t.decisiones, "decisiones");
    pedir("/api/v1/memoria", t.memoria, "memoria");
  });

  if (datos.ids.length) {
    group("ver un incidente", () => {
      const id = datos.ids[Math.floor(Math.random() * datos.ids.length)];
      pedir(`/api/v1/incidents/${encodeURIComponent(id)}`, t.incidente, "incidente");
    });
  }

  // La verificación de la cadena es una acción ocasional del auditor (~1 de cada 10).
  if (Math.random() < 0.1) {
    group("verificar la cadena", () => {
      pedir("/api/v1/audit/verify", t.verificar, "verificar_cadena");
    });
  }

  pedir("/api/v1/healthz", t.salud, "salud");

  // Tiempo de lectura entre refrescos: 1-3 s.
  sleep(1 + Math.random() * 2);
}

export function soloLogin() {
  iniciarSesion();
}
