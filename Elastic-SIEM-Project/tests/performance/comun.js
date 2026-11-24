// Piezas comunes de los escenarios CP-REN-01 a CP-REN-09 (plan de pruebas de rendimiento).
//
// Se reutiliza de `neuraldefender.js` la secuencia de lectura del panel (me, incidents, decisions,
// memoria) y el modelo de carga de la ERS: cada usuario virtual refresca cada 1 a 3 s. A diferencia
// de ese script, acá CADA usuario virtual inicia sesión una vez y conserva su cookie y su token CSRF
// (el módulo se evalúa una vez por usuario virtual, así que `sesion` es propia de cada uno).
//
// Variables de entorno:
//   BASE_URL     URL del gateway (por defecto la malla: http://127.0.0.1:18080)
//   K6_CLAVE     contraseña de los usuarios de la malla (obligatoria)
//   K6_USUARIO   usuario de las lecturas y decisiones (por defecto analista00)
//   ESCALA       multiplica las duraciones (solo para probar un script rápido; las corridas usan 1)

import http from "k6/http";
import { check, fail, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";
import exec from "k6/execution";

export const BASE = (__ENV.BASE_URL || "http://127.0.0.1:18080").replace(/\/$/, "");
export const CLAVE = __ENV.K6_CLAVE;
export const USUARIO = __ENV.K6_USUARIO || "analista00";
export const ESCALA = Number(__ENV.ESCALA || 1);
export const CABECERAS = { "User-Agent": "k6-cp-ren" };
export const JSON_H = { ...CABECERAS, "Content-Type": "application/json" };

if (!CLAVE) {
  throw new Error("Falta K6_CLAVE (la contraseña de los usuarios de la malla).");
}

// Duración escalada: `d(30)` son 30 s en una corrida real.
export const d = (segundos) => `${Math.max(1, Math.round(segundos * ESCALA))}s`;
export const NOMBRES = ["me", "incidentes", "decisiones", "memoria"];

// Una tendencia por endpoint (percentiles p50, p90 y p95 salen de `summaryTrendStats`).
export const t = {
  me: new Trend("t_me", true),
  incidentes: new Trend("t_incidentes", true),
  decisiones: new Trend("t_decisiones", true),
  memoria: new Trend("t_memoria", true),
  salud: new Trend("t_salud", true),
  login: new Trend("t_login", true),
  decision: new Trend("t_decision", true),
};
// Fracción de lecturas que fallaron (código distinto de 200 o estructura inválida).
export const lecturasFallidas = new Rate("lecturas_fallidas");

export const opcionesComunes = {
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
  // Cada usuario virtual conserva su cookie de sesión entre iteraciones.
  noCookiesReset: true,
};

// ─── Sesión: una por usuario virtual ────────────────────────────────────────

let sesion = null;   // propia de cada usuario virtual

export function iniciarSesion(usuario, clave = CLAVE) {
  const r = http.post(`${BASE}/api/v1/login`, JSON.stringify({ username: usuario, password: clave }),
    { headers: JSON_H, tags: { name: "login" } });
  t.login.add(r.timings.duration);
  const ok = check(r, { "login 200": (x) => x.status === 200 });
  if (!ok) return null;
  return { usuario, csrf: r.json("csrf_token") };
}

export function miSesion(usuario = USUARIO) {
  if (sesion === null) sesion = iniciarSesion(usuario);
  return sesion;
}

// ─── Lecturas del panel ─────────────────────────────────────────────────────

// Estructura mínima de cada respuesta, comprobada sin parsear el JSON entero (el listado de 100
// incidentes pesa ~1,4 MB): el cuerpo de k6 es texto y el JSON del servidor es compacto.
const ESTRUCTURA = {
  me: (b) => b.indexOf('"usuario"') !== -1,
  incidentes: (b) => b.indexOf('"incidents":[') !== -1,
  decisiones: (b) => b.charAt(0) === "[",
  memoria: (b) => b.indexOf('"lecciones":[') !== -1,
};
const RUTAS = { me: "/api/v1/me", incidentes: "/api/v1/incidents",
                decisiones: "/api/v1/decisions", memoria: "/api/v1/memoria" };

// Una lectura. `extras` son tendencias adicionales (por escalón o fase) donde también se anota el tiempo.
export function leer(nombre, extras = []) {
  const r = http.get(`${BASE}${RUTAS[nombre]}`, { headers: CABECERAS, tags: { name: nombre } });
  t[nombre].add(r.timings.duration);
  for (const tr of extras) tr.add(r.timings.duration);
  const ok = check(r, { [`${nombre} 200`]: (x) => x.status === 200,
                        [`${nombre} estructura`]: (x) => typeof x.body === "string" && ESTRUCTURA[nombre](x.body) });
  lecturasFallidas.add(!ok);
  return { r, ok };
}

// El recorrido de lectura del panel: al abrirlo `me`, y en cada refresco `incidents`, `decisions` y `memoria`.
export function recorrerPanel(extrasPor = () => []) {
  for (const nombre of NOMBRES) leer(nombre, extrasPor(nombre));
}

export function pensar() {
  sleep((1 + Math.random() * 2) * Math.min(1, ESCALA));   // 1 a 3 s entre refrescos
}

// ─── Decisiones ─────────────────────────────────────────────────────────────

// Pares (incident_id, action_id) de acciones principales, tomados de la lista de incidentes.
export function accionesDisponibles() {
  const r = http.get(`${BASE}/api/v1/incidents`, { headers: CABECERAS, tags: { name: "incidentes_setup" } });
  const pares = [];
  for (const inc of (r.json("incidents") || [])) {
    for (const a of (inc.recommended_actions || [])) {
      if (!a.alternativa_de) pares.push([inc.incident_id, a.action_id]);
    }
  }
  return pares;
}

// Registra una decisión (aprobar o descartar) y devuelve la respuesta. 201 es lo esperado.
export function decidir(ses, par, decision, nota, extras = []) {
  const r = http.post(`${BASE}/api/v1/decision`,
    JSON.stringify({ incident_id: par[0], action_id: par[1], decision, note: nota }),
    { headers: { ...JSON_H, "X-CSRFToken": ses.csrf }, tags: { name: "decision" } });
  t.decision.add(r.timings.duration);
  for (const tr of extras) tr.add(r.timings.duration);
  const ok = check(r, { "decision 201": (x) => x.status === 201 });
  return { r, ok };
}

// ─── Ayudas de tiempo ───────────────────────────────────────────────────────

// Milisegundos desde que arrancó la prueba.
export const transcurrido = () => exec.instance.currentTestRunDuration;

// Umbral "p(95) <= X" con un valor que llega por variable de entorno (p95 de otro caso).
export function p95De(variable, multiplicador) {
  const valor = Number(__ENV[variable]);
  if (!valor) fail(`Falta ${variable} (p95 en ms de otro caso, necesario para el umbral).`);
  return `p(95)<=${(valor * multiplicador).toFixed(3)}`;
}
export { fail, sleep, check, http, exec };
