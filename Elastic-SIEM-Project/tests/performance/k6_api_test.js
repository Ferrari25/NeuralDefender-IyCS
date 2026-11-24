import http from 'k6/http';
import { check, group } from 'k6';
import { Trend } from 'k6/metrics';
import exec from 'k6/execution';

// Pruebas de rendimiento del panel de NeuralDefender (gateway) con Grafana k6, con un PERFIL DE USO POR GRUPO
// de endpoints (plan 4.1, corrección del profesor). Característica ISO/IEC 25010: Eficiencia en el desempeño.
// Requisitos: RNF-RD-01, RNF-RD-04 y RNF-RD-09.
//
// Uso (desde Elastic-SIEM-Project/, con la malla levantada con --incidentes 100 --analistas 20 --decisiones 1400):
//   k6 run -e ESCENARIO=carga -e K6_CLAVE=... tests/performance/k6_api_test.js
//       todos los grupos EN PARALELO, cada uno con su tasa real      -> tests/performance/summary.json
//   k6 run -e ESCENARIO=estres -e GRUPO=lecturas|decisiones|login|auditoria -e K6_CLAVE=... tests/performance/k6_api_test.js
//       el estrés de UN grupo, con sus niveles propios               -> tests/performance/summary_estres_<grupo>.json
// Variables de entorno: ESCENARIO, GRUPO, BASE_URL (por defecto http://127.0.0.1:18080), K6_CLAVE (obligatoria),
// K6_PREFIJO_ANALISTA (analista), K6_ANALISTAS (20), K6_AUDITOR (auditor00) y ESCALA (solo para pruebas rápidas
// del script: acorta las duraciones; las corridas oficiales usan 1).
//
// SUPUESTOS DEL PERFIL (declarados en el plan):
//   - Refresco del panel: 15 s (app.js:1308, RF-SUP-07). La ERS, línea 720, modela 1 a 3 s: es una diferencia.
//   - Roles: analista, administrador y auditor (no hay "supervisor").
//   - Decisiones: 200 por analista por día en un turno de 8 h (ERS, línea 621) = 500 por hora con 20 analistas.
//   - Informes: 1 por analista por hora (20 por hora). Verificación de la cadena: 12 por hora (2 auditores cada 10 min);
//     como en una corrida de 4:30 no cae ninguna a esa tasa, se fuerza una verificación en la meseta.
//   - Login: ráfaga de inicio de turno de 20 inicios simultáneos (3 ráfagas durante la meseta).
//   - Estrés de lecturas y de decisiones: x2,5, x5 y x7,5 sobre la tasa nominal (50, 100 y 150 analistas).
//   - Estrés de login: 20, 50 y 100 inicios de sesión simultáneos. Estrés de auditoría: 1, 3, 5 y 10 pedidos concurrentes.
//   - Cada nivel de estrés: subida corta y meseta de 60 s.

const ESCENARIO = (__ENV.ESCENARIO || 'carga').toLowerCase();
const GRUPO = (__ENV.GRUPO || '').toLowerCase();
const BASE_URL = (__ENV.BASE_URL || 'http://127.0.0.1:18080').replace(/\/$/, '');
const CLAVE = __ENV.K6_CLAVE;
const PREFIJO = __ENV.K6_PREFIJO_ANALISTA || 'analista';
const ANALISTAS = Number(__ENV.K6_ANALISTAS || 20);
const AUDITOR = __ENV.K6_AUDITOR || 'auditor00';
const ESCALA = Number(__ENV.ESCALA || 1);
const GRUPOS_ESTRES = ['lecturas', 'decisiones', 'login', 'auditoria'];

if (!CLAVE) {
  throw new Error('Falta K6_CLAVE (la contraseña de los usuarios de la malla).');
}
if (!['carga', 'estres'].includes(ESCENARIO)) {
  throw new Error(`ESCENARIO=${ESCENARIO} no existe. Opciones: carga, estres.`);
}
if (ESCENARIO === 'estres' && !GRUPOS_ESTRES.includes(GRUPO)) {
  throw new Error(`En estrés hay que indicar GRUPO. Opciones: ${GRUPOS_ESTRES.join(', ')}.`);
}

// Métricas personalizadas para diferenciar latencias de lectura vs escritura
const decisionPostDuration = new Trend('decision_post_duration');
const incidentsGetDuration = new Trend('incidents_get_duration');
const decisionsGetDuration = new Trend('decisions_get_duration');
const memoriaGetDuration = new Trend('memoria_get_duration');
const reportesGetDuration = new Trend('reportes_get_duration');
const verifyGetDuration = new Trend('verify_get_duration');
const loginPostDuration = new Trend('login_post_duration');

// ─── Perfil: tasas nominales y niveles ──────────────────────────────────────

const REFRESCO_S = 15;                               // el panel pide los 3 GET cada 15 s por analista
const DECISIONES_POR_HORA = ANALISTAS * 200 / 8;     // 200 por analista por día, en 8 h
const INFORMES_POR_HORA = ANALISTAS;                 // 1 por analista por hora
const MULTIPLOS = [2.5, 5, 7.5];                     // niveles de estrés sobre la tasa nominal
const NIVELES_ANALISTAS = MULTIPLOS.map((m) => m * ANALISTAS);   // 50, 100 y 150 analistas equivalentes

// HORARIO: fases de cada grupo en orden. `seg` es la duración real, `objetivo` el valor al final de la fase
// (iteraciones por unidad de tiempo o usuarios virtuales, según el ejecutor). De acá salen las etapas de k6,
// la etiqueta `fase` de cada pedido y los umbrales por meseta.
const subida = (nivel, seg, objetivo) => ({ fase: `subida_${nivel}`, seg, objetivo });
const meseta = (nivel, seg, objetivo) => ({ fase: `meseta_${nivel}`, seg, objetivo });
const HORARIO = {
  carga: {
    lecturas: [subida(ANALISTAS, 30, ANALISTAS), meseta(ANALISTAS, 240, ANALISTAS)],
    decisiones: [subida(ANALISTAS, 30, DECISIONES_POR_HORA), meseta(ANALISTAS, 240, DECISIONES_POR_HORA)],
    login: [meseta(ANALISTAS, 3600, ANALISTAS)],                  // ráfagas puntuales, todas en la meseta
    auditoria: [{ fase: 'meseta_nominal', seg: 3600, objetivo: INFORMES_POR_HORA }],
    sonda: [{ fase: 'continua', seg: 3600, objetivo: 6 }],
  },
  estres: {
    lecturas: NIVELES_ANALISTAS.flatMap((n) => [subida(n, 15, n), meseta(n, 60, n)]),
    decisiones: NIVELES_ANALISTAS.flatMap((n, i) =>
      [subida(n, 15, DECISIONES_POR_HORA * MULTIPLOS[i]), meseta(n, 60, DECISIONES_POR_HORA * MULTIPLOS[i])]),
    login: [20, 50, 100].flatMap((n) => [subida(n, 10, n), meseta(n, 60, n)]),
    auditoria: [1, 3, 5, 10].flatMap((n) => [subida(n, 10, n), meseta(n, 60, n)]),
    sonda: [{ fase: 'continua', seg: 3600, objetivo: 6 }],
  },
};
const PLAN = HORARIO[ESCENARIO];
const sc = (s) => Math.max(1, Math.round(s * ESCALA));          // segundos escalados (ESCALA = 1: reales)
const etapas = (grupo) => PLAN[grupo].map((f) => ({ duration: `${sc(f.seg)}s`, target: f.objetivo }));
const duracionTotal = (grupo) => PLAN[grupo].reduce((suma, f) => suma + sc(f.seg), 0);

// ─── Escenarios ─────────────────────────────────────────────────────────────

function escenarios() {
  if (ESCENARIO === 'carga') {
    const s = {
      lecturas: { executor: 'ramping-arrival-rate', exec: 'lecturas', startRate: 0, timeUnit: `${REFRESCO_S}s`,
                  preAllocatedVUs: 30, maxVUs: 100, stages: etapas('lecturas') },
      decisiones: { executor: 'ramping-arrival-rate', exec: 'decisiones', startRate: DECISIONES_POR_HORA, timeUnit: '1h',
                    preAllocatedVUs: 5, maxVUs: 20, stages: etapas('decisiones') },
      informes: { executor: 'constant-arrival-rate', exec: 'informes', rate: INFORMES_POR_HORA, timeUnit: '1h',
                  duration: `${sc(270)}s`, preAllocatedVUs: 2, maxVUs: 5 },
      // A 12 por hora (1 cada 5 min) caen menos de 1 verificaciones en 270 s: se fuerza una, en medio de la meseta.
      verificaciones: { executor: 'shared-iterations', exec: 'verificar', vus: 1, iterations: 1,
                        startTime: `${sc(135)}s`, maxDuration: '60s' },
      sonda: { executor: 'constant-arrival-rate', exec: 'sonda', rate: 6, timeUnit: '1m',
               duration: `${sc(270)}s`, preAllocatedVUs: 1, maxVUs: 3 },
    };
    // Ráfaga de inicio de turno: 20 inicios de sesión simultáneos, 3 veces durante la meseta.
    [40, 100, 160].forEach((inicio, i) => {
      s[`login_rafaga_${i + 1}`] = { executor: 'shared-iterations', exec: 'loginRafaga', vus: ANALISTAS,
                                     iterations: ANALISTAS, startTime: `${sc(inicio)}s`, maxDuration: '60s' };
    });
    return s;
  }
  const total = `${duracionTotal(GRUPO)}s`;
  const grupo = {
    lecturas: { lecturas: { executor: 'ramping-arrival-rate', exec: 'lecturas', startRate: ANALISTAS, timeUnit: `${REFRESCO_S}s`,
                            preAllocatedVUs: 60, maxVUs: 500, stages: etapas('lecturas') } },
    decisiones: { decisiones: { executor: 'ramping-arrival-rate', exec: 'decisiones', startRate: DECISIONES_POR_HORA, timeUnit: '1h',
                                preAllocatedVUs: 20, maxVUs: 300, stages: etapas('decisiones') } },
    login: { login: { executor: 'ramping-vus', exec: 'loginContinuo', startVUs: 0, gracefulRampDown: '5s', stages: etapas('login') } },
    auditoria: { auditoria: { executor: 'ramping-vus', exec: 'auditoriaContinua', startVUs: 0, gracefulRampDown: '5s',
                              stages: etapas('auditoria') } },
  }[GRUPO];
  grupo.sonda = { executor: 'constant-arrival-rate', exec: 'sonda', rate: 6, timeUnit: '1m', duration: total,
                  preAllocatedVUs: 1, maxVUs: 3 };
  return grupo;
}

// ─── Umbrales por subserie: un p95 por grupo, endpoint y meseta ─────────────

function umbrales() {
  const u = {};
  const duracion = (grupo, endpoint, fase, limites) => {
    u[`http_req_duration{grupo:${grupo},endpoint:${endpoint},fase:${fase}}`] = limites;
  };
  const fallos = (grupo, fase) => {
    u[`http_req_failed{grupo:${grupo},fase:${fase}}`] = ['rate<0.01'];
  };
  const mesetas = (grupo) => PLAN[grupo].filter((f) => f.fase.startsWith('meseta')).map((f) => f.fase);
  const grupos = ESCENARIO === 'carga' ? ['lecturas', 'decisiones', 'login', 'auditoria'] : [GRUPO];
  for (const g of grupos) {
    for (const fase of mesetas(g)) {
      fallos(g, fase);
      if (g === 'lecturas') {
        // RNF-RD-01 (listado de incidentes < 2 s) y RNF-RD-09 (lecturas del panel < 500 ms).
        duracion(g, 'incidents', fase, ESCENARIO === 'carga' ? ['p(95)<2000', 'p(95)<500'] : ['p(95)<500']);
        duracion(g, 'decisions', fase, ['p(95)<500']);
        duracion(g, 'memoria', fase, ['p(95)<500']);
      } else if (g === 'decisiones') {
        duracion(g, 'decision', fase, ['p(95)<500']);              // RNF-RD-04
      } else if (g === 'login') {
        duracion(g, 'login', fase, ['p(95)<2000']);                // umbral interno
      } else {
        duracion(g, 'reportes', fase, ['p(95)<2000']);             // umbral interno
        duracion(g, 'verify', fase, ['p(95)<2000']);               // umbral interno
      }
    }
  }
  u['http_req_duration{grupo:sonda}'] = ['max<2000'];              // RNF-COMP-01: sondeo < 2 s
  u['http_req_failed{grupo:sonda}'] = ['rate==0'];
  return u;
}

export const options = {
  scenarios: escenarios(),
  thresholds: umbrales(),
  // Cada usuario virtual conserva su cookie de sesión entre iteraciones.
  noCookiesReset: true,
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
};

// ─── Sesión: un inicio de sesión por usuario virtual (el módulo se evalúa una vez por VU) ───

let sesion = null;   // { csrf }
let acciones = [];   // pares [incident_id, action_id] de acciones principales
let contadorDecisiones = 0;
const CABECERAS_JSON = { 'Content-Type': 'application/json' };

// Fase en la que está este pedido, según el horario del grupo y el momento en que arrancó el escenario.
function fase(grupo) {
  const t = (Date.now() - exec.scenario.startTime) / 1000;
  let acumulado = 0;
  for (const f of PLAN[grupo]) {
    acumulado += sc(f.seg);
    if (t < acumulado) return f.fase;
  }
  return PLAN[grupo][PLAN[grupo].length - 1].fase;
}

const etiquetas = (grupo, endpoint, faseActual, nombre) => ({ name: nombre, grupo, endpoint, fase: faseActual });

function iniciarSesion(usuario, etiquetasPedido) {
  const res = http.post(`${BASE_URL}/api/v1/login`, JSON.stringify({ username: usuario, password: CLAVE }), {
    headers: CABECERAS_JSON, tags: etiquetasPedido,
  });
  loginPostDuration.add(res.timings.duration);
  const ok = check(res, { 'Login status 200': (r) => r.status === 200 });
  return ok ? { csrf: res.json('csrf_token') } : null;
}

// Inicio de sesión del usuario virtual: no cuenta en ningún grupo (grupo "sesion").
function miSesion(usuario) {
  if (sesion === null) {
    sesion = iniciarSesion(usuario, etiquetas('sesion', 'login_inicial', 'inicio', 'POST /api/v1/login (inicio del VU)'));
  }
  return sesion;
}

const analistaDelVU = () => `${PREFIJO}${String((__VU - 1) % ANALISTAS).padStart(2, '0')}`;

function cargarAcciones() {
  const res = http.get(`${BASE_URL}/api/v1/incidents`, {
    tags: etiquetas('sesion', 'preparacion', 'inicio', 'GET /api/v1/incidents (preparación)'),
  });
  const pares = [];
  try {
    for (const inc of res.json('incidents') || []) {
      for (const a of inc.recommended_actions || []) {
        if (!a.alternativa_de) pares.push([inc.incident_id, a.action_id]);
      }
    }
  } catch {
    // sin incidentes no hay decisiones que registrar
  }
  return pares;
}

// ─── Grupo 1: lecturas del panel (refresco de 15 s por analista) ────────────

export function lecturas() {
  if (miSesion(analistaDelVU()) === null) return;
  const f = fase('lecturas');
  group('Lecturas del panel (refresco de 15 s)', function () {
    const pedir = (endpoint, ruta, trend, valida) => {
      const res = http.get(`${BASE_URL}${ruta}`, { tags: etiquetas('lecturas', endpoint, f, `GET ${ruta}`) });
      trend.add(res.timings.duration);
      check(res, { [`${endpoint} status 200`]: (r) => r.status === 200, [`${endpoint} estructura`]: (r) => valida(r.body) });
    };
    // El listado pesa ~1,3 MB: se comprueba sin parsearlo entero.
    pedir('incidents', '/api/v1/incidents', incidentsGetDuration, (b) => typeof b === 'string' && b.indexOf('"incidents":[') !== -1);
    pedir('decisions', '/api/v1/decisions', decisionsGetDuration, (b) => typeof b === 'string' && b.charAt(0) === '[');
    pedir('memoria', '/api/v1/memoria', memoriaGetDuration, (b) => typeof b === 'string' && b.indexOf('"lecciones":[') !== -1);
  });
}

// ─── Grupo 2: registro de decisiones ────────────────────────────────────────

export function decisiones() {
  const ses = miSesion(analistaDelVU());
  if (ses === null) return;
  if (acciones.length === 0) acciones = cargarAcciones();
  if (acciones.length === 0) return;
  const f = fase('decisiones');
  group('Registro de Decisión (POST)', function () {
    const par = acciones[Math.floor(Math.random() * acciones.length)];
    const payload = JSON.stringify({
      incident_id: par[0], action_id: par[1],
      decision: contadorDecisiones % 2 === 0 ? 'approved' : 'dismissed',   // alterna aprobar y descartar
      note: `Prueba de rendimiento VU-${__VU}-${contadorDecisiones}`,
    });
    contadorDecisiones += 1;
    const res = http.post(`${BASE_URL}/api/v1/decision`, payload, {
      headers: { ...CABECERAS_JSON, 'X-CSRFToken': ses.csrf },
      tags: etiquetas('decisiones', 'decision', f, 'POST /api/v1/decision'),
    });
    decisionPostDuration.add(res.timings.duration);
    check(res, {
      'Decisión status 201': (r) => r.status === 201,
      'Decisión confirma el registro': (r) => {
        try {
          return JSON.parse(r.body).ok === true;
        } catch {
          return false;
        }
      },
    });
  });
}

// ─── Grupo 3: inicio de sesión ──────────────────────────────────────────────

function loginUnico(f) {
  const usuario = `${PREFIJO}${String(Math.floor(Math.random() * ANALISTAS)).padStart(2, '0')}`;
  group('Inicio de Sesión (POST)', function () {
    iniciarSesion(usuario, etiquetas('login', 'login', f, 'POST /api/v1/login'));
  });
}

export function loginRafaga() {            // carga: ráfaga de inicio de turno, 20 simultáneos
  loginUnico(PLAN.login[0].fase);
}

export function loginContinuo() {          // estrés: N inicios de sesión siempre en curso (sin pausa)
  loginUnico(fase('login'));
}

// ─── Grupo 4: auditoría (informes y verificación de la cadena) ──────────────

function pedidoDeAuditoria(f, endpoint, ruta, trend) {
  const res = http.get(`${BASE_URL}${ruta}`, { tags: etiquetas('auditoria', endpoint, f, `GET ${ruta.split('?')[0]}`) });
  trend.add(res.timings.duration);
  check(res, { [`${endpoint} status 200`]: (r) => r.status === 200, [`${endpoint} con contenido`]: (r) => r.body && r.body.length > 0 });
}

export function informes() {
  if (miSesion(AUDITOR) === null) return;
  group('Informe de Auditoría (GET)', function () {
    pedidoDeAuditoria(fase('auditoria'), 'reportes', '/api/v1/reportes?formato=csv', reportesGetDuration);
  });
}

export function verificar() {
  if (miSesion(AUDITOR) === null) return;
  group('Verificación de la Cadena (GET)', function () {
    pedidoDeAuditoria(fase('auditoria'), 'verify', '/api/v1/audit/verify', verifyGetDuration);
  });
}

export function auditoriaContinua() {      // estrés: N pedidos concurrentes siempre en curso (sin pausa)
  if (miSesion(AUDITOR) === null) return;
  const f = fase('auditoria');
  group('Auditoría bajo estrés (GET)', function () {
    pedidoDeAuditoria(f, 'reportes', '/api/v1/reportes?formato=csv', reportesGetDuration);
    pedidoDeAuditoria(f, 'verify', '/api/v1/audit/verify', verifyGetDuration);
  });
}

// ─── Grupo 5: sonda de salud (como el healthcheck de Docker) ────────────────

export function sonda() {
  group('Sonda de Salud (GET)', function () {
    const res = http.get(`${BASE_URL}/api/v1/healthz`, { tags: etiquetas('sonda', 'healthz', 'continua', 'GET /api/v1/healthz') });
    check(res, { 'Sonda status 200': (r) => r.status === 200 });
  });
}

// Exportación automática del resumen al finalizar la prueba
export function handleSummary(data) {
  const archivo = ESCENARIO === 'carga' ? 'tests/performance/summary.json'
    : `tests/performance/summary_estres_${GRUPO}.json`;
  return {
    [archivo]: JSON.stringify(data, null, 4),
  };
}
