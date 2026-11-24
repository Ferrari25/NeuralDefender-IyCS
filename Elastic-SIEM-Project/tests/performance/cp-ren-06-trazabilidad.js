// CP-REN-06 · Trazabilidad de los accesos y las decisiones. Requisito: RQ-SEC-27.
// Verifica que 50 usuarios virtuales inician sesión y registran 5 decisiones cada uno (50 accesos y 250
// decisiones), y que después el auditor, con el reporte de auditoría, encuentra al menos el 99 % de lo
// enviado (X_TRA >= 0,99), cada registro atribuido a su usuario, y que la cadena de hash es válida.
// Precondición: malla con `--analistas 50`. Escribe en el registro de auditoría: reiniciar después.
// La lista de lo esperado es fija (50 accesos y 250 decisiones): si un usuario virtual no logra iniciar
// sesión, falta lo que no registró y X_TRA baja.
import { check, sleep, http, exec, BASE, CABECERAS, iniciarSesion, accionesDisponibles, decidir,
         opcionesComunes, d } from "./comun.js";
import { Rate } from "k6/metrics";

const PREFIJO = __ENV.K6_PREFIJO_ANALISTA || "analista";
const AUDITOR = __ENV.K6_AUDITOR || "auditor00";
const VUS = 50, DECISIONES = 5;
const usuario = (i) => `${PREFIJO}${String(i).padStart(2, "0")}`;

const trazabilidad = new Rate("trazabilidad_x_tra");        // X_TRA = registrados / enviados
const atribucion = new Rate("atribucion_correcta");         // cada registro, a quien lo hizo
const cadenaValida = new Rate("cadena_valida");

export const options = {
  ...opcionesComunes,
  scenarios: {
    analistas: { executor: "per-vu-iterations", vus: VUS, iterations: 1, maxDuration: "2m", exec: "registrar" },
    auditor: { executor: "per-vu-iterations", vus: 1, iterations: 1, maxDuration: "1m",
               startTime: d(45), exec: "auditar" },
  },
  thresholds: {
    trazabilidad_x_tra: ["rate>=0.99"],   // X_TRA >= 0,99
    atribucion_correcta: ["rate==1"],      // cada acceso y decisión atribuido a su usuario
    cadena_valida: ["rate==1"],            // la verificación de la cadena de hash es válida
    checks: ["rate>0.99"],
  },
};

export function registrar() {
  const nombre = usuario(exec.scenario.iterationInTest);
  const ses = iniciarSesion(nombre);
  if (!ses) return;
  const acciones = accionesDisponibles();
  for (let j = 0; j < DECISIONES; j++) {
    const par = acciones[(exec.scenario.iterationInTest * DECISIONES + j) % acciones.length];
    decidir(ses, par, j % 2 === 0 ? "approved" : "dismissed", `ren06|${nombre}|${j}`);
    sleep(0.5);
  }
}

export function auditar() {
  const ses = iniciarSesion(AUDITOR);
  if (!ses) { cadenaValida.add(false); return; }
  const reporte = http.get(`${BASE}/api/v1/reportes?formato=json`, { headers: CABECERAS, tags: { name: "reporte" } });
  check(reporte, { "reporte 200": (r) => r.status === 200 });
  const datos = reporte.json();
  // Accesos: un login_exitoso por analista.
  const accesos = new Set((datos.accesos || []).filter((a) => a.evento === "login_exitoso").map((a) => a.usuario));
  for (let i = 0; i < VUS; i++) trazabilidad.add(accesos.has(usuario(i)));
  for (const a of (datos.accesos || [])) {
    if (a.evento === "login_exitoso" && /^analista\d\d$/.test(a.usuario)) atribucion.add(a.rol === "analyst");
  }
  // Decisiones: 5 por analista, identificadas por la nota `ren06|usuario|j`.
  const vistas = new Map();
  for (const x of (datos.decisiones || [])) {
    const m = /^ren06\|([^|]+)\|(\d)$/.exec(x.note || "");
    if (!m) continue;
    vistas.set(`${m[1]}|${m[2]}`, x);
    atribucion.add(x.analyst === m[1]);
  }
  for (let i = 0; i < VUS; i++) {
    for (let j = 0; j < DECISIONES; j++) trazabilidad.add(vistas.has(`${usuario(i)}|${j}`));
  }
  const verificar = http.get(`${BASE}/api/v1/audit/verify`, { headers: CABECERAS, tags: { name: "verificar_cadena" } });
  cadenaValida.add(verificar.status === 200 && verificar.json("chain_ok") === true);
  const integridad = datos.integridad || {};
  for (const k of Object.keys(integridad)) cadenaValida.add(integridad[k].chain_ok === true);
}
