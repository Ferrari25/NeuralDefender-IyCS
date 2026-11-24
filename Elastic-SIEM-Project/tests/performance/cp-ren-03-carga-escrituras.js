// CP-REN-03 · Carga de escrituras. Requisito: RNF-RD-04.
// Verifica que con 20 usuarios virtuales durante 2 min, cada uno registrando decisiones (aprobar o
// descartar, alternando, con nota) sobre acciones elegidas al azar, POST /api/v1/decision responde
// 201 con p95 < 500 ms y con menos de 1 % de errores.
// Precondición: malla reiniciada con 100 incidentes. Escribe en el registro de auditoría de la malla:
// hay que reiniciarla después.
import { opcionesComunes, d, miSesion, accionesDisponibles, decidir, pensar, exec } from "./comun.js";

export const options = {
  ...opcionesComunes,
  scenarios: { escrituras: { executor: "constant-vus", vus: 20, duration: d(120), gracefulStop: "5s" } },
  thresholds: {
    t_decision: ["p(95)<500"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
};

let acciones = null;   // por usuario virtual
let n = 0;

export default function () {
  const ses = miSesion();
  if (!ses) return;
  if (acciones === null) acciones = accionesDisponibles();
  if (!acciones.length) return;
  const par = acciones[Math.floor(Math.random() * acciones.length)];
  const decision = n % 2 === 0 ? "approved" : "dismissed";   // alterna aprobar y descartar
  decidir(ses, par, decision, `k6 CP-REN-03 vu${exec.vu.idInTest} n${n}`);
  n += 1;
  pensar();
}
