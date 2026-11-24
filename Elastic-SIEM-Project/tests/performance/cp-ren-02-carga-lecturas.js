// CP-REN-02 · Carga de lecturas. Requisito: RNF-RD-01.
// Verifica que con 20 usuarios virtuales sostenidos (subida de 30 s, 3 min, bajada de 30 s), cada
// uno refrescando el panel cada 1 a 3 s sobre 100 incidentes, GET incidents responde con p95 < 2 s,
// todas las lecturas con p95 < 500 ms y con menos de 1 % de errores.
// Precondición: malla reiniciada con 100 incidentes.
import { opcionesComunes, d, miSesion, recorrerPanel, pensar } from "./comun.js";

export const options = {
  ...opcionesComunes,
  scenarios: {
    carga: { executor: "ramping-vus", startVUs: 0, gracefulRampDown: "0s",
      stages: [{ duration: d(30), target: 20 }, { duration: d(180), target: 20 }, { duration: d(30), target: 0 }] },
  },
  thresholds: {
    t_incidentes: ["p(95)<2000", "p(95)<500"],
    t_me: ["p(95)<500"],
    t_decisiones: ["p(95)<500"],
    t_memoria: ["p(95)<500"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
};

export default function () {
  if (!miSesion()) return;
  recorrerPanel();
  pensar();
}
