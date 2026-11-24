// CP-REN-08 · Pico y recuperación. Requisito: RNF-RD-09.
// Verifica que tras un salto de 5 a 100 usuarios virtuales en 10 s (30 s a 5 VUs, 10 s de salto, 1 min a 100,
// caída a 5 VUs durante 1 min) el sistema vuelve a un p95 no mayor a 1,2 veces el nominal de CP-REN-01 en
// menos de 1 min después del pico, con menos de 1 % de errores.
// Precondición: malla reiniciada con 100 incidentes.
// Variables obligatorias: P95_NOM_ME, P95_NOM_INCIDENTES, P95_NOM_DECISIONES, P95_NOM_MEMORIA (p95 en ms
// de cada endpoint en CP-REN-01).
import { opcionesComunes, d, miSesion, pensar, leer, p95De, NOMBRES, transcurrido, ESCALA } from "./comun.js";
import { Trend } from "k6/metrics";

const PICO_HASTA_S = 30 + 10 + 60;   // el pico termina a los 100 s
const rec = Object.fromEntries(NOMBRES.map((n) => [n, new Trend(`t_rec_${n}`, true)]));          // 1 min tras el pico
const cubos = Array.from({ length: 6 }, (_, i) => new Trend(`t_rec_cubo${i}`, true));             // 10 s cada uno (informativo)

export const options = {
  ...opcionesComunes,
  scenarios: {
    pico: { executor: "ramping-vus", startVUs: 5, gracefulRampDown: "0s",
      stages: [{ duration: d(30), target: 5 }, { duration: d(10), target: 100 }, { duration: d(60), target: 100 },
               { duration: d(1), target: 5 }, { duration: d(59), target: 5 }] },
  },
  thresholds: {
    t_rec_me: [p95De("P95_NOM_ME", 1.2)],
    t_rec_incidentes: [p95De("P95_NOM_INCIDENTES", 1.2)],
    t_rec_decisiones: [p95De("P95_NOM_DECISIONES", 1.2)],
    t_rec_memoria: [p95De("P95_NOM_MEMORIA", 1.2)],
    http_req_failed: ["rate<0.01"],
  },
};

export default function () {
  if (!miSesion()) return;
  const desdePico = transcurrido() / ESCALA / 1000 - PICO_HASTA_S;
  for (const nombre of NOMBRES) {
    const extras = [];
    if (desdePico >= 0) {
      extras.push(rec[nombre]);
      extras.push(cubos[Math.min(5, Math.floor(desdePico / 10))]);
    }
    leer(nombre, extras);
  }
  pensar();
}
