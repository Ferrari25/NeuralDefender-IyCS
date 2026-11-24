// CP-REN-01 · Línea de base (humo). Requisito: valor nominal para RNF-RD-05.
// Verifica que con 1 usuario virtual durante 30 s todas las lecturas del panel (me, incidents,
// decisions, memoria) responden 200 con la estructura esperada y sin errores. El p95 de cada
// endpoint queda registrado como valor nominal para RNF-RD-05 (CP-REN-04) y para CP-REN-08.
// Precondición: malla reiniciada con 100 incidentes (`malla.sh reiniciar --incidentes 100`).
import { opcionesComunes, d, miSesion, recorrerPanel, pensar } from "./comun.js";

export const options = {
  ...opcionesComunes,
  scenarios: { humo: { executor: "constant-vus", vus: 1, duration: d(30) } },
  thresholds: {
    checks: ["rate==1"],              // todas las peticiones responden lo esperado
    http_req_failed: ["rate==0"],     // sin errores
  },
};

export default function () {
  if (!miSesion()) return;
  recorrerPanel();
  pensar();
}
