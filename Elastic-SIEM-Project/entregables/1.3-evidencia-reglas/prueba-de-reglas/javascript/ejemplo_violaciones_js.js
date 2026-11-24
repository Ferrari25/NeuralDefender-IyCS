// ARCHIVO DE PRUEBA: contiene violaciones intencionales. No es codigo del producto.
// El runner lo analiza con --stdin-filename services/gateway/static/..., para que eslint
// le aplique las mismas reglas que a app.js sin copiarlo dentro del producto.
const datos = window.location.hash;
const objeto = {};
const a = 1;
const b = "1";

document.getElementById("a").innerHTML = datos; // no-unsanitized/property: innerHTML con datos
document.body.insertAdjacentHTML("beforeend", datos); // no-unsanitized/method
eval(datos); // no-eval y security/detect-eval-with-expression
setTimeout("alert(1)", 10); // no-implied-eval
const f = new Function("return " + datos); // no-new-func
const cp = require("child_process"); // (sin la llamada a exec, la regla no se dispara)
cp.exec(datos); // security/detect-child-process: exec con dato no literal
const m = require(datos); // security/detect-non-literal-require
const re1 = /(a+)+$/; // security/detect-unsafe-regex (ReDoS)
const re2 = new RegExp(datos); // security/detect-non-literal-regexp (warn)
const x = objeto[datos]; // security/detect-object-injection (warn)
if (a == b) { // eqeqeq
  console.log(f, cp, m, re1, re2, x);
}
const sinUsar = 1; // no-unused-vars (warn)
