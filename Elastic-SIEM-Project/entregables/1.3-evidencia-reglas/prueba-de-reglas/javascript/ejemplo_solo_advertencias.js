// ARCHIVO DE PRUEBA: solo produce advertencias (warn), ningun error.
const objeto = {};
const clave = window.location.hash;
console.log(objeto[clave]); // security/detect-object-injection (warn)
