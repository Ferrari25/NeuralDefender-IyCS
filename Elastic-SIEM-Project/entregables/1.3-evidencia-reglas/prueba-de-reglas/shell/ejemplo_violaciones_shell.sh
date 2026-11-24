#!/bin/bash
# ARCHIVO DE PRUEBA: contiene violaciones intencionales. No es codigo del producto.
# No declara "set -euo pipefail": sin corte ante errores (regla 5.1 de calidad; shellcheck no la detecta).
archivo=$1
rm -rf $archivo/*                          # SC2086: variable sin comillas
cd /tmp                                    # SC2164: cd sin control de error
rm *.log                                   # SC2035: glob que puede leerse como opcion
echo $(cat $archivo)                       # SC2046 y SC2086: sustitucion sin comillas
[ -f "$archivo" ] && echo si || echo no    # SC2015: A && B || C no es if/else
for f in $(ls /tmp); do echo $f; done      # SC2045 y SC2086: iterar sobre la salida de ls
