#!/bin/bash
# ARCHIVO DE PRUEBA: sintaxis invalida (falta el fi). bash -n lo detecta sin ejecutarlo.
if [ -f "$1" ]; then
  echo "existe"
