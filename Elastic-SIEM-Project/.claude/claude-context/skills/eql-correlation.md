# Reglas de correlación de eventos (Event Query Language, EQL)

EQL permite expresar **secuencias** y correlación temporal — útil para ataques que se ven solo al
encadenar eventos, no en uno aislado.

## Ejemplos aplicables al proyecto

```eql
# Fuerza bruta seguida de un login exitoso desde la MISMA IP (intrusión probable)
sequence by source_ip with maxspan=10m
  [ authentication where tag == "authentication_failure" ]
  [ authentication where tag == "authentication_success" ]

# Port scan seguido de un intento de conexión al servicio descubierto
sequence by source_ip with maxspan=5m
  [ network where event_type == "network_flow" and action == "probe" ]
  [ authentication where tag == "authentication_failure" ]
```

## Cuándo conviene EQL vs. Threshold
- **Threshold** (lo que usa hoy el brute force): "N eventos del mismo tipo en T minutos". Simple y barato.
- **EQL/sequence:** cuando importa el **orden** y la **relación causal** entre eventos distintos
  (reconocimiento → acceso → movimiento lateral). Más caro, más expresivo.
