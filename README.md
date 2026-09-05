# ipv6route-watch

Inspector de la **tabla de rutas IPv6 del kernel Linux** en C++23, zero deps.

Lee la tabla FIB IPv6 de `/proc/net/ipv6_route` (formato hex del kernel: direcciones
de 32 hex sin `:`, prefijos `%02x`, flags `%08x`), la cruza con el inventario de
direcciones asignadas de `/proc/net/if_inet6` y reporta los contadores acumulados
de `/proc/net/rt6_stats`.

## Features

- **Tabla FIB completa**: destino, prefijo (hex `80` = /128), origen, gateway,
  métrica, refcnt, flags decodificados (`UP|GATEWAY|DEFAULT|ADDRCONF|...`)
- **Tipos de ruta**: `local` (direcciones asignadas vía `if_inet6` + heuristicas),
  `default` (`::/0`), `link` (`fe80::/10`), `multicast` (`ff00::/8`), `anycast`,
  `reject`, y los tipos literales del kernel en la fila 1 (`unreachable`,
  `blackhole`, `throw`, `nat`)
- **Compresión RFC 5952** de los 32-hex del kernel a notación `::` (run de ceros
  más larga, empates → primera)
- **Resumen por tipo** + histograma de prefijos por longitud (`0:4 8:2 64:3 128:3`)
- **`--rt6`**: contadores acumulados de `fib6_table_entries`, `fib6_rt_entries`,
  `fib6_rt_cache`, `fib6_discarded_routes` (2 lecturas → delta)
- **`--ifaces`**: recuento de rutas por interfaz
- **Filtros**: `--all` (incluye host-locales de `lo`), `--top N`, `--routes`,
  `--stats`
- **Modo watch (`--watch N`)**: refresh periódico con flush por frame
- **Salida JSON (`--json`)**: `summary` + `routes[]`, claves siempre citadas
- **Demo mode (`--demo`)**: router sintético dual-stack (12 rutas, eth0/wg0/lo,
  anycast, multicast, link, 2 `::/0` y filas literales unreachable/blackhole)
- **`--file`**: parsea un dump (tolera comentarios `#` y líneas en blanco)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 51 checks (compresión, parser de filas, tipos literales, demo,
  `/proc` real, JSON parseable, --no-color, helpers)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ipv6route-watch
```

## Usage

```bash
# Snapshot único (host real)
./ipv6route-watch

# Demo (router sintético)
./ipv6route-watch --demo

# Solo resumen
./ipv6route-watch --stats

# Tabla completa (incluye rutas host-local de lo)
./ipv6route-watch --all

# Top 8 rutas
./ipv6route-watch --top 8

# Contadores rt6_stats con delta
./ipv6route-watch --rt6

# Rutas por interfaz
./ipv6route-watch --ifaces

# Parsear un dump con comentarios
./ipv6route-watch --file sample-ipv6route.table --no-color

# JSON
./ipv6route-watch --json

# Modo watch (cada 2s)
./ipv6route-watch --watch 2

# Sin colores
./ipv6route-watch --no-color

# Auto-tests
./ipv6route-watch --selftest
```

## Data Sources

| Campo | Origen |
|-------|--------|
| tabla de rutas (dest/plen/src/gw/métrica/flags/iface) | `/proc/net/ipv6_route` (`ipv6_route_seq_show`) |
| direcciones asignadas para tipar `local` | `/proc/net/if_inet6` (`inet6_if_seq_show`) |
| contadores `fib6_*` (walkers, trees, table entries, rt entries, rt cache, discarded) | `/proc/net/rt6_stats` (`ipv6_route_ioctl` / `fib6_stats`) |

## Notas

- El campo `plen` del kernel es **hex**: `80` = `/128`, `40` = `/64`, `08` = `/8`.
- Las filas `unreachable`/`blackhole`/`throw`/`nat` no imprimen destino — el
  primer token es el tipo literal; la herramienta las muestra con su nombre.
- Los flags impresos (`0x80200001` para `::1/128` en kernels recientes) varían
  entre versiones; la clasificación `local` usa el set de `if_inet6` como fuente
  primaria y los bits clásicos (`0x4000`/`0x8000`) como pista.
- `--rt6` lee el contador dos veces (300 ms) para mostrar el delta.