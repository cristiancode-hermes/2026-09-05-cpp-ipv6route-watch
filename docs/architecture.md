# Arquitectura — ipv6route-watch

## Flujo

```
/proc/net/ipv6_route   ──► parse_route_line() ──► Snapshot.routes[]
/proc/net/if_inet6     ──► parse (addr+iface)   ──► Snapshot.addrs[]
/proc/net/rt6_stats    ──► parse_rt6_stats()    ──► (modo --rt6)
                                                       │
                                  refine_types() ◄──────┤ (set de asignadas)
                                                       ▼
                             compute_stats() → render_stats() / render_routes()
                                               render_ifaces() / render_rt6()
                                               render_json()
```

## Estructura de datos

- `Route` — dest/plen/src/src_plen/gw (arrays de 8 words), metric, refcnt, use,
  flags crudos, iface, y `type` (local/anycast/multicast/link/default/unicast/
  reject/nat/unreachable/blackhole/throw).
- `Inet6Iface` — dirección comprimida + iface del inventario `if_inet6`.
- `SnapStats` — conteos por tipo, interfaces únicas, histograma de prefijos,
  max_plen.
- `Snapshot` — `routes[]` + `addrs[]` + `stats` + fuentes.

## Parsing

- **Rutas** (`ipv6_route_seq_show`): 10 tokens separados por espacio.
  `dest plen src srcplen gw metric refcnt use flags iface`. `plen` y `src_plen`
  son **hex** (`%02x`: `80` = 128); `flags` es hex `%08x`. Las direcciones son
  32 hex sin `:` en orden de red; `compress_ipv6()` las convierte a RFC 5952.
  Filas con tipo literal en token 0 (`unreachable`/`blackhole`/`throw`/`nat`) no
  traen destino — solo plen, src, gw y el resto de columnas.
- **if_inet6**: el formato de columnas centrales varía entre kernels
  (`addr plen scope flags name` vs `... flags devflags name`); solo se usan el
  token 0 (dirección) y el último (iface), con tolerancia al resto.
- **rt6_stats**: una línea de 6 contadores `%08x` (walkers, trees,
  table_entries, rt_entries, rt_cache, discarded_routes).
- Comentarios `#` y líneas en blanco se ignoran en `--file`.

## Clasificación

`refine_types()` reconstruye el tipo de cada ruta tras cargar el snapshot:

1. Tipos literales del kernel (unreachable/blackhole/throw/nat) → se conservan.
2. Bits clásicos: `0x4000`/`0x8000` → local, `0x10000` → multicast,
   `0x20000` → anycast, `0x40000` → nat, `0x8` → reject.
3. Heurísticas de destino: `::/0` → default, `::1` → local,
   destino en el set de `if_inet6` → local, `fe80::/10` → link,
   `ff00::/8` → multicast.
4. Resto → unicast.

Esta doble vía (flags + destino) es robusta frente a kernels que imprimen
flags no documentados (p.ej. `0x80200001` para `::1/128`).

## Decisiones

- **C++23 stdlib-only**: g++ directo, cero dependencias.
- **`--demo`**: 12 rutas sintéticas (2 `::/0`, 2 local, 1 anycast, 1 multicast,
  1 link, 1 ULA, 1 on-link, 2 literales) que ejercitan todos los tipos y el
  histograma `0:4 8:2 64:3 128:3`.
- **JSON autocontenido**: `summary.types` + `routes[]` con `type` ya resuelto —
  los consumidores no necesitan re-clasificar.
- **`--no-color` paleta mutable**: las strings ANSI se vacían al parsear el
  flag, afectando a todas las vistas por igual.