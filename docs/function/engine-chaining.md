# The detour graph and ordered chains

<!-- scope:begin -->
- paths: -
- symbols: next_hop_tag, flatten_chain, ChainLane, chain_lane_tag, build_chain_lanes
<!-- scope:end -->
Row 147: an outbound may name the outbound it dials through with xray's
`streamSettings.sockopt.dialerProxy`, sing-box's top-level `detour`, or an LxBox ordered
`type: "chain"` list. All three are one hop graph. [`engine-tagged`](engine-tagged.md) is the
one-hop socket seam this page extends; [`engine-router`](engine-router.md) chooses the outbound that
starts the graph.

## The two spellings of one edge

`next_hop_tag` reads `dialerProxy` and `detour`. They are the same edge, so a config that names both
with different tags is refused; either name is accepted alone. `parse_outbound_sockopt` turns a
top-level `detour` into the same socket options `dialerProxy` already used, so the TCP dial seam and
every UDP carrier see it without a second path. `dialer_proxy` protobuf field 9 still decodes into
the same key.

A missing hop, a self-reference, and a walk that returns to an earlier tag are startup refusals.
The refusal runs before any lane is built, so the process stops rather than a flow recursing.

## The ordered chain

An LxBox chain names `outbounds` in client-to-exit order:

```json
{"tag":"chain","type":"chain","outbounds":["first","second"]}
```

`flatten_chain` enforces the list rules before a lane exists: at least two hops, no duplicate, no
missing tag, no self-reference, and a nested chain only in the first position. A chain nested first
is replaced by its own ordered hops, in place; a nested chain anywhere else and a chain cycle are
refusals. The list is the route, so a hop's own `detour` is not carried inside the chain; the
position before it is the edge.

`build_chain_lanes` builds each leaf outbound once. The exit keeps the chain's route tag. Every
earlier hop gets a private tag, and its socket options name the hop before it. The chain's route tag
carries the exit's source, options and target strategy, so a rule that names the chain reaches the
exit with the same settings it would have had directly. The private lanes are also inserted into the
route registry, which is what lets `dial_through_proxy` resolve the next edge by tag.

The first hop's socket options are kept except for the upstream edge, which the chain list already
names. A hop that cannot relay, such as `freedom`, `blackhole`, `dns`, `loopback`, `route`, the
metrics lane or the API, is refused before the exit when it appears in an intermediate position.

## TCP and UDP

The TCP arm is the existing local-front recursion: the exit's `dial` sees its hop tag, calls
`dial_through_proxy`, and the spawned lane enters that hop's own source, socket options, target
strategy and `OutboundTag` before serving the next CONNECT. Repeating the synthetic tags walks the
list in order.

The datagram arm is the same recursion over `dial_udp_through_proxy`: the terminal freedom or carrier
lifts each destination into the named hop's UDP lane, and the hop's own options name the next hop.
A hop without a datagram lane refuses the datagram instead of falling back to the machine's route.

## Data path

```mermaid
graph TD
    C["config: dialerProxy / detour /<br/>type: chain"] --> N["next_hop_tag"]
    N --> G{"both names differ?"}
    G -- yes --> R["startup refusal"]
    G -- no --> F["flatten_chain<br/>ordered leaf hops"]
    F --> L["build_chain_lanes<br/>private tags, exit keeps route tag"]
    L --> T{"TCP?"}
    T -- yes --> D["dial_through_proxy<br/>local front, hop settings"]
    T -- no --> U["dial_udp_through_proxy<br/>SOCKS5-framed relay"]
    D --> H["next synthetic hop"]
    U --> H
    H --> X["the far end"]
```

## What was removed

- **A `detour` that started the process and was ignored.** The key now normalises into the same
  socket options as `dialerProxy`, so the existing TCP and UDP seams carry it and the cycle check
  sees it.
- **A chain that could only be spelled as a hand-written local front per flow.** The ordered list is
  flattened and built once at startup, and each hop edge is a private registry entry rather than a
  per-flow copy of the outbound.
- **A cycle that could reach the runtime recursion.** Missing, self, duplicate, nested-out-of-place
  and cyclic lists are refused before the route table is built.

What is **not** removed: each hop still pays the local-front loopback pipe on TCP and the shim's
threads and SOCKS5 framing on UDP; the chain is not a pooled carrier; and a chain whose intermediate
hop has no UDP lane refuses datagrams rather than synthesising one.

## Time

Nothing here is timed by a local run. `bench.yml` and `parity.yml` have no detour-chain cell, so
this page carries no duration and quotes none. The ordered TCP and UDP walks are gated by local
tests; the instruction, syscall and copy counts are `UNBLESSED` until an `ops.yml` artefact measures
this method, and `scripts/count-ops.sh` is CI-only on macOS/aarch64.

## Gated counts

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| syscalls-per-detour-dial | UNBLESSED | scripts/count-ops.sh |
| copies-per-detour-dial | UNBLESSED | scripts/count-ops.sh |
| seconds-per-chain-dial | UNBLESSED | CI (no chain cell yet) |
| detour-tcp-hops | 1 | ferrox-app-proxy::tests::a_detour_hop_carries_the_outbound_dial |
| ordered-tcp-hops | 2 | ferrox-app-proxy::tests::an_ordered_chain_carries_tcp_through_each_hop |
| ordered-udp-hops | 1 | ferrox-app-proxy::tests::an_ordered_chain_carries_udp_through_its_hop |
<!-- counts:end -->
