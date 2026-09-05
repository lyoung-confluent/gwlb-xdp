# gwlb-xdp

A PoC using XDP/eBPF to parse/redirect GENEVE traffic to/from an [AWS Gateway Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/introduction.html) (gwlb) into different [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) for each attached VPC endpoint. Essentially a kernel-mode implementation of [aws-gateway-load-balancer-tunnel-handler](https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler).

## Architecture

`gwlb-xdp` is a CLI ([main.go](main.go), commands in [cmd/](cmd)) that loads and wires up two XDP programs, then exits — packet processing happens entirely in the kernel, driven by nothing running in userspace. The programs and the maps they share are pinned under `/sys/fs/bpf/gwlb-xdp` ([bpf/maps.go](bpf/maps.go)) so they keep running (and can be found by later invocations of the CLI) after the loader process exits.

```
+----------------------------------------------------------------+
|   physical uplink (single NIC, shared by every VPC endpoint)   |
+----------------------------------------------------------------+
                |                                 ^
                | GENEVE/UDP from GWLB            | reply GENEVE/UDP to GWLB
                v                                 |
+------------------------------+  +------------------------------+
|         decap (XDP)          |  |         encap (XDP)          |
|        attached once,        |  |      attached per ENI,       |
|        on the uplink         |  |        on veth-outer         |
+------------------------------+  +------------------------------+
                |                                 ^
                | redirect via                    | redirect via
                | eni_to_ifindex;                 | flow_state
                | cache outer hdr                 | (cached outer
                | in flow_state                   | hdr replayed)
                v                                 |
+----------------------------------------------------------------+
|        veth-outer (gwlb<base58 ENI id>, default netns)         |
+----------------------------------------------------------------+
                |                                 ^
                | veth pair                       |
                | (crosses into                   |
                | the ENI's netns)                |
                v                                 |
+----------------------------------------------------------------+
|         veth-inner (same name, inside vpce-... netns)          |
|                 -> appliance / backend traffic                 |
+----------------------------------------------------------------+
```

### Two XDP programs, one shared cache

- **[decap](bpf/decap/_decap.c)** is attached once, to the physical uplink interface (`setup`). For every inbound GENEVE/UDP packet it walks the GENEVE options to pull out the AWS ENI ID, looks that up in the `eni_to_ifindex` map to find which VPC endpoint's veth pair it belongs to, strips the outer Ethernet/IP/UDP/GENEVE headers, synthesizes a new Ethernet header addressed to that veth, and redirects the bare inner packet onto it (`bpf_redirect`). Before stripping, it caches the entire outer header verbatim in `flow_state_v4`/`flow_state_v6`, keyed by the inner packet's 5-tuple plus the veth's ifindex.
- **[encap](bpf/encap/_encap.c)** is loaded once at `setup` but attached separately per ENI, to that ENI's veth-outer end (`add`). When the backend behind that veth replies, encap looks its 5-tuple up in the same `flow_state` map (swapped or literal, depending on whether the ENI is NAT/terminating or transparent — see `eni_mode` below), replays the cached outer header bytes verbatim, patches in the fields that must change per-reply (swapped src/dst IP, recomputed IPv4 checksum, total length), and redirects the packet back out the uplink toward GWLB.

Both programs are compiled from C to CO-RE-free BPF object code by [bpf2go](https://github.com/cilium/ebpf) (`go generate`, see the `//go:generate` directives in [decap.go](bpf/decap/decap.go) and [encap.go](bpf/encap/encap.go)); the generated `.o` files and Go bindings are checked in, so a normal `go build` doesn't need clang/libbpf at all — only `make generate`/`make verify` do (see [Dockerfile](Dockerfile) and [Makefile](Makefile)).

### Per-ENI isolation: one netns, one veth pair

Each attached VPC endpoint (`vpce-...`) is provisioned independently at runtime with `gwlb-xdp add <vpce-id>` ([cmd/add.go](cmd/add.go)):

1. Create a named network namespace for the VPC endpoint.
2. Create a veth pair; move one end into the new netns and rename both ends to a name derived from the AWS ENI ID (`FormatInterfaceName` in [cmd/utils.go](cmd/utils.go), a `gwlb` prefix plus the ID base58-encoded).
3. Disable TX checksum offload on the inner veth, since BPF can't compute the real L4 checksum for the netns's egress traffic — the kernel must write it before encap ever sees the packet.
4. Optionally run a `--script` hook (netns name + interface name as args) so the backend/appliance side can finish its own setup before the ENI is reachable.
5. Insert `(ENI ID → outer ifindex, inner MAC, outer MAC)` into `eni_to_ifindex` and attach the shared `encap` program to the veth-outer — this is the last step, since it's what makes the ENI live.

`gwlb-xdp remove <vpce-id>` ([cmd/remove.go](cmd/remove.go)) reverses this: detach encap, delete the veth pair (which removes both ends), delete the netns, and sweep any `flow_state`/`metrics` entries still keyed by that ENI's ifindex so a later ENI that recycles the same ifindex doesn't inherit stale cache hits. `gwlb-xdp teardown` ([cmd/teardown.go](cmd/teardown.go)) does this for every provisioned ENI, then detaches decap and removes the whole pin directory.

Namespacing each VPC endpoint this way means the appliance/backend logic behind each ENI runs in full network isolation from the others, while decap/encap — running once each, in the root context — do the actual per-ENI dispatch and caching using ifindex as the tenant key.

### Shared BPF state

All maps live in [bpf/maps.h](bpf/maps.h) (`metrics`, `flow_state_v4` and `flow_state_v6`) and [bpf/decap/_decap.c](bpf/decap/_decap.c) (`eni_to_ifindex`), pinned by name so both programs' loads resolve to the same underlying map:

| Map | Purpose |
|---|---|
| `eni_to_ifindex` | AWS ENI ID → veth-outer ifindex + synthesized L2 addressing. Sized by `--max-enis` at `setup`. |
| `flow_state_v4` / `flow_state_v6` | Inner 5-tuple (+ ifindex) → cached outer header bytes, an LRU hash so old flows age out automatically. Disabling a family (`--max-flows-v4/v6 <=1`) shrinks its map to a 1-entry placeholder and sets a `.rodata` flag so both programs drop that family's traffic before touching the map. |
| `metrics` | Per-(ifindex, counter) packet and byte counts, per-CPU, exposed by `gwlb-xdp metrics` ([cmd/metrics.go](cmd/metrics.go)) as Prometheus counters. |

Two `.rodata` knobs set at `setup` fix behavior for the life of the loaded program rather than being looked up per packet: `eni_mode` (NAT/terminating vs. transparent-appliance reply orientation) and the uplink's own MAC/ifindex (so encap can address and redirect replies without a map lookup).

### Build & deploy

[Dockerfile](Dockerfile) has three stages: `dev` (clang/llvm/libbpf/bpftool, used by `make generate` and `make verify` to rebuild the checked-in BPF objects and sanity-check them against the kernel verifier), `build` (compiles the static, CGO-free Go binary against the checked-in bindings — no BPF toolchain needed), and `final` (just that binary on `scratch`). Normal iteration only needs `go build`; the dev container is for regenerating or verifying the BPF side after editing `_decap.c`/`_encap.c`.

## Usage

```
gwlb-xdp setup <uplink-ifname>            # load decap+encap, attach decap to the uplink
gwlb-xdp add <vpce-0000000aabbccddee>     # provision one ENI: netns + veth + attach encap
gwlb-xdp remove <vpce-0000000aabbccddee>  # reverse add
gwlb-xdp teardown                         # reverse setup (and any remaining add's)
gwlb-xdp metrics                          # serve BPF packet counters as Prometheus metrics
```
