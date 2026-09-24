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
|        veth-outer (gxdp<base58 ENI id>, default netns)         |
+----------------------------------------------------------------+
                |                                 ^
                | veth pair                       |
                | (crosses into                   |
                | the ENI's netns)                |
                v                                 |
+----------------------------------------------------------------+
|    veth-inner (gwlb<base58 ENI id>, inside vpce-... netns)     |
|                 -> appliance / backend traffic                 |
+----------------------------------------------------------------+
```

### Two XDP programs, one shared cache

- **[decap](bpf/decap/_decap.c)** is attached once, to the physical uplink interface (`setup`). For every inbound GENEVE/UDP packet it parses GWLB's fixed 3-option GENEVE layout — ENI ID, attachment ID, flow cookie, always in that order and always that length, so no options loop is needed — to pull out the AWS ENI ID, looks that up in the `eni_to_ifindex` map to find which VPC endpoint's veth pair it belongs to, strips the outer Ethernet/IP/UDP/GENEVE headers, synthesizes a new Ethernet header addressed to that veth, and redirects the bare inner packet onto it (`bpf_redirect`). Before stripping, it caches the entire outer header in `flow_state` — with its Ethernet and IP addressing already swapped into reply orientation, and its TTL, ECN bits, DF flag and IP ID set to what a new reply datagram should carry (TTL 64, Not-ECT, DF, ID 0) rather than inherited from the request — keyed by the inner packet's 5-tuple plus the veth's ifindex. The entry is only rewritten when the flow's encapsulation actually changes (a different GWLB node, outer port or flow cookie), not on every packet. Outer IP fragments are never decapped (GWLB doesn't fragment its outer packets, and a first fragment's inner packet would be truncated). Non-first inner fragments (no L4 header to key on) and ICMP errors (which never elicit a reply) are delivered without caching anything, and an inner packet larger than one GENEVE packet on the uplink can carry — e.g. GENEVE packets GRO merged before decap ran — is dropped and counted as oversize.
- **[encap](bpf/encap/_encap.c)** is loaded once at `setup` but attached separately per ENI, to that ENI's veth-outer end (`add`). When the backend behind that veth replies, encap looks its 5-tuple up in the same `flow_state` map (swapped or literal, depending on whether the ENI is NAT/terminating or transparent — see `eni_mode` below), replays the cached outer header bytes completely unmodified — decap already pre-swapped its addressing — except for the fields that depend on this specific reply's own size (recomputed IPv4 checksum, total length), and redirects the packet back out the uplink toward GWLB. Three kinds of reply can't be matched by their own tuple and are handled specially:
  - **ICMP/ICMPv6 errors** the backend generates about a flow (port unreachable, time exceeded, packet too big, parameter problem) are matched through the packet they quote — the one decap delivered — so they go back with that flow's own GENEVE options, flow cookie included.
  - **Fragments**: a datagram's first fragment is matched normally and recorded in `frag_state`; its later fragments, which carry no L4 header, are matched through that.
  - **IPv6 Neighbor Discovery and MLD** (ICMPv6 types 130–143) between the netns and its veth are passed to the kernel, like ARP, rather than looked up.

  A reply too large to leave the uplink once encapsulated (see `max_inner_len` below) is dropped and counted as oversize rather than redirected into a silent drop.

Both programs are compiled from C to CO-RE-free BPF object code by [bpf2go](https://github.com/cilium/ebpf) (`go generate`, see the `//go:generate` directives in [decap.go](bpf/decap/decap.go) and [encap.go](bpf/encap/encap.go)); the generated `.o` files and Go bindings are checked in, so a normal `go build` doesn't need clang/libbpf at all — only `make generate`/`make verify` do (see [Dockerfile](Dockerfile) and [Makefile](Makefile)).

### Per-ENI isolation: one netns, one veth pair

Each attached VPC endpoint (`vpce-...`) is provisioned independently at runtime with `gwlb-xdp add <vpce-id>` ([cmd/add.go](cmd/add.go)). `add` refuses an ENI that's already provisioned, and if it fails partway it rolls back only what it created itself — never a veth, netns or map entry that was already there:

1. Create a named network namespace for the VPC endpoint.
2. Create a veth pair with an MTU of the uplink's MTU minus GENEVE's 68 bytes (8933 on a 9001-byte uplink) — the largest inner packet decap can deliver, since veth drops a frame over the receiving end's MTU — both ends named from the AWS ENI ID (`FormatInterfaceName` in [cmd/utils.go](cmd/utils.go)) — `gxdp<id>` for the outer end, `gwlb<id>` for the inner — and move the inner end into the new netns. Both ends get MACs derived from the ENI ID rather than the kernel's random ones (`FormatInterfaceMAC` in [cmd/utils.go](cmd/utils.go)): `02` for the outer end or `06` for the inner, then the last 10 hex digits of the VPC endpoint ID — `06:78:9a:bc:de:f0` for `vpce-0123456789abcdef0`'s inner end — so they're recognizable in a capture and stay the same across `remove`/`add`. Being explicitly assigned also keeps systemd-udevd off them: its default `MACAddressPolicy=persistent` replaces a kernel-random MAC asynchronously, which could happen after `add` has recorded it for decap.
3. Disable TX checksum offload and every segmentation/GRO offload (TSO, GSO, USO, GRO, ...) on both veth ends (`vethDisabledFeatures` in [cmd/add.go](cmd/add.go)). BPF can't compute the real L4 checksum for the netns's egress traffic, so the kernel must write it before encap ever sees the packet; and every packet crossing the veth must be a single wire-sized packet, since a GSO super-packet reaching encap would be encapsulated as one oversized frame and dropped on the way out.
4. Optionally run a `--script` hook (netns name + interface name as args) so the backend/appliance side can finish its own setup before the ENI is reachable. This is where the netns's addresses and routes belong — including the route MTU its replies need (see [MTU and offloads](#mtu-and-offloads)).
5. Read both ends' MACs — only now, since the script may set the inner end's address itself, and decap writes that address into every frame it delivers — and insert `(ENI ID → outer ifindex, inner MAC, outer MAC)` into `eni_to_ifindex` and attach the shared `encap` program to the veth-outer — this is the last step, since it's what makes the ENI live.

`gwlb-xdp remove <vpce-id>` ([cmd/remove.go](cmd/remove.go)) reverses this: delete the `eni_to_ifindex` entry, detach encap, delete the veth pair (which removes both ends), then sweep any `flow_state`/`frag_state`/`metrics` entries still keyed by that ENI's ifindex so a later ENI that recycles the same ifindex doesn't inherit stale cache hits, and finally delete the netns. The sweep comes after the veth is gone on purpose: until then, packets already in decap or encap can still write entries for that ifindex. `gwlb-xdp teardown` ([cmd/teardown.go](cmd/teardown.go)) does this for every provisioned ENI, then detaches decap and removes the whole pin directory.

Namespacing each VPC endpoint this way means the appliance/backend logic behind each ENI runs in full network isolation from the others, while decap/encap — running once each, in the root context — do the actual per-ENI dispatch and caching using ifindex as the tenant key.

`add --no-netns` skips the dedicated netns: the inner end (`gwlb<id>`) stays in the root netns alongside the outer end (`gxdp<id>`) instead of migrating — the naming is the same either way (see `FormatInterfaceName` in [cmd/utils.go](cmd/utils.go)). This only makes sense when no two ENIs on the box have overlapping backend addressing, since without separate netns nothing keeps their routing tables apart — which is also why netns isolation is the default rather than an opt-in.

### Shared BPF state

All maps live in [bpf/maps.h](bpf/maps.h) (`metrics` and `flow_state`), [bpf/decap/_decap.c](bpf/decap/_decap.c) (`eni_to_ifindex`) and [bpf/encap/_encap.c](bpf/encap/_encap.c) (`frag_state`), pinned by name so both programs' loads resolve to the same underlying map:

| Map | Purpose |
|---|---|
| `eni_to_ifindex` | AWS ENI ID → veth-outer ifindex + synthesized L2 addressing. Sized by `--max-enis` at `setup`. |
| `flow_state` | Inner 5-tuple (+ ifindex) → cached outer header bytes, one LRU hash shared by IPv4 and IPv6 flows alike (`struct flow_key`'s own family tag tells them apart) so old flows age out automatically. Sized by `--max-flows` for both families combined. Sharing one map trades away the hard per-family capacity isolation two separate maps gave — a burst of one family's flows can now evict the other's — for less space wasted on a v4 entry's unused address bytes. |
| `frag_state` | encap's in-flight reply fragment tracking: a first fragment's (addresses, protocol, fragment id) → its flow's cached outer header, so the later fragments can find it. Fixed at 16384 entries, LRU — an entry only needs to outlive one datagram. |
| `metrics` | Per-(ifindex, counter) packet and byte counts, per-CPU. Every `_bytes` counter counts full frames as they cross the uplink — encapsulated, in both directions. With `--interval` set to a positive duration, `gwlb-xdp serve` ([cmd/serve.go](cmd/serve.go)) samples this map that often and pushes how much each counter grew since the previous sample as a statsd counter (`|c`) to a statsd endpoint (the local CloudWatch agent by default), tagged with `interface` and, for ENIs, `gwlb_id`. Pushing is off by default (`--interval 0`), leaving `serve` a health-only endpoint. |

A few `.rodata` knobs set at `setup` fix behavior for the life of the loaded program rather than being looked up per packet: `eni_mode` (NAT/terminating vs. transparent-appliance reply orientation), the uplink's ifindex (so encap can redirect replies without a map lookup), `max_inner_len` in both programs — uplink MTU − 68, the largest inner packet decap delivers and encap sends — and `allowed_origin_addr`/`allowed_origin_mask`, the one GENEVE outer source IPv4 CIDR decap accepts, from `--allowed-origin-cidr`. A GENEVE packet from outside it is dropped and counted in `decap_drop_origin_not_allowed_{packets,bytes}`. The CLI requires the flag, so accepting every origin is an explicit choice (`--allowed-origin-cidr 0.0.0.0/0`, the all-zero default): otherwise anyone who can reach UDP 6081 could inject packets into an ENI's netns, or overwrite a flow's cached outer header and redirect its replies.

### Build & deploy

[Dockerfile](Dockerfile) has three stages: `dev` (clang/llvm/libbpf/bpftool, used by `make generate` and `make verify` to rebuild the checked-in BPF objects and sanity-check them against the kernel verifier), `build` (compiles the static, CGO-free Go binary against the checked-in bindings — no BPF toolchain needed), and `final` (just that binary on `scratch`). Normal iteration only needs `go build`; the dev container is for regenerating or verifying the BPF side after editing `_decap.c`/`_encap.c`.

### End-to-end test

[test/e2e](test/e2e) exercises decap and encap together without a real GWLB: it synthesizes an AWS GWLB GENEVE packet and sends it into a veth pair standing in for the physical uplink, lets `setup`/`add`'s real veths, netns and a UDP echo server (standing in for the backend) carry it end to end, and checks the GENEVE reply that comes back — verbatim outer-header replay, swapped addressing, and the echoed payload all included. A separate ICMP test (`TestICMPEcho`) checks the same round trip for a ping instead of UDP, needing no backend server at all — the kernel answers an echo request addressed to one of its own interfaces on its own. [datapath_test.go](test/e2e/datapath_test.go) covers the replies that can't be matched by their own tuple — ICMP errors, fragmented replies, Neighbor Discovery — plus both oversize drops and a TCP burst that must arrive fully segmented. It needs real netns/veth/XDP support (`CAP_NET_ADMIN`/`CAP_SYS_ADMIN`/`CAP_BPF`), so run it via:

```
make e2e
```

which runs it (and the plain unit tests) inside the same `--privileged` dev container `make verify` uses — this works both locally (Docker Desktop's Linux VM has everything needed) and in CI ([.github/workflows/e2e.yml](.github/workflows/e2e.yml)).

## Usage

```
gwlb-xdp setup --allowed-origin-cidr <gwlb-cidr> <uplink-ifname>  # load decap+encap, attach decap to the uplink
gwlb-xdp add <vpce-0000000aabbccddee>     # provision one ENI: netns + veth + attach encap
gwlb-xdp remove <vpce-0000000aabbccddee>  # reverse add
gwlb-xdp teardown                         # reverse setup (and any remaining add's)
gwlb-xdp serve                            # serve the HTTP liveness endpoint (and optionally push counters to statsd)
```

VPC endpoint IDs are accepted in AWS's current 17-hex-digit form or the legacy 8-hex-digit one (`vpce-1a2b3c4d`), in either case; the netns and statsd `gwlb_id` tag always use the canonical lowercase spelling.

`serve`'s health endpoint returns 200 only while decap is attached and the uplink it's attached to is up with carrier. Statsd counters go out in datagrams of at most 1432 bytes.

`setup`, `add`, `remove` and `teardown` take an exclusive lock on `/run/gwlb-xdp.lock`, so concurrent invocations (a provisioning system adding several ENIs at once, say) run one at a time rather than racing.

### Next-hop resolution in the netns

encap replaces a reply's whole Ethernet header with the cached outer one, so the destination MAC the netns puts on a reply never reaches the wire — but the netns's kernel still won't send the reply until it has resolved *some* neighbor entry for the next hop. Its ARP and Neighbor Discovery go out the veth into the root netns (encap passes them to the kernel), which only answers for addresses it owns itself. Unless the next hop happens to be one of those, `--script` should pin a permanent neighbor entry for it — any unicast MAC will do — alongside the route:

```
ip -n "$1" neigh replace <next hop> lladdr 02:00:00:00:00:01 dev "$2" nud permanent
```

Every destination the netns reaches directly (on-link, with no `via`) needs an entry of its own the same way, so route replies through a single next hop where possible. The e2e test does exactly this for its fake client (see `provisionENI` in [test/e2e/e2e_test.go](test/e2e/e2e_test.go)).

### MTU and offloads

GWLB's documented MTU is 8500 bytes of inner packet, but it doesn't hold what it delivers to that: it can send larger inner packets whole, and fragments a packet too large for it itself — so the fragments it creates can be larger than 8500 too. It never sends ICMP "fragmentation needed", so a DF-set reply larger than it will carry back is silently lost. That makes the two directions asymmetric:

- **Receiving: the uplink's MTU, minus 68.** decap delivers any inner packet one GENEVE packet on the uplink can carry, and `add` sets each ENI's veth MTU to the same value (8933 on a 9001-byte uplink), both taken from the uplink's MTU at `setup`/`add` time. Re-run `setup` (and re-add ENIs) if the uplink's MTU changes. `setup` warns below 8568, the least that carries GWLB's documented 8500-byte packets.
- **Sending: a route MTU of 8500 in the netns.** The veth's interface MTU is too large for replies, so the netns's routes out of it need `mtu 8500` — set by `--script` alongside the routes themselves, e.g.

  ```
  ip -n "$1" route add default via <next hop> dev "$2" mtu 8500
  ip -n "$1" route change <connected prefix> dev "$2" mtu 8500
  ```

  The kernel then picks a TCP MSS that fits (8460), fragments larger UDP datagrams itself (encap matches every fragment to its flow), and answers a forwarded DF-set packet that's too large with its own "fragmentation needed", which encap sends back to the sender. encap's own limit is only what the uplink can carry, so without the route MTU, replies of 8501–8933 bytes are encapsulated and left for GWLB to carry or lose.
- **XDP mode.** At a jumbo MTU both ENA and veth refuse native XDP for programs like these (single-buffer, no `xdp.frags`), so both programs normally run as generic XDP — after GRO. Keep UDP GRO forwarding (`rx-udp-gro-forwarding`, `rx-gro-list`) off on the uplink, or GENEVE packets can reach decap merged into one; `setup` warns if either is on, and any that get through are counted as `decap_drop_oversize`.
