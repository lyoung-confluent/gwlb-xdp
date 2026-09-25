# gwlb-xdp

A proof of concept that uses XDP/eBPF to terminate GENEVE traffic from an [AWS Gateway Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/introduction.html) (GWLB) and hand each attached VPC endpoint's traffic to its own [Linux network namespace](https://man7.org/linux/man-pages/man7/network_namespaces.7.html). It's essentially a kernel-mode version of [aws-gateway-load-balancer-tunnel-handler](https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler).

## How it works

`gwlb-xdp` is a CLI that loads two XDP programs into the kernel, wires them up, and exits. There is no userspace process on the packet path. The programs and their shared maps are pinned under `/sys/fs/bpf/gwlb-xdp`, so they keep running after the CLI exits and later commands can find them.

- **decap** runs on the physical uplink. It receives GENEVE packets from GWLB, reads the VPC endpoint ID that GWLB puts in the GENEVE options, strips the outer headers, and redirects the inner packet to that VPC endpoint's veth pair. It also caches the outer header so the reply can reuse it.
- **encap** runs on each VPC endpoint's veth. When the backend replies, encap finds the cached outer header for that flow, puts it back on the packet, and sends the packet back out the uplink to GWLB.

```
                 physical uplink (one NIC, shared by every VPC endpoint)
                    |                                    ^
      GENEVE from   |                                    |  GENEVE reply
      GWLB          v                                    |  to GWLB
            +---------------+    flow_state cache    +---------------+
            |  decap (XDP)  | ---------------------> |  encap (XDP)  |
            |  on uplink    |   (outer header saved  |  on each veth |
            +---------------+    for the reply)      +---------------+
                    |                                    ^
      inner packet  v                                    |  reply
            +---------------------------------------------------------+
            |  veth pair per VPC endpoint                             |
            |  gxdp<id> (root netns)  <-->  gwlb<id> (vpce-... netns) |
            +---------------------------------------------------------+
                                        |
                              appliance / backend
```

Each VPC endpoint (`vpce-...`) gets its own netns and veth pair, so the backend behind each one runs fully isolated from the others. decap and encap run once in the root netns and use the veth's ifindex to tell endpoints apart.

## Usage

A typical host runs `setup` once, `add` for each VPC endpoint, and `serve` for health checks and metrics:

```
gwlb-xdp setup --allowed-origin-cidr 10.0.0.0/16 eth0
gwlb-xdp add --script /etc/gwlb-xdp/configure.sh vpce-0123456789abcdef0
gwlb-xdp serve --interval 10s
```

VPC endpoint IDs can be in AWS's current 17-hex-digit form (`vpce-0123456789abcdef0`) or the legacy 8-digit form (`vpce-1a2b3c4d`), in any case.

`setup`, `add`, `remove` and `teardown` take an exclusive lock on `/run/gwlb-xdp.lock`, so concurrent calls run one at a time instead of racing.

### `setup`

```
gwlb-xdp setup --allowed-origin-cidr <cidr> [flags] <uplink-ifname>
```

Loads decap and encap and attaches decap to the uplink interface.

- `--allowed-origin-cidr` *(required)*: only accept GENEVE packets whose outer source IPv4 address is in this CIDR (the GWLB's subnet). It's required so that accepting all traffic is an explicit choice. Without it, anyone who can reach UDP 6081 could inject packets into an endpoint's netns or hijack a flow's replies. If AWS security groups already restrict who can reach UDP 6081 on this host, you can set it to `0.0.0.0/0` and let the security group do the filtering.
- `--max-endpoints` (default `128`): maximum number of VPC endpoints on this host.
- `--max-flows` (default `1048576`): maximum number of tracked flows, IPv4 and IPv6 combined.
- `--transparent` (default `false`): treat every endpoint as a transparent appliance, so replies keep the request's 5-tuple rather than swapping it. Usually needs a larger `add --mtu`; see [MTU and offloads](#mtu-and-offloads).

### `add`

```
gwlb-xdp add [flags] <vpce-id>
```

Provisions one VPC endpoint: creates its netns and veth pair, gives the netns default routes out the veth, and attaches encap. See [What `add` does](#what-add-does) for the details.

- `--script <path>`: an executable run inside the endpoint's own netns (unless `--no-netns`), with the VPC endpoint ID and inner interface name as arguments, after the veth is up but before traffic can reach it. Use it to configure the backend side (see below).
- `--mtu` (default `8500`): MTU of the endpoint's veth pair, which caps what the backend both sends and receives. The default is GWLB's documented MTU, lowered to the uplink's limit (its MTU minus 68) if that's smaller.
- `--no-netns` (default `false`): keep the inner veth end in the root netns. Only safe if no two endpoints on the host have overlapping backend addresses. No default routes are added, since they'd replace the host's own.

`add` leaves addressing to your `--script`. It already adds IPv4 and IPv6 default routes out the inner interface, so replies reach clients outside the backend's subnet. The routes don't need a next hop: ARP is off on that interface and encap rewrites the Ethernet header anyway. For example:

```sh
#!/bin/sh
# $1 = VPC endpoint ID, $2 = inner interface name — already running inside
# the endpoint's netns, so these apply directly with no need to reach into it.
ip addr add 10.0.0.2/24 dev "$2"
```

To change a default route (to set a route MTU, say), use `ip route replace`, since `ip route add default` fails when one already exists.

The default veth MTU of 8500 keeps replies within what GWLB will carry, so no route MTU is needed. This assumes the backend terminates connections (a NAT or proxy, say). A transparent appliance (`setup --transparent`) needs a larger `--mtu`; see [MTU and offloads](#mtu-and-offloads).

### `remove`

```
gwlb-xdp remove <vpce-id>
```

Undoes `add` for one VPC endpoint, deleting its veth pair, netns and cached state. It takes no flags.

### `teardown`

```
gwlb-xdp teardown
```

Undoes `setup`: removes every endpoint still provisioned, detaches decap and deletes the pinned BPF state. It takes no flags.

### `serve`

```
gwlb-xdp serve [flags]
```

Serves an HTTP health endpoint and optionally pushes counters to statsd. It returns HTTP 200 on any path, but only while decap is attached and the uplink is up with carrier.

- `--listen` (default `:6082`): address for the HTTP health server.
- `--interval` (default `0`): how often to push counters to statsd. `0` disables pushing, leaving just the health endpoint.
- `--statsd` (default `127.0.0.1:8125`): the statsd endpoint to push to, typically the local CloudWatch agent.

With `--interval` set, `serve` reads the per-interface packet and byte counters and pushes how much each grew since the last sample to statsd as counters (`|c`). They're tagged with `interface` and, for VPC endpoints, `gwlb_id` (the lowercase VPC endpoint ID). Byte counters count full encapsulated frames as they cross the uplink, in both directions. Datagrams are at most 1432 bytes.

## Building and testing

Normal development only needs `go build`. The BPF programs are compiled from C by [bpf2go](https://github.com/cilium/ebpf), and the generated `.o` files and Go bindings are checked in.

After editing `_decap.c` or `_encap.c`, regenerate and check them against the kernel verifier inside the dev container:

```
make generate
make verify
```

The [Dockerfile](Dockerfile) has three stages:

- `dev`: clang, llvm, libbpf and bpftool, used by `make generate` and `make verify`.
- `build`: compiles a static, CGO-free Go binary against the checked-in bindings.
- `final`: just that binary on `scratch`.

### End-to-end tests

[test/e2e](test/e2e) tests decap and encap together without a real GWLB. It builds synthetic GWLB GENEVE packets, sends them into a veth pair standing in for the uplink, runs them through the real `setup`/`add` netns and veths to a UDP echo server, and checks the GENEVE reply that comes back. Other tests cover ICMP echo, ICMP errors, off-link clients, fragmented replies, Neighbor Discovery, sending without neighbor resolution, oversize drops, and TCP segmentation ([datapath_test.go](test/e2e/datapath_test.go)).

The tests need real netns, veth and XDP support (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_BPF`), so run them in the privileged dev container:

```
make e2e
```

This works locally (Docker Desktop's Linux VM has everything needed) and in CI ([.github/workflows/e2e.yml](.github/workflows/e2e.yml)). It runs the unit tests too.

---

## Technical reference

The rest of this document covers the datapath in detail.

### Code layout

- [main.go](main.go) and [cmd/](cmd): the CLI.
- [bpf/decap/_decap.c](bpf/decap/_decap.c): the decap XDP program and the `vpce_to_ifindex` map.
- [bpf/encap/_encap.c](bpf/encap/_encap.c): the encap XDP program and the `frag_state` map.
- [bpf/maps.h](bpf/maps.h): the shared `flow_state` and `metrics` maps.
- [bpf/maps.go](bpf/maps.go): map pinning under `/sys/fs/bpf/gwlb-xdp`.

### decap

decap is attached once to the uplink by `setup`. For each GENEVE/UDP packet it:

1. Drops the packet if its outer source isn't in `--allowed-origin-cidr`, counting it in `decap_drop_origin_not_allowed_{packets,bytes}`.
2. Parses GWLB's GENEVE options. GWLB always sends the same three options in the same order and at the same length (VPC endpoint ID, attachment ID, flow cookie), so no options loop is needed.
3. Looks up the VPC endpoint ID in `vpce_to_ifindex` to find the endpoint's veth.
4. Caches the outer header in `flow_state`, keyed by the inner packet's 5-tuple plus the veth's ifindex. The cached copy is already in reply form: Ethernet and IP addresses are swapped, and TTL, ECN, DF and IP ID are set to what a new reply should carry (TTL 64, Not-ECT, DF, ID 0) instead of being copied from the request. The entry is only rewritten when the flow's encapsulation changes (a different GWLB node, outer port or flow cookie), not on every packet.
5. Strips the outer Ethernet, IP, UDP and GENEVE headers, writes a new Ethernet header addressed to the veth, and redirects the inner packet onto it with `bpf_redirect`.

Special cases:

- **Outer IP fragments** are never decapped. GWLB doesn't fragment its outer packets, and a first fragment's inner packet would be truncated.
- **Non-first inner fragments** (no L4 header to key on) and **ICMP errors** (which never get a reply) are delivered without caching anything.
- **Oversize inner packets**, larger than one GENEVE packet on the uplink can carry, are dropped and counted as `decap_drop_oversize`. This happens when GRO merged GENEVE packets before decap ran.

### encap

encap is loaded once by `setup` and attached to each endpoint's outer veth end (`gxdp<id>`) by `add`. For each reply from the backend it:

1. Looks up the reply's 5-tuple in `flow_state`. In the default NAT/terminating mode it looks up the swapped tuple. With `--transparent` it looks up the tuple as-is.
2. Copies the cached outer header back onto the packet unchanged, except for fields that depend on this reply's size (IPv4 total length and checksum). decap already swapped the addressing.
3. Redirects the packet out the uplink to GWLB.

Some replies can't be matched by their own 5-tuple:

- **ICMP and ICMPv6 errors** from the backend (port unreachable, time exceeded, packet too big, parameter problem) are matched using the packet they quote, which is the one decap delivered. They go back with that flow's GENEVE options, flow cookie included.
- **Fragments.** A datagram's first fragment is matched normally and recorded in `frag_state`. Later fragments have no L4 header, so they're matched through that record.
- **IPv6 Neighbor Discovery and MLD** (ICMPv6 types 130–143) between the netns and its veth are passed to the kernel, like ARP, instead of being looked up. Since `add` turns ARP/ND off on the inner end, in practice this is mostly MLD, unless `--script` turns ARP back on.

A reply too large to leave the uplink once encapsulated (larger than `max_inner_len`) is dropped and counted as oversize, rather than being redirected into a silent drop.

### What `add` does

`add <vpce-id>` ([cmd/add.go](cmd/add.go)) refuses an endpoint that's already provisioned. If it fails partway, it rolls back only what it created, never a veth, netns or map entry that already existed.

1. **Create a netns** for the endpoint, named after the VPC endpoint ID.
2. **Create a veth pair** and move the inner end into the netns.
   - Names come from the VPC endpoint ID (`FormatInterfaceName` in [cmd/utils.go](cmd/utils.go)): `gxdp<id>` for the outer end and `gwlb<id>` for the inner end.
   - MTU is `--mtu`, 8500 by default (see [MTU and offloads](#mtu-and-offloads)).
   - MACs are derived from the endpoint ID instead of being random (`FormatInterfaceMAC` in [cmd/utils.go](cmd/utils.go)): `02` for the outer end or `06` for the inner end, followed by the last 10 hex digits of the ID. For `vpce-0123456789abcdef0`, the inner end is `06:78:9a:bc:de:f0`. This makes them easy to spot in captures and stable across `remove`/`add`. Setting them explicitly also stops systemd-udevd's default `MACAddressPolicy=persistent` from replacing a random MAC after `add` has recorded it.
3. **Turn ARP/ND off on the inner end** (`IFF_NOARP`). encap replaces the reply's whole Ethernet header, so the destination MAC the netns picks never reaches the wire. With ARP on, though, the netns's kernel would hold every reply until it resolved the next hop, and nothing would answer, because the root netns only answers for its own addresses. With ARP off, the kernel sends right away to the interface's own MAC, whatever the routes look like. Nothing needs to resolve the inner end either, since decap addresses every frame it delivers directly.
4. **Disable offloads** on both ends: TX checksum offload and every segmentation and GRO offload (TSO, GSO, USO, GRO and so on; see `vethDisabledFeatures` in [cmd/add.go](cmd/add.go)). BPF can't compute the real L4 checksum, so the kernel has to write it before encap sees the packet. Every packet crossing the veth also has to be wire-sized, because encap would turn a GSO super-packet into one oversized frame that gets dropped.
5. **Add default routes** (`0.0.0.0/0` and `::/0`) out the inner end, with no next hop. The inner end is the netns's only way out, so these routes let the backend reply to clients that aren't on its subnet, which is nearly all of them behind GWLB. With ARP off, nothing is ever resolved, so no gateway is needed. The IPv6 route is skipped if IPv6 is disabled.
6. **Run `--script`**, if given, so the backend can finish its setup before the endpoint is reachable. It runs inside the endpoint's own netns (via `setns`, before forking it), so it can address the inner interface directly instead of reaching into the netns itself.
7. **Go live.** Read both ends' MACs (only now, since the script may have changed the inner one), insert `VPC endpoint ID → (outer ifindex, inner MAC, outer MAC)` into `vpce_to_ifindex`, and attach encap to the outer end. This is last because it's what makes the endpoint reachable.

With `--no-netns`, steps 1 and 5 are skipped and the inner end stays in the root netns with the same name. Nothing then keeps different endpoints' routing tables apart, which is why a dedicated netns is the default.

### What `remove` and `teardown` do

`remove <vpce-id>` ([cmd/remove.go](cmd/remove.go)) undoes `add` in this order:

1. Delete the `vpce_to_ifindex` entry.
2. Detach encap.
3. Delete the veth pair.
4. Delete any `flow_state`, `frag_state` and `metrics` entries keyed by that ifindex, so a future endpoint that reuses the ifindex doesn't inherit them. This happens after the veth is gone because packets already in decap or encap can still write entries until then.
5. Delete the netns.

`teardown` ([cmd/teardown.go](cmd/teardown.go)) removes every provisioned endpoint, then detaches decap and deletes the pin directory.

### BPF maps

Maps are pinned by name, so both programs share the same instances.

| Map | Purpose |
|---|---|
| `vpce_to_ifindex` | VPC endpoint ID → outer veth ifindex and the L2 addresses decap writes. Sized by `--max-endpoints`. |
| `flow_state` | Inner 5-tuple plus ifindex → cached outer header. One LRU hash for both IPv4 and IPv6 (`struct flow_key` has a family tag), sized by `--max-flows`. Old flows age out automatically. Sharing one map wastes less space than separate per-family maps, but a burst of one family's flows can evict the other's. |
| `frag_state` | encap's tracking for fragmented replies: a first fragment's addresses, protocol and fragment ID → its flow's cached outer header. LRU with 16384 entries, since an entry only needs to outlive one datagram. |
| `metrics` | Per-CPU packet and byte counters per (ifindex, counter). Read by `serve`. |

### Load-time constants

Some settings are written into each program's `.rodata` at `setup` and are fixed until the next `setup`, instead of being looked up per packet:

- `vpce_mode`: NAT/terminating (default) or transparent (`--transparent`), which sets how encap orients its lookups.
- The uplink's ifindex, so encap can redirect replies without a map lookup.
- `max_inner_len`, in both programs: uplink MTU minus 68, the largest inner packet decap delivers and encap sends.
- `allowed_origin_addr` and `allowed_origin_mask`, from `--allowed-origin-cidr`.

### MTU and offloads

GWLB documents an MTU of 8500 bytes of inner packet but doesn't stick to it. It can deliver larger inner packets whole, and when it fragments a packet itself, the fragments can also exceed 8500. It never sends ICMP "fragmentation needed", so a DF-set reply larger than it will carry is lost silently.

- **The veth MTU is 8500 by default.** Replies from the netns are then sized to fit: the kernel picks a TCP MSS of 8460, fragments larger UDP datagrams itself (encap matches every fragment to its flow), and answers a DF-set packet that's too large with its own "fragmentation needed", which encap sends back to the sender.
- **The same MTU limits what the netns receives.** veth drops any frame over the receiving end's MTU, so inner packets from GWLB larger than 8500 bytes are dropped at the veth, silently and after decap has counted them as delivered. A terminating backend doesn't see these, because its peers size their TCP segments to the MSS it advertises. A transparent appliance forwards traffic whose packet size was agreed with other hosts, so GWLB's larger packets and fragments would be lost at the default MTU.
- **The uplink sets the upper limit.** decap and encap accept inner packets up to the uplink's MTU minus 68 (8933 on a 9001-byte uplink), read when `setup` runs, and `--mtu` can go up to the same value. Raising `--mtu` to it, as a transparent appliance needs, lets the netns receive everything GWLB delivers. Replies over 8500 bytes are then sent too, and left for GWLB to carry or drop, unless `--script` also sets a route MTU of 8500 (`ip route replace default dev "$2" mtu 8500`, and likewise with `ip -6`). Re-run `setup` and re-add endpoints if the uplink's MTU changes. `setup` warns if the MTU is below 8568, the minimum that carries GWLB's documented 8500-byte packets.
- **XDP runs in generic mode.** At a jumbo MTU, both ENA and veth refuse native XDP for single-buffer programs like these (no `xdp.frags`), so both programs normally run as generic XDP, after GRO. Keep UDP GRO forwarding (`rx-udp-gro-forwarding`, `rx-gro-list`) off on the uplink, or GENEVE packets can reach decap merged together. `setup` warns if either is on, and any merged packets that get through are counted as `decap_drop_oversize`.
