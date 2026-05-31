# Magnum-TCP

A production-grade, zero-dependency TCP/IPv4 stack written entirely in Rust — from raw kernel bytes to a working HTTP server — with no networking libraries, no `libc` wrappers for protocol logic, and no shortcuts.

Every byte parsed by hand. Every RFC implemented explicitly.

---

## What This Is

Magnum-TCP intercepts raw Layer 2 frames directly from a kernel TAP device and processes them through a complete, hand-built network stack: Ethernet → IPv4 → TCP → application. The operating system provides only the file descriptor. Everything above that — frame parsing, checksum validation, connection state, flow control, congestion control, retransmission — is implemented from scratch in safe Rust.

The result is a TCP stack that can accept real connections from a real kernel, complete a full three-way handshake, transfer data reliably under simulated packet loss, and serve HTTP responses — all without touching a single external networking crate.

---

## What Was Built

### Layer 2 — Ethernet II
- Full Ethernet frame parser over `&[u8]` slices — zero allocation at parse time
- EtherType dispatch: routes IPv4 frames forward, silently drops everything else
- ARP responder: handles `who-has` requests for the stack's own IP, constructs and returns reply frames

### Layer 3 — IPv4 (RFC 791)
- IPv4 header parser with IHL-aware variable-length parsing
- RFC 791 one's-complement checksum validation and generation
- Outbound packet builder for response frames
- Non-fatal handling: bad checksums and truncated headers are logged and dropped, never crash the loop

### Layer 4 — TCP (RFC 793)

**Header parsing**
- Full TCP header parser including options offset and all six flag bits
- RFC 793 pseudo-header checksum over `(src_ip, dst_ip, proto, tcp_len)` + segment

**The state machine — all 11 states**

```
CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED
                                              → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
                                              → FIN_WAIT_1 → CLOSING → TIME_WAIT → CLOSED
SYN_SENT → ESTABLISHED  (active open)
SYN_SENT → SYN_RECEIVED (simultaneous open)
```

Every state transition is an explicit `match` arm. No implicit fallthrough, no string-keyed dispatch.

**Send buffer** — 64 KB circular ring tracking `SND.UNA` / `SND.NXT` with wraparound-safe modular arithmetic

**Receive buffer** — 64 KB in-order reassembly with a `BTreeMap` out-of-order staging area; duplicate segments and partial overlaps handled correctly

**Retransmission (RFC 6298)**
- RTT sampling with Karn's algorithm (no sampling on retransmitted segments)
- SRTT/RTTVAR smoothed estimator → RTO
- Exponential backoff on retransmit; bounded queue of 128 in-flight segments
- Fast retransmit on 3 duplicate ACKs

**Congestion control — TCP Reno (RFC 5681)**
- Slow start: `cwnd += min(bytes_acked, MSS)` per ACK
- Congestion avoidance: `cwnd += MSS² / cwnd` per ACK
- Fast retransmit: retransmit head-of-line on triple duplicate ACK
- Fast recovery: `cwnd` inflation per additional duplicate ACK; exit to CA on new ACK
- RTO fires: `ssthresh = cwnd / 2`, `cwnd = MSS`, return to slow start

**Zero-window probing** — 1-byte probe from `SND.NXT` when remote window = 0; driven by `tokio::time::interval`

### Async Dispatch

- `AsyncFd<Tun>` — non-blocking kernel reads via `tokio`'s I/O reactor
- `AsyncDispatch` — per-connection `mpsc` channel map keyed on `(remote_ip, remote_port, local_port)`
- First SYN for an unknown four-tuple spawns a new `tokio::task` owning that connection's TCB
- Subsequent segments are routed to the correct task via `try_send`; stale entries evicted on closed channel

### Observability

**Structured logging** — every TCB state transition emits a `tracing` span:
```
INFO  magnum_tcp::tcp::connection: LISTEN -> SYN_RECEIVED local_port=80 remote_port=54321 iss=3787787296
INFO  magnum_tcp::tcp::connection: SYN_RECEIVED -> ESTABLISHED local_port=80 remote_port=54321
INFO  magnum_tcp::tcp::connection: ESTABLISHED -> CLOSE_WAIT
```

**PCAP capture** — every inbound and outbound frame written to `capture.pcap` in standard pcap format (magic `0xa1b2c3d4`, version 2.4). Open in Wireshark to see the handshake, data segments, and teardown at the wire level.

### Chaos Engineering Middleware

Intercepts outbound frames before the TAP write:

| Flag | Effect |
|---|---|
| `--chaos <rate>` | Drop each frame with probability `rate` (e.g. `0.10` = 10%) |
| `--chaos-reorder <rate>` | Hold frames and release them out of order |
| `--chaos-jitter-ms <ms>` | Add random delay up to `ms` milliseconds |

Uses an xorshift64 PRNG — no external dependencies.

### HTTP Application Layer

A small HTTP router running over the TCP stack, demonstrating that the stack is a full transport:

| Route | Response |
|---|---|
| `GET /` | `Hello from Magnum-TCP!` |
| `GET /echo` | Your request headers echoed back verbatim |
| `GET /time` | Unix timestamp from the stack process |
| `POST /` | Request body echoed back |
| Anything else | `404 Not Found` |

Non-HTTP connections (e.g. raw `nc`) get their data echoed back as-is.

---

## Numbers

| Metric | Value |
|---|---|
| Lines of Rust source | ~5 000 |
| Test cases | 94 (all passing) |
| External networking dependencies | **0** |
| TCP states implemented | 11 / 11 |
| Allowed crates | `tokio`, `tracing`, `thiserror`, `libc`, `clap` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│          HTTP router (/, /echo, /time, POST /)               │
│                   Raw TCP echo fallback                      │
├──────────────────────────────────────────────────────────────┤
│               Async Dispatch  ·  tokio tasks                 │
│     AsyncFd<Tun>  →  AsyncDispatch  →  per-TCB mpsc channel  │
├──────────────────────────────────────────────────────────────┤
│                   TCP  (RFC 793 / 5681 / 6298)               │
│   11-state machine  ·  Reno CC  ·  RTO  ·  ZWP  ·  buffers  │
├──────────────────────────────────────────────────────────────┤
│                      IPv4  (RFC 791)                         │
│            Header parser  ·  Checksum  ·  Builder            │
├──────────────────────────────────────────────────────────────┤
│                    Ethernet II  ·  ARP                       │
│         Frame parser  ·  EtherType dispatch  ·  ARP reply    │
├──────────────────────────────────────────────────────────────┤
│              TUN / TAP  kernel device  (AsyncFd)             │
│              Linux TAP  ·  macOS utun  ·  PCAP writer        │
└──────────────────────────────────────────────────────────────┘
            ↕  raw Ethernet frames  ↕
       Linux kernel network subsystem
```

---

## File Layout

```
magnum-tcp/
├── src/
│   ├── main.rs            Entry point, CLI, async event loop, HTTP router
│   ├── tun.rs             TUN/TAP fd — open, async read/write (Linux + macOS)
│   ├── ethernet.rs        Ethernet II frame parser + builder
│   ├── ipv4.rs            IPv4 header parser, checksum, outbound builder
│   ├── arp.rs             ARP request parser + reply frame builder
│   ├── pcap.rs            PCAP file writer (standard pcap format)
│   ├── chaos.rs           Chaos middleware — drop / reorder / jitter
│   ├── error.rs           Unified MagnumError via thiserror
│   └── tcp/
│       ├── mod.rs         Public TCP surface, AsyncDispatch, FourTuple
│       ├── header.rs      TCP header parser, checksum, SegmentBuilder
│       ├── tcb.rs         TCB struct, 11 states, seq arithmetic, ISN
│       ├── connection.rs  Per-connection state machine (all transitions)
│       ├── task.rs        tokio::spawn task — inbound/retransmit/ZWP arms
│       ├── send_buffer.rs 64 KB circular send ring
│       ├── recv_buffer.rs 64 KB in-order recv buffer + OOO staging
│       ├── retransmit.rs  Retransmit queue, Karn's algorithm, RTO
│       └── listener.rs    Port registration
├── Dockerfile
├── test_entrypoint.sh
├── Cargo.toml
└── Cargo.lock
```

---

## Prerequisites

You need either:
- **Docker Desktop** (easiest — works on Mac and Linux with no setup), or
- **Linux** with `iproute2` and root / `CAP_NET_ADMIN` (native run)

To build from source you also need Rust 1.85+ (`rustup` is the recommended installer).

---

## Quick Start — Docker (Recommended)

This is the fastest way to see the stack working end-to-end.

**1. Build the image**

```bash
cd magnum-tcp
docker build -t magnum-tcp:test .
```

The first build pulls base images and compiles dependencies (~2 min). Subsequent builds are cached and take ~10 seconds.

**2. Run the automated test**

```bash
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun magnum-tcp:test
```

This creates a TAP interface inside the container, starts the stack, fires two `curl` requests, and prints the full stack log and PCAP summary. Expected output:

```
[PASS]  Response: Hello from Magnum-TCP!
[PASS]  Response: Hello from Magnum-TCP!
Results: 2 passed, 0 failed
```

---

## Manual Testing — Two Terminals

This lets you watch live state transitions in one window while driving traffic from another.

**Terminal 1 — start the stack (logs stay visible)**

```bash
docker run -it --rm --name magnum-test \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint /bin/bash magnum-tcp:test -c "
    ip tuntap add dev tap0 mode tap
    ip link set tap0 up
    ip addr add 192.168.100.1/24 dev tap0
    RUST_LOG=info magnum-tcp --bind-ip 192.168.100.2 --port 80
  "
```

You will see the stack announce itself and then wait:
```
INFO magnum_tcp: Magnum-TCP starting on ports [80]
INFO magnum_tcp: interface tap0 opened (async)
```

**Terminal 2 — send requests, watch Terminal 1 respond**

```bash
# Hello world
docker exec magnum-test curl -s http://192.168.100.2/

# See your own request headers reflected back
docker exec magnum-test curl -s http://192.168.100.2/echo

# Unix timestamp from the stack
docker exec magnum-test curl -s http://192.168.100.2/time

# POST — body is echoed back
docker exec magnum-test curl -s -X POST -d "hello from the other side" http://192.168.100.2/

# 404
docker exec magnum-test curl -s http://192.168.100.2/doesnotexist

# Raw TCP echo (not HTTP — nc sends raw bytes, stack echoes them)
docker exec magnum-test bash -c "echo 'raw data' | nc -q1 192.168.100.2 80"
```

Each command in Terminal 2 produces a complete state-machine trace in Terminal 1:
```
INFO  LISTEN -> SYN_RECEIVED  local_port=80 remote_port=54321 iss=3787787296
INFO  SYN_RECEIVED -> ESTABLISHED  local_port=80 remote_port=54321
INFO  HTTP response sent
INFO  ESTABLISHED -> CLOSE_WAIT
```

**Stop the stack when done**

```bash
docker stop magnum-test
```

---

## Chaos Mode

Test the retransmission and congestion control paths by injecting faults:

```bash
docker run -it --rm --name magnum-test \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint /bin/bash magnum-tcp:test -c "
    ip tuntap add dev tap0 mode tap
    ip link set tap0 up
    ip addr add 192.168.100.1/24 dev tap0
    RUST_LOG=info magnum-tcp --bind-ip 192.168.100.2 --port 80 \
      --chaos 0.10 \
      --chaos-reorder 0.05 \
      --chaos-jitter-ms 50
  "
```

Then hit it from Terminal 2 as above. Connections still complete — retransmit timers and fast retransmit fire to recover dropped segments.

| Flag | Example | Effect |
|---|---|---|
| `--chaos` | `0.10` | 10% of outbound frames are silently dropped |
| `--chaos-reorder` | `0.05` | 5% of frames are held and released out of order |
| `--chaos-jitter-ms` | `50` | Each frame delayed by 0–50ms randomly |

---

## PCAP Capture

Every run writes `capture.pcap` to the working directory (inside the container at `/tmp/capture.pcap`). To extract it:

```bash
docker cp magnum-test:/tmp/capture.pcap ./capture.pcap
```

Open in Wireshark to see every Ethernet frame — ARP exchange, three-way handshake, data segments, FIN teardown — exactly as the stack processed them.

---

## Running the Test Suite

No kernel or TAP device needed. All 94 tests run in-process.

```bash
cd magnum-tcp
cargo test
```

```
running 94 tests
...
test result: ok. 94 passed; 0 failed; 0 ignored; 0 measured
```

Run a specific module:
```bash
cargo test tcp::connection        # state machine tests
cargo test tcp::retransmit        # RTO and fast retransmit
cargo test tcp::recv_buffer       # 1 MB in-order + OOO reassembly
cargo test all_11_tcp_states      # single test exercises every state
cargo test -- --nocapture         # show println! output
```

Lint check (must be clean):
```bash
cargo clippy -- -D warnings
```

---

## CLI Reference

```
magnum-tcp [OPTIONS]

OPTIONS:
    --bind-ip <IP>            Virtual IP for this stack  [default: 192.168.100.2]
    --port <PORT>             Port(s) to listen on; repeat for multiple  [default: 80]
    --chaos <RATE>            Outbound drop rate 0.0–1.0  [default: 0]
    --chaos-reorder <RATE>    Outbound reorder rate 0.0–1.0  [default: 0]
    --chaos-jitter-ms <MS>    Max outbound jitter in milliseconds  [default: 0]
```

Multiple ports:
```bash
magnum-tcp --port 80 --port 8080 --port 443
```

---

## Native Linux Run (No Docker)

If you are on Linux with `iproute2` and a Rust toolchain:

```bash
cargo build --release

sudo ip tuntap add dev tap0 mode tap
sudo ip link set tap0 up
sudo ip addr add 192.168.100.1/24 dev tap0

sudo ./target/release/magnum-tcp --bind-ip 192.168.100.2 --port 80
```

Then from another terminal:
```bash
curl http://192.168.100.2/
```

Cleanup:
```bash
sudo ip tuntap del dev tap0 mode tap
```

---

## Design Decisions

**Why TAP (Layer 2) and not TUN (Layer 3)?**
TAP delivers full Ethernet frames, which means the stack must handle ARP. This is a harder and more realistic target — a production userspace stack (like the ones in DPDK applications or virtual machine hypervisors) sits at Layer 2.

**Why `tokio` tasks per connection instead of a polling loop?**
A single polling loop over all TCBs scales poorly and couples retransmit timers to the read loop. With one `tokio::task` per connection, each TCB independently drives its retransmit timer (`interval(100ms)`), ZWP timer (`interval(1s)`), and TIME_WAIT timer via `tick_time_wait()` — no global tick needed.

**Why `mpsc` channels instead of `Arc<Mutex<TCB>>`?**
Channel ownership means no lock contention on the hot path. The dispatch loop never blocks waiting for a connection task; it `try_send`s and moves on. If a task's inbox is full, the segment is dropped — matching real network behaviour.

**Why `thiserror` typed errors instead of `anyhow`?**
Every error variant is explicitly named (`MagnumError::BadChecksum`, `MagnumError::TruncatedHeader`, …). The dispatch loop matches on these variants to decide whether to log-and-drop or log-and-exit — impossible to do correctly with an opaque error string.
