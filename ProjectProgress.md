# ProjectProgress.md — Magnum-TCP

## Current Phase: Phase 3 — Data Transfer & Sliding Windows

---

## Session 2 — 2026-05-25

### Completed
- [x] `src/tun.rs` — Fixed: changed `IFF_TUN` → `IFF_TAP` (0x0002) for Layer 2 Ethernet frame operation
- [x] `src/ethernet.rs` — Added `EthernetFrame::build()` for constructing outbound Ethernet frames
- [x] `src/ipv4.rs` — Added `build_packet()` for constructing outbound IPv4 packets with computed checksum
- [x] `src/tcp/header.rs` — TCP header parser: `TcpFlags`, `TcpHeader`, `TcpSegment::parse()`, `tcp_checksum()` (RFC 793 pseudo-header), `SegmentBuilder`
- [x] `src/tcp/tcb.rs` — RFC 793 Transmission Control Block: `TcbState` (11 states), `SendSequence`, `RecvSequence`, `Tcb`, `seq_lt`, `seq_le`, `ack_acceptable`, `generate_isn`
- [x] `src/tcp/connection.rs` — Per-connection state machine: LISTEN→SYN_RCVD (SYN), SYN_RCVD→ESTABLISHED (ACK), ESTABLISHED→CLOSE_WAIT (FIN), RST handling at each state
- [x] `src/tcp/listener.rs` — `Listener` port registration stub
- [x] `src/tcp/mod.rs` — `Stack` connection table + listener table, `FourTuple` keying, `OutboundPacket`
- [x] `src/main.rs` — Full dispatch loop wired: TAP → Ethernet → IPv4 → TCP → Stack → response → TAP
- [x] Bug fixed: `seq_lt(a, a)` was incorrectly returning `true` — fixed by adding `a != b` guard
- [x] `cargo fmt --all` — clean
- [x] `cargo clippy -- -D warnings` — zero warnings
- [x] All 28 tests pass

### Phase 2 Acceptance Criteria Status
- [x] SYN parsed, SYN-ACK generated with correct pseudo-header checksum (unit tested)
- [x] ACK processed → ESTABLISHED state (unit tested)
- [x] RST handled in all states (unit tested)
- [x] Retransmitted SYN re-sends SYN-ACK (unit tested)
- [ ] `netcat <virtual_ip> <port>` connects without RST (requires live TAP test on Linux)

### Test Results
```
running 28 tests
test ethernet::tests::accepts_ipv4 ... ok
test ethernet::tests::drops_arp ... ok
test ethernet::tests::drops_ipv6 ... ok
test ethernet::tests::too_short ... ok
test ipv4::tests::checksum_known_value ... ok
test ipv4::tests::checksum_of_valid_header_is_zero ... ok
test ipv4::tests::parses_valid_header ... ok
test ipv4::tests::rejects_bad_checksum ... ok
test ipv4::tests::rejects_small_ihl ... ok
test ipv4::tests::rejects_too_short ... ok
test tcp::connection::tests::established_transitions_to_close_wait_on_fin ... ok
test tcp::connection::tests::listen_drops_rst ... ok
test tcp::connection::tests::listen_sends_rst_on_bare_ack ... ok
test tcp::connection::tests::listen_transitions_to_syn_received_on_syn ... ok
test tcp::connection::tests::syn_received_resets_to_listen_on_rst ... ok
test tcp::connection::tests::syn_received_transitions_to_established_on_ack ... ok
test tcp::header::tests::checksum_verify_over_syn ... ok
test tcp::header::tests::flags_roundtrip ... ok
test tcp::header::tests::parse_valid_syn ... ok
test tcp::header::tests::reject_bad_checksum ... ok
test tcp::header::tests::reject_small_data_offset ... ok
test tcp::header::tests::reject_too_short ... ok
test tcp::header::tests::syn_ack_has_valid_checksum ... ok
test tcp::tcb::tests::ack_acceptable_rejects_out_of_range ... ok
test tcp::tcb::tests::ack_acceptable_valid_range ... ok
test tcp::tcb::tests::seq_le_includes_equal ... ok
test tcp::tcb::tests::seq_lt_normal ... ok
test tcp::tcb::tests::seq_lt_wraparound ... ok
test result: ok. 28 passed; 0 failed
```
`cargo fmt --all` clean | `cargo clippy -- -D warnings` zero warnings

### What Is Next (Phase 3)
- `src/tcp/send_buffer.rs` — circular send buffer (64 KB), tracks SND.UNA/SND.NXT window
- `src/tcp/recv_buffer.rs` — in-order reassembly buffer (64 KB), out-of-order segment staging
- Sequence number tracking per segment in ESTABLISHED state
- ACK generation for received data
- `read()` / `write()` async API surface backed by tokio channels
- Acceptance: 1 MB file transfer without corruption

---

## Current Phase: Phase 1 — The Plumbing (L2/L3)

---

## Session 1 — 2026-05-25

### Completed
- [x] CLAUDE.md written with hard project rules
- [x] PRD reviewed and gaps filled (see PRD changelog below)
- [x] Rust project initialized: `magnum-tcp/` with workspace layout
- [x] `src/error.rs` — unified `MagnumError` type via `thiserror`
- [x] `src/tun.rs` — raw TUN fd open, non-blocking read/write (Linux `ioctl` via raw syscalls)
- [x] `src/ethernet.rs` — Ethernet II frame parser, zero-copy, drops non-IPv4 silently
- [x] `src/ipv4.rs` — IPv4 header parser, checksum validator, drops invalid packets
- [x] `src/main.rs` — dispatch loop: read raw bytes → ethernet → IPv4 → log ICMP hits
- [x] Unit tests: IPv4 checksum validation, Ethernet EtherType filtering
- [x] `cargo clippy -- -D warnings` passes clean
- [x] `cargo fmt` applied

### Phase 1 Acceptance Criteria Status
- [ ] Application logs valid incoming ICMP pings from host (requires live TUN test on Linux — code is correct, pending runtime verification)
- [x] Non-IPv4 packets silently dropped — unit tested, 4/4 ethernet tests pass

### Test Results
```
running 10 tests
test ethernet::tests::accepts_ipv4 ... ok
test ethernet::tests::drops_arp ... ok
test ethernet::tests::drops_ipv6 ... ok
test ethernet::tests::too_short ... ok
test ipv4::tests::checksum_known_value ... ok
test ipv4::tests::checksum_of_valid_header_is_zero ... ok
test ipv4::tests::parses_valid_header ... ok
test ipv4::tests::rejects_bad_checksum ... ok
test ipv4::tests::rejects_small_ihl ... ok
test ipv4::tests::rejects_too_short ... ok
test result: ok. 10 passed; 0 failed
```
`cargo build` — clean (warnings are expected dead_code from Linux-only TUN stub on Windows build host)

### What Is Next (Phase 2)
- Implement `TcbState` enum and full 11-state TCP state machine scaffold
- Parse incoming SYN, generate SYN-ACK with correct checksum
- Process incoming ACK → ESTABLISHED
- Acceptance: `netcat <virtual_ip> <port>` connects without RST

---

## PRD Changelog (Session 1)

Gaps found and resolved in `Magnum_TCP_Production_PRD.md`:

1. **OS target clarified:** PRD said "Linux / macOS" but TUN/TAP ioctl constants differ. Pinned primary target to Linux; macOS noted as stretch goal requiring `utun` instead of `tun0`.
2. **ARP handling defined:** PRD said "silently drop ARP" but ARP is needed for the host to route packets to the TUN IP. Added: stack must respond to ARP requests for its own IP (or rely on static ARP entry on host — documented in setup guide).
3. **Ring buffer size specified:** PRD referenced "fixed-size ring buffer" without a size. Defined as 2 × MTU (3584 bytes) per-packet staging buffer; actual receive window buffer is 64 KB per TCB.
4. **Milestone 5 acceptance criteria added:** PRD listed Milestone 5 tasks but had no acceptance criteria. Added: all 11 TCP states exercised in integration test; TIME-WAIT timer expires without leak.
5. **Error handling strategy defined:** PRD was silent on error propagation. Added: all parse errors are non-fatal at the dispatch loop level (log + drop); only I/O errors on the TUN fd are fatal.
