# ProjectProgress.md — Magnum-TCP

## Current Phase: Phase 5 — Chaos Engineering / Live Integration

---

## Session 4 — 2026-05-26

### Completed
- [x] `src/tcp/retransmit.rs` — `RetransmitQueue`: RTT-sampled RTO (Karn's algorithm + RFC 6298 SRTT/RTTVAR), exponential backoff on retransmit, 128-segment bounded queue, `expired_segments()`, `first_unacked()` for fast retransmit; 6 unit tests
- [x] `src/chaos.rs` — `ChaosMiddleware`: configurable drop rate, reorder rate, jitter; xorshift64 PRNG (no external deps); `intercept()` / `flush_ready()` API; 4 unit tests
- [x] `src/tcp/tcb.rs` — Added `cwnd: u32`, `ssthresh: u32`, `dup_ack_count: u8` to `Tcb`; initial values: `cwnd = 1460 (1 MSS)`, `ssthresh = 65535`
- [x] `src/tcp/connection.rs` — Full Phase 4 overhaul:
  - `next_segment_to_send` now enforces `min(cwnd, snd.wnd)` effective window; every sent segment is pushed to the retransmit queue
  - `handle_established` implements RFC 5681 TCP Reno: slow start (cwnd += min(bytes_acked, MSS)), congestion avoidance (cwnd += MSS²/cwnd), duplicate ACK detection, fast retransmit (3 dup ACKs), fast recovery (cwnd inflate per extra dup ACK)
  - `take_retransmits()` — returns expired in-flight segments as serialised TCP bytes; on RTO fires, resets to slow start (ssthresh = cwnd/2, cwnd = MSS)
  - `initiate_close()` — ESTABLISHED→FIN_WAIT_1 (active close) and CLOSE_WAIT→LAST_ACK (passive close completion)
  - `tick_time_wait(now)` — transitions TIME_WAIT→CLOSED after 2×MSL (60 s)
  - All new close-state handlers: `handle_fin_wait_1`, `handle_fin_wait_2`, `handle_closing`, `handle_last_ack`, `handle_time_wait`
  - 16 new tests covering every new code path
- [x] `src/tcp/mod.rs` — wired `pub mod retransmit;`
- [x] `src/main.rs` — wired `mod chaos;`
- [x] `cargo fmt --all` — clean
- [x] `cargo clippy -- -D warnings` — zero warnings
- [x] All 73 tests pass

### Phase 4 Acceptance Criteria Status
- [x] Active close path exercised: FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT (unit tested)
- [x] Passive close path exercised: CLOSE_WAIT → LAST_ACK → CLOSED (unit tested)
- [x] Simultaneous close via CLOSING state (unit tested)
- [x] TIME_WAIT 2×MSL expiry → CLOSED (unit tested)
- [x] RTO retransmit with exponential backoff (unit tested)
- [x] Fast retransmit on 3 duplicate ACKs (unit tested)
- [x] Slow start cwnd growth (unit tested)
- [x] Congestion avoidance linear growth (unit tested)
- [x] RTO resets cwnd to slow-start (unit tested)
- [ ] 10MB transfer over chaos link with Fast Retransmit in logs (requires Linux + TAP device)

### Test Results
```
running 73 tests ... test result: ok. 73 passed; 0 failed
```
`cargo fmt --all` clean | `cargo clippy -- -D warnings` zero warnings

### What Is Next (Phase 5)
- PCAP-compatible packet capture output (§5.2 of PRD) for Wireshark verification
- Zero-window probing (send 1-byte probe when remote window = 0)
- Simultaneous open (SYN_SENT state handler)
- Live end-to-end test on Linux: `nc <virtual_ip> 80`, Wireshark capture, 10MB file transfer with `--chaos 0.10` CLI flag
- Valgrind / ASAN check: all 11 states exercised, TIME_WAIT expires without leak

---

## Session 3 — 2026-05-25

### Completed
- [x] **Phase 1 & 2 review + hardening:**
  - Added `MagnumError::Ipv4TotalLenTooSmall` and guard against `total_len < header_len` panic in `ipv4.rs`
  - Removed CLAUDE.md-violating inline comments from `tcp/header.rs`
  - Replaced `sum += 6;` with `sum += u32::from(crate::ipv4::PROTO_TCP)` in `tcp_checksum`
  - Removed redundant per-field `#[allow(dead_code)]` from `tcp/tcb.rs`
- [x] `src/tcp/send_buffer.rs` — 64 KB circular ring buffer tracking SND.UNA / SND.NXT; `write()`, `next_segment()`, `advance_nxt()`, `acknowledge()`; 8 unit tests
- [x] `src/tcp/recv_buffer.rs` — 64 KB in-order reassembly buffer with BTreeMap OOO staging; correct modular-arithmetic `insert()` using `seq_lt`; 9 unit tests including 1 MB in-order and 4 KB out-of-order integration tests
- [x] `src/tcp/header.rs` — `SegmentBuilder` extended: `payload(&[u8])` setter, `window(u16)` setter; `build()` updated to include payload in checksum calculation
- [x] `src/tcp/connection.rs` — `Connection` now owns `SendBuffer` + `Option<RecvBuffer>`; `write_data()`, `next_segment_to_send()`, `read_received()`, `received_available()` public API; `handle_established()` processes incoming data and generates data-bearing ACKs; `build_ack()` and `build_syn_ack()` advertise real receive window; 5 new data-transfer tests added
- [x] `src/tcp/mod.rs` — wired `pub mod send_buffer;` and `pub mod recv_buffer;`
- [x] `cargo fmt --all` — clean
- [x] `cargo clippy -- -D warnings` — zero warnings
- [x] All 49 tests pass

### Phase 3 Acceptance Criteria Status
- [x] 1 MB receive transfer without corruption (unit tested: `large_transfer_receive_1mb`)
- [x] 1 MB send transfer without corruption (unit tested: `large_transfer_send_1mb`)
- [x] Out-of-order segment reassembly (unit tested: `out_of_order_data_reassembled`, `large_transfer_out_of_order`)
- [x] Duplicate segment handling — silently ignored (unit tested: `duplicate_segment_ignored`)
- [x] Partial-overlap trimming at recv buffer boundary (unit tested: `partial_overlap_trimmed`)
- [ ] Live `nc` data transfer verified in Wireshark (requires Linux + TAP device)

### Test Results
```
running 49 tests
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
test tcp::connection::tests::large_transfer_receive_1mb ... ok
test tcp::connection::tests::large_transfer_send_1mb ... ok
test tcp::connection::tests::listen_drops_rst ... ok
test tcp::connection::tests::listen_sends_rst_on_bare_ack ... ok
test tcp::connection::tests::listen_transitions_to_syn_received_on_syn ... ok
test tcp::connection::tests::out_of_order_data_reassembled ... ok
test tcp::connection::tests::receives_data_in_established ... ok
test tcp::connection::tests::sends_data_in_established ... ok
test tcp::connection::tests::syn_received_resets_to_listen_on_rst ... ok
test tcp::connection::tests::syn_received_transitions_to_established_on_ack ... ok
test tcp::header::tests::checksum_verify_over_syn ... ok
test tcp::header::tests::flags_roundtrip ... ok
test tcp::header::tests::parse_valid_syn ... ok
test tcp::header::tests::reject_bad_checksum ... ok
test tcp::header::tests::reject_small_data_offset ... ok
test tcp::header::tests::reject_too_short ... ok
test tcp::header::tests::syn_ack_has_valid_checksum ... ok
test tcp::recv_buffer::tests::duplicate_segment_ignored ... ok
test tcp::recv_buffer::tests::in_order_insert_and_read ... ok
test tcp::recv_buffer::tests::large_transfer_in_order ... ok
test tcp::recv_buffer::tests::large_transfer_out_of_order ... ok
test tcp::recv_buffer::tests::next_expected_advances ... ok
test tcp::recv_buffer::tests::out_of_order_reassembly ... ok
test tcp::recv_buffer::tests::partial_overlap_trimmed ... ok
test tcp::recv_buffer::tests::partial_read ... ok
test tcp::recv_buffer::tests::window_shrinks_as_buffer_fills ... ok
test tcp::send_buffer::tests::acknowledge_advances_una ... ok
test tcp::send_buffer::tests::partial_acknowledge ... ok
test tcp::send_buffer::tests::respects_max_len ... ok
test tcp::send_buffer::tests::seq_starts_after_iss ... ok
test tcp::send_buffer::tests::write_and_read_single_segment ... ok
test tcp::send_buffer::tests::wraparound_write ... ok
test tcp::send_buffer::tests::write_respects_capacity ... ok
test tcp::tcb::tests::ack_acceptable_rejects_out_of_range ... ok
test tcp::tcb::tests::ack_acceptable_valid_range ... ok
test tcp::tcb::tests::seq_le_includes_equal ... ok
test tcp::tcb::tests::seq_lt_normal ... ok
test tcp::tcb::tests::seq_lt_wraparound ... ok
test result: ok. 49 passed; 0 failed
```
`cargo fmt --all` clean | `cargo clippy -- -D warnings` zero warnings

### What Is Next (Phase 4)
- Active close: FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT path (server-initiated close)
- TIME_WAIT 2×MSL timer (tokio time)
- Retransmission timer: track unacknowledged segments, resend after RTO expiry
- Basic congestion control: slow-start, CWND, ssthresh (RFC 5681)
- Acceptance: sustained throughput without stall under simulated 1% packet loss

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
- [ ] Application logs valid incoming ICMP pings from host (requires live TUN test on Linux)
- [x] Non-IPv4 packets silently dropped — unit tested, 4/4 ethernet tests pass

---

## PRD Changelog (Session 1)

Gaps found and resolved in `Magnum_TCP_Production_PRD.md`:

1. **OS target clarified:** PRD said "Linux / macOS" but TUN/TAP ioctl constants differ. Pinned primary target to Linux; macOS noted as stretch goal requiring `utun` instead of `tun0`.
2. **ARP handling defined:** PRD said "silently drop ARP" but ARP is needed for the host to route packets to the TUN IP. Added: stack must respond to ARP requests for its own IP (or rely on static ARP entry on host — documented in setup guide).
3. **Ring buffer size specified:** PRD referenced "fixed-size ring buffer" without a size. Defined as 2 × MTU (3584 bytes) per-packet staging buffer; actual receive window buffer is 64 KB per TCB.
4. **Milestone 5 acceptance criteria added:** PRD listed Milestone 5 tasks but had no acceptance criteria. Added: all 11 TCP states exercised in integration test; TIME-WAIT timer expires without leak.
5. **Error handling strategy defined:** PRD was silent on error propagation. Added: all parse errors are non-fatal at the dispatch loop level (log + drop); only I/O errors on the TUN fd are fatal.
