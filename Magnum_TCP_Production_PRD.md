# Product Requirements Document (PRD): Magnum-TCP

## 1. Executive Summary
**Project Name:** Magnum-TCP  
**Objective:** Architect and implement a high-performance, user-space TCP/IPv4 stack from scratch in Rust.  
**Target:** To serve as a definitive portfolio piece demonstrating senior-level systems engineering, mastery of zero-copy memory management, complex state machines, and adherence to dense IETF specifications (RFCs).  
**Context:** Designed for environments requiring extreme reliability and low-latency packet processing, mirroring the rigor required in high-performance data pipelines and financial reconciliation engines.

---

## 2. System Architecture & Constraints

### 2.1 Interface Layer
* **Target OS:** Linux / macOS.
* **Virtual Network Device:** System will bind to a `TUN/TAP` interface to read/write raw Layer 2 (Ethernet) or Layer 3 (IP) packets directly from the kernel.
* **Async Integration:** The public API must expose async/await semantics compatible with `tokio`, allowing users to spawn tasks for connection handling (`let stream = listener.accept().await;`).

### 2.2 Memory & Performance (Non-Negotiable)
* **Zero-Copy Parsing:** Buffer allocations must be strictly minimized. Network payloads must be parsed in place using slice references (`&[u8]`). Avoid copying data into intermediate structs unless crossing a thread boundary requiring `Arc`/`Mutex` or `Bytes`.
* **No Garbage Collection:** Rely strictly on Rust's ownership, borrowing, and lifetimes for memory safety. 
* **Concurrency:** Must support multiple simultaneous connections (minimum 1024 concurrent streams) via efficient state multiplexing, avoiding thread-per-connection blocking.

---

## 3. Core Protocol Specifications (The "What")

### 3.1 Layer 2/3: Ethernet & IPv4
* **Ethernet Frame Parsing:** Extract MAC addresses and EtherType. Silently drop non-IPv4 traffic (e.g., ARP, IPv6).
* **IPv4 Header (RFC 791):**
    * Parse Source/Destination IP addresses, TTL, and Protocol fields.
    * Calculate and validate the IPv4 Header Checksum. Drop packets with invalid checksums.
    * *Out of Scope for v1.0:* IP Fragmentation (assume MTU is respected).

### 3.2 Layer 4: Transmission Control Protocol (TCP - RFC 793)
* **Header Parsing:** Source/Dest Ports, Sequence Number, Acknowledgment Number, Window Size, Flags (URG, ACK, PSH, RST, SYN, FIN).
* **Checksum:** Implement the TCP Pseudo-Header checksum calculation.
* **The State Machine:** Must rigorously implement the 11 TCP states:
    * `LISTEN`, `SYN-SENT`, `SYN-RECEIVED`
    * `ESTABLISHED`
    * `FIN-WAIT-1`, `FIN-WAIT-2`, `CLOSE-WAIT`, `CLOSING`, `LAST-ACK`, `TIME-WAIT`
    * `CLOSED`

---

## 4. Advanced Features (The "Resume Builders")

To achieve "production grade," the stack must survive hostile network environments.

### 4.1 Flow Control & Reliability
* **Sliding Window Protocol:** Dynamically adjust the advertised window size based on the application's read buffer capacity.
* **Sequence Number Wrapping:** Correctly handle arithmetic wrapping of 32-bit sequence numbers.
* **Retransmission Timeout (RTO):** Implement Karn's Algorithm and exponential backoff to handle dynamic network latency without triggering broadcast storms.

### 4.2 Congestion Control (RFC 5681)
* **Algorithms:** Implement TCP Reno.
* **Phases:** Must explicitly log state transitions between:
    * Slow Start
    * Congestion Avoidance
    * Fast Retransmit & Fast Recovery

---

## 5. Observability & Testing Rigor

### 5.1 Chaos Engineering Wrapper
* The system must include a testing middleware layer capable of intercepting `TUN/TAP` writes to simulate real-world degradation:
    * Random packet drop (configurable 1% - 20%).
    * Packet reordering.
    * Artificial jitter/latency (e.g., 50ms ± 20ms).

### 5.2 Telemetry
* **State Logging:** Every TCB (Transmission Control Block) state transition must emit a structured log (JSON or tracing span).
* **PCAP Compatibility:** The interface must output standard pcap-compatible data streams so internal stack behavior can be verified visually in Wireshark.

---

## 6. Project Milestones & Execution Plan

### Milestone 1: The Plumbing (L2/L3)
* [ ] Initialize `tun` interface in Rust.
* [ ] Read raw bytes into a fixed-size ring buffer.
* [ ] Implement bitwise parsing for Ethernet and IPv4 headers.
* [ ] Validate IPv4 checksums.
* **Acceptance Criteria:** The application logs valid incoming ICMP pings from the host machine (and drops them correctly).

### Milestone 2: The Handshake (L4 Setup)
* [ ] Implement the TCB struct and the `ESTABLISHED` state machine path.
* [ ] Parse incoming `SYN`.
* [ ] Generate and calculate checksum for outbound `SYN-ACK`.
* [ ] Process incoming `ACK`.
* **Acceptance Criteria:** `netcat <virtual_ip> <port>` results in a successful connection in Wireshark without immediate RST.

### Milestone 3: Data Transfer & Sliding Windows
* [ ] Implement sequence number tracking.
* [ ] Buffer incoming segments and assemble them in order.
* [ ] Expose a `read()` and `write()` API to the user application.
* **Acceptance Criteria:** Successfully transfer a 1MB text file over the connection without corruption.

### Milestone 4: Hostile Networks (Congestion & RTO)
* [ ] Implement Retransmission Queues.
* [ ] Implement Slow Start / Congestion Avoidance algorithms.
* [ ] Enable the Chaos middleware (10% drop rate).
* **Acceptance Criteria:** Successfully transfer a 10MB file over the chaos link; logs must demonstrate Fast Retransmit engaging.

### Milestone 5: Teardown & Edge Cases
* [ ] Implement the active/passive close state machine (`FIN`, `ACK`, `TIME-WAIT`).
* [ ] Handle edge cases: Zero-window probing, simultaneous open/close.
* **Acceptance Criteria:** All 11 TCP states exercised in integration test; TIME-WAIT timer expires without fd/memory leak (verified via `valgrind` or Rust's address sanitizer).

---

## 7. Out of Scope (For Now)
* IPv6 support.
* UDP and ICMP (beyond basic ignoring/dropping).
* Hardware offloading (Checksum Offload - TSO/LRO).
* SACK (Selective Acknowledgments - RFC 2018) - *can be added as an extension later*.

---

## 8. Implementation Decisions & Clarifications

### 8.1 OS Target
Primary target is **Linux** (kernel ≥ 4.4). The `tun0` device is opened via `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`. macOS (`utun`) is a stretch goal requiring a separate driver path and is out of scope for v1.0.

### 8.2 ARP Handling
Raw `TUN` mode (Layer 3) does not receive Ethernet frames, so ARP does not apply at the TUN layer. However, for the host to route packets to the stack's virtual IP, the operator must configure a static route:
```
ip addr add 192.168.100.1/24 dev tun0
ip link set tun0 up
```
The stack's virtual IP is `192.168.100.2`. No ARP implementation is required.

### 8.3 Buffer Sizes
* **Per-read staging buffer:** 2 × MTU = 3584 bytes. Holds one max-size packet with headroom.
* **Per-TCB receive buffer:** 64 KB. Determines the maximum advertised window.
* **Retransmission queue:** Bounded at 128 segments per connection.

### 8.4 Error Handling Strategy
* Parse errors (malformed packets, bad checksums) are **non-fatal**: log at WARN level and drop the packet.
* I/O errors on the TUN fd are **fatal**: log at ERROR level and exit.
* TCB-level errors (unexpected segment in wrong state) are non-fatal: log and send RST where RFC 793 requires it.

### 8.5 Concurrency Model
The dispatch loop runs on a single `tokio` task reading from the TUN fd. Each accepted TCP connection gets its own `tokio::spawn`-ed task owning the TCB. The dispatch loop sends segments to the correct TCB via `tokio::sync::mpsc` channel keyed on `(src_ip, src_port, dst_port)`.
