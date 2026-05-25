# CLAUDE.md — Magnum-TCP Project Rules

## Project Identity

Magnum-TCP: A production-grade, zero-dependency TCP/IPv4 stack written entirely in Rust from scratch.
No external networking libraries. No libc wrappers for protocol logic. Every byte parsed by hand.

---

## Hard Rules (Non-Negotiable)

### Git
- **Claude must NEVER commit to git.** Not ever. Not even WIP commits.
- **Claude must NEVER push to remote.**
- User owns all commits. Claude writes code, user decides what to ship.

### Code Style
- **No comments in code.** Names must be self-documenting. If a name needs a comment, rename it.
- Exception: a single `// RFC 793 §3.4` style RFC section reference is allowed on non-obvious protocol math. Nothing else.
- No `TODO`, `FIXME`, `HACK`, `NOTE` inline comments.
- No docstrings unless a public API surface demands it for `cargo doc`.

### Dependencies
- **Zero external networking or protocol libraries.** No `tun`, `etherparse`, `pnet`, `smoltcp`, or any crate that touches packet parsing or network interfaces.
- Allowed crates: `tokio` (async runtime only), `tracing` + `tracing-subscriber` (structured logging), `bytes` (only if zero-copy slicing is genuinely required), `clap` (CLI args).
- Every new dependency requires explicit user approval before adding to `Cargo.toml`.

### Quality
- All public types and functions must have corresponding unit or integration tests.
- `cargo clippy -- -D warnings` must pass clean before any work is considered done.
- `cargo fmt` must be applied. Code must be formatted.
- No `unwrap()` or `expect()` in production paths. Use `?` with typed errors.
- No `unsafe` unless implementing a zero-copy buffer optimization — requires user approval and explicit justification.

---

## Architecture Principles

- Parse in place. Slices over copies. `&[u8]` over owned `Vec<u8>` at parse boundaries.
- Typed errors via `thiserror`. No string errors in library code.
- State machines are enums. Every TCP state is a variant. Transitions are explicit match arms.
- Concurrency via `tokio` tasks + channels (`mpsc`, `watch`). No `Arc<Mutex<T>>` hot paths.
- Separation of concerns: parsing layer never allocates, state machine layer owns TCBs, I/O layer owns the TUN fd.

---

## Session Discipline

- After every Claude session, `ProjectProgress.md` must be updated with: what was implemented, what tests pass, what is next.
- Claude proposes the update to `ProjectProgress.md`; user commits it alongside their code.
- Phase completion is declared only when all acceptance criteria in the PRD pass.

---

## File Layout (Enforced)

```
magnum-tcp/
├── src/
│   ├── main.rs            # Entry point, TUN setup, dispatch loop
│   ├── tun.rs             # TUN/TAP fd open, raw read/write
│   ├── ethernet.rs        # L2 frame parsing
│   ├── ipv4.rs            # L3 header parsing + checksum
│   ├── tcp/
│   │   ├── mod.rs         # Public TCP surface
│   │   ├── header.rs      # TCP header parsing + checksum
│   │   ├── tcb.rs         # Transmission Control Block + state machine
│   │   ├── connection.rs  # Per-connection logic (send/recv)
│   │   └── listener.rs    # LISTEN state, accept queue
│   ├── error.rs           # Unified error types
│   └── chaos.rs           # Chaos engineering middleware (Phase 4)
├── tests/
│   ├── ipv4_checksum.rs
│   ├── tcp_header.rs
│   └── handshake.rs
├── CLAUDE.md
├── ProjectProgress.md
└── Magnum_TCP_Production_PRD.md
```

---

## What Claude Must NOT Do

- Must not scaffold placeholder modules and call them "done."
- Must not use `todo!()` macros as a delivery mechanism.
- Must not add features outside the current milestone without user direction.
- Must not refactor code that is not part of the current task.
- Must not ask clarifying questions mid-implementation for things resolvable from the PRD or RFCs.
