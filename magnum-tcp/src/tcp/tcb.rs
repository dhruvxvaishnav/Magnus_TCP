#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug)]
pub struct SendSequence {
    pub una: u32,
    pub nxt: u32,
    pub wnd: u16,
    pub iss: u32,
}

#[derive(Debug)]
pub struct RecvSequence {
    pub nxt: u32,
    pub wnd: u16,
    pub irs: u32,
}

#[derive(Debug)]
pub struct Tcb {
    pub state: TcbState,
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub snd: SendSequence,
    pub rcv: RecvSequence,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub dup_ack_count: u8,
}

impl Tcb {
    pub fn new_for_listen(
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Self {
        let iss = generate_isn(local_ip, local_port, remote_ip, remote_port);
        Self {
            state: TcbState::Listen,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            snd: SendSequence {
                una: iss,
                nxt: iss,
                wnd: 65535,
                iss,
            },
            rcv: RecvSequence {
                nxt: 0,
                wnd: 65535,
                irs: 0,
            },
            cwnd: 1460,
            ssthresh: 65535,
            dup_ack_count: 0,
        }
    }

    pub fn new_for_connect(
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Self {
        let iss = generate_isn(local_ip, local_port, remote_ip, remote_port);
        Self {
            state: TcbState::Closed,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            snd: SendSequence {
                una: iss,
                nxt: iss,
                wnd: 65535,
                iss,
            },
            rcv: RecvSequence {
                nxt: 0,
                wnd: 65535,
                irs: 0,
            },
            cwnd: 1460,
            ssthresh: 65535,
            dup_ack_count: 0,
        }
    }
}

// RFC 793 §3.3: a < b in modular 32-bit space
pub fn seq_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

// RFC 793 §3.3: SND.UNA < SEG.ACK <= SND.NXT
pub fn ack_acceptable(una: u32, ack: u32, nxt: u32) -> bool {
    seq_lt(una, ack) && seq_le(ack, nxt)
}

fn generate_isn(local_ip: [u8; 4], local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> u32 {
    let mut hasher = DefaultHasher::new();
    local_ip.hash(&mut hasher);
    local_port.hash(&mut hasher);
    remote_ip.hash(&mut hasher);
    remote_port.hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        .hash(&mut hasher);
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_lt_normal() {
        assert!(seq_lt(0, 1));
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
        assert!(!seq_lt(5, 5));
    }

    #[test]
    fn seq_lt_wraparound() {
        assert!(seq_lt(u32::MAX - 1, 1));
        assert!(seq_lt(u32::MAX, 0));
        assert!(!seq_lt(1, u32::MAX - 1));
    }

    #[test]
    fn seq_le_includes_equal() {
        assert!(seq_le(5, 5));
        assert!(seq_le(4, 5));
        assert!(!seq_le(6, 5));
    }

    #[test]
    fn ack_acceptable_valid_range() {
        assert!(ack_acceptable(100, 150, 200));
        assert!(ack_acceptable(100, 101, 200));
        assert!(ack_acceptable(100, 200, 200));
    }

    #[test]
    fn ack_acceptable_rejects_out_of_range() {
        assert!(!ack_acceptable(100, 100, 200)); // equal to UNA, not strictly greater
        assert!(!ack_acceptable(100, 201, 200)); // past NXT
        assert!(!ack_acceptable(100, 50, 200)); // before UNA
    }
}
