#![allow(dead_code)]

pub mod connection;
pub mod header;
pub mod listener;
pub mod recv_buffer;
pub mod retransmit;
pub mod send_buffer;
pub mod tcb;

use std::collections::HashMap;

use crate::tcp::connection::Connection;
use crate::tcp::header::TcpSegment;
use crate::tcp::listener::Listener;
use crate::tcp::tcb::Tcb;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub local_ip: [u8; 4],
    pub local_port: u16,
}

pub struct OutboundPacket {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub tcp_bytes: Vec<u8>,
}

pub struct Stack {
    listeners: HashMap<u16, Listener>,
    connections: HashMap<FourTuple, Connection>,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            listeners: HashMap::new(),
            connections: HashMap::new(),
        }
    }

    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port, Listener::new(port));
    }

    pub fn process(
        &mut self,
        remote_ip: [u8; 4],
        local_ip: [u8; 4],
        seg: &TcpSegment<'_>,
    ) -> Option<OutboundPacket> {
        let key = FourTuple {
            remote_ip,
            remote_port: seg.header.src_port,
            local_ip,
            local_port: seg.header.dst_port,
        };

        if !self.connections.contains_key(&key) {
            if seg.header.flags.syn
                && !seg.header.flags.ack
                && self.listeners.contains_key(&seg.header.dst_port)
            {
                let tcb = Tcb::new_for_listen(
                    local_ip,
                    seg.header.dst_port,
                    remote_ip,
                    seg.header.src_port,
                );
                self.connections.insert(key, Connection::new(tcb));
            } else {
                warn!(
                    dst_port = seg.header.dst_port,
                    "segment for unknown connection dropped"
                );
                return None;
            }
        }

        let conn = self.connections.get_mut(&key)?;

        match conn.process_segment(seg) {
            Ok(Some(tcp_bytes)) => Some(OutboundPacket {
                src_ip: local_ip,
                dst_ip: remote_ip,
                tcp_bytes,
            }),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "connection processing error");
                None
            }
        }
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}
