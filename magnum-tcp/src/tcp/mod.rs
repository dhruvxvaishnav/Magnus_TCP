#![allow(dead_code)]

pub mod connection;
pub mod header;
pub mod listener;
pub mod recv_buffer;
pub mod retransmit;
pub mod send_buffer;
pub mod task;
pub mod tcb;

use std::collections::HashMap;

use tokio::sync::mpsc;
use tracing::warn;

use crate::tcp::connection::Connection;
use crate::tcp::header::{TcpSegment, TcpSegmentOwned};
use crate::tcp::listener::Listener;
use crate::tcp::task::{InboundMsg, OutboundMsg};
use crate::tcp::tcb::Tcb;

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

pub struct NewConnectionHandle {
    pub key: FourTuple,
    pub data_rx: mpsc::Receiver<Vec<u8>>,
    pub send_tx: mpsc::Sender<Vec<u8>>,
    pub close_tx: mpsc::Sender<()>,
}

pub struct AsyncDispatch {
    listeners: HashMap<u16, ()>,
    channels: HashMap<FourTuple, mpsc::Sender<InboundMsg>>,
    outbound_tx: mpsc::Sender<OutboundMsg>,
}

impl AsyncDispatch {
    pub fn new(outbound_tx: mpsc::Sender<OutboundMsg>) -> Self {
        Self {
            listeners: HashMap::new(),
            channels: HashMap::new(),
            outbound_tx,
        }
    }

    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port, ());
    }

    pub fn dispatch(
        &mut self,
        remote_ip: [u8; 4],
        local_ip: [u8; 4],
        ether_src: [u8; 6],
        ether_dst: [u8; 6],
        seg: &TcpSegment<'_>,
    ) -> Option<NewConnectionHandle> {
        let key = FourTuple {
            remote_ip,
            remote_port: seg.header.src_port,
            local_ip,
            local_port: seg.header.dst_port,
        };

        if !self.channels.contains_key(&key) {
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
                let conn = Connection::new(tcb);
                let (inbound_tx, inbound_rx) = mpsc::channel(64);
                let (app_data_tx, app_data_rx) = mpsc::channel(64);
                let (app_send_tx, app_send_rx) = mpsc::channel(64);
                let (close_tx, close_rx) = mpsc::channel(1);
                tokio::spawn(task::run_connection_task(
                    conn,
                    inbound_rx,
                    self.outbound_tx.clone(),
                    ether_src,
                    ether_dst,
                    app_data_tx,
                    app_send_rx,
                    close_rx,
                ));
                self.channels.insert(key, inbound_tx);
                return Some(NewConnectionHandle {
                    key,
                    data_rx: app_data_rx,
                    send_tx: app_send_tx,
                    close_tx,
                });
            } else {
                warn!(
                    dst_port = seg.header.dst_port,
                    "segment for unknown connection"
                );
                return None;
            }
        }

        if let Some(tx) = self.channels.get(&key) {
            let msg = InboundMsg {
                seg: TcpSegmentOwned::from(seg),
            };
            if tx.try_send(msg).is_err() {
                self.channels.remove(&key);
                warn!(dst_port = key.local_port, "connection task gone, evicted");
            }
        }

        None
    }
}
