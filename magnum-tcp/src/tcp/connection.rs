#![allow(dead_code)]

use crate::error::Result;
use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
use crate::tcp::tcb::{Tcb, TcbState, ack_acceptable};
use tracing::{info, warn};

pub struct Connection {
    pub tcb: Tcb,
}

impl Connection {
    pub fn new(tcb: Tcb) -> Self {
        Self { tcb }
    }

    pub fn process_segment(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        match self.tcb.state {
            TcbState::Listen => self.handle_listen(seg),
            TcbState::SynReceived => self.handle_syn_received(seg),
            TcbState::Established => self.handle_established(seg),
            TcbState::CloseWait => self.handle_close_wait(seg),
            TcbState::SynSent
            | TcbState::FinWait1
            | TcbState::FinWait2
            | TcbState::Closing
            | TcbState::LastAck
            | TcbState::TimeWait
            | TcbState::Closed => {
                warn!(state = ?self.tcb.state, "segment in unimplemented state dropped");
                Ok(None)
            }
        }
    }

    fn handle_listen(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            return Ok(None);
        }

        if seg.header.flags.ack {
            return Ok(Some(self.build_rst(seg.header.ack_num)));
        }

        if !seg.header.flags.syn {
            return Ok(None);
        }

        self.tcb.rcv.irs = seg.header.seq;
        self.tcb.rcv.nxt = seg.header.seq.wrapping_add(1);
        self.tcb.rcv.wnd = seg.header.window;
        self.tcb.snd.nxt = self.tcb.snd.iss.wrapping_add(1);
        self.tcb.state = TcbState::SynReceived;

        info!(
            local_port = self.tcb.local_port,
            remote_port = seg.header.src_port,
            iss = self.tcb.snd.iss,
            "LISTEN -> SYN_RECEIVED"
        );

        Ok(Some(self.build_syn_ack()))
    }

    fn handle_syn_received(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Listen;
            info!("SYN_RECEIVED -> LISTEN");
            return Ok(None);
        }

        // RFC 793: retransmitted SYN — re-send SYN-ACK
        if seg.header.flags.syn && !seg.header.flags.ack && seg.header.seq == self.tcb.rcv.irs {
            return Ok(Some(self.build_syn_ack()));
        }

        if !seg.header.flags.ack {
            return Ok(None);
        }

        if !ack_acceptable(self.tcb.snd.una, seg.header.ack_num, self.tcb.snd.nxt) {
            return Ok(Some(self.build_rst(seg.header.ack_num)));
        }

        self.tcb.snd.una = seg.header.ack_num;
        self.tcb.snd.wnd = seg.header.window;
        self.tcb.state = TcbState::Established;

        info!(
            local_port = self.tcb.local_port,
            remote_port = self.tcb.remote_port,
            "SYN_RECEIVED -> ESTABLISHED"
        );

        Ok(None)
    }

    fn handle_established(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            info!("ESTABLISHED -> CLOSED");
            return Ok(None);
        }

        if seg.header.flags.ack {
            if ack_acceptable(self.tcb.snd.una, seg.header.ack_num, self.tcb.snd.nxt) {
                self.tcb.snd.una = seg.header.ack_num;
            }
            self.tcb.snd.wnd = seg.header.window;
        }

        if seg.header.flags.fin {
            self.tcb.rcv.nxt = seg
                .header
                .seq
                .wrapping_add(seg.payload.len() as u32)
                .wrapping_add(1);
            self.tcb.state = TcbState::CloseWait;
            info!("ESTABLISHED -> CLOSE_WAIT");
            return Ok(Some(self.build_ack()));
        }

        Ok(None)
    }

    fn handle_close_wait(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            return Ok(None);
        }
        warn!("segment in CLOSE_WAIT state dropped (passive close pending)");
        Ok(None)
    }

    fn build_syn_ack(&self) -> Vec<u8> {
        SegmentBuilder::new(
            self.tcb.local_ip,
            self.tcb.remote_ip,
            self.tcb.local_port,
            self.tcb.remote_port,
        )
        .seq(self.tcb.snd.iss)
        .ack(self.tcb.rcv.nxt)
        .flags(TcpFlags {
            syn: true,
            ack: true,
            ..TcpFlags::default()
        })
        .build()
    }

    fn build_ack(&self) -> Vec<u8> {
        SegmentBuilder::new(
            self.tcb.local_ip,
            self.tcb.remote_ip,
            self.tcb.local_port,
            self.tcb.remote_port,
        )
        .seq(self.tcb.snd.nxt)
        .ack(self.tcb.rcv.nxt)
        .flags(TcpFlags {
            ack: true,
            ..TcpFlags::default()
        })
        .build()
    }

    fn build_rst(&self, seq: u32) -> Vec<u8> {
        SegmentBuilder::new(
            self.tcb.local_ip,
            self.tcb.remote_ip,
            self.tcb.local_port,
            self.tcb.remote_port,
        )
        .seq(seq)
        .flags(TcpFlags {
            rst: true,
            ..TcpFlags::default()
        })
        .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
    use crate::tcp::tcb::{Tcb, TcbState};

    const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
    const SERVER_IP: [u8; 4] = [192, 168, 100, 2];
    const CLIENT_PORT: u16 = 54321;
    const SERVER_PORT: u16 = 80;

    fn make_connection() -> Connection {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        Connection::new(tcb)
    }

    fn parse_segment<'a>(raw: &'a [u8]) -> TcpSegment<'a> {
        TcpSegment::parse(raw, CLIENT_IP, SERVER_IP).unwrap()
    }

    fn parse_response<'a>(raw: &'a [u8]) -> TcpSegment<'a> {
        TcpSegment::parse(raw, SERVER_IP, CLIENT_IP).unwrap()
    }

    #[test]
    fn listen_transitions_to_syn_received_on_syn() {
        let mut conn = make_connection();
        let syn = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1000)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();

        let response = conn.process_segment(&parse_segment(&syn)).unwrap();
        assert!(response.is_some());
        assert_eq!(conn.tcb.state, TcbState::SynReceived);

        let syn_ack = parse_response(response.as_ref().unwrap());
        assert!(syn_ack.header.flags.syn);
        assert!(syn_ack.header.flags.ack);
        assert_eq!(syn_ack.header.ack_num, 1001);
    }

    #[test]
    fn syn_received_transitions_to_established_on_ack() {
        let mut conn = make_connection();

        let syn = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1000)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();
        let syn_ack_raw = conn.process_segment(&parse_segment(&syn)).unwrap().unwrap();
        let syn_ack = parse_response(&syn_ack_raw);

        let ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1001)
            .ack(syn_ack.header.seq.wrapping_add(1))
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();

        let response = conn.process_segment(&parse_segment(&ack)).unwrap();
        assert!(response.is_none());
        assert_eq!(conn.tcb.state, TcbState::Established);
    }

    #[test]
    fn listen_drops_rst() {
        let mut conn = make_connection();
        let rst = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(0)
            .flags(TcpFlags {
                rst: true,
                ..TcpFlags::default()
            })
            .build();

        let response = conn.process_segment(&parse_segment(&rst)).unwrap();
        assert!(response.is_none());
        assert_eq!(conn.tcb.state, TcbState::Listen);
    }

    #[test]
    fn listen_sends_rst_on_bare_ack() {
        let mut conn = make_connection();
        let ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(0)
            .ack(12345)
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();

        let response = conn.process_segment(&parse_segment(&ack)).unwrap();
        assert!(response.is_some());

        let rst = parse_response(response.as_ref().unwrap());
        assert!(rst.header.flags.rst);
    }

    #[test]
    fn syn_received_resets_to_listen_on_rst() {
        let mut conn = make_connection();

        let syn = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1000)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();
        conn.process_segment(&parse_segment(&syn)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::SynReceived);

        let rst = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1001)
            .flags(TcpFlags {
                rst: true,
                ..TcpFlags::default()
            })
            .build();
        conn.process_segment(&parse_segment(&rst)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::Listen);
    }

    #[test]
    fn established_transitions_to_close_wait_on_fin() {
        let mut conn = make_connection();

        let syn = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1000)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();
        let syn_ack_raw = conn.process_segment(&parse_segment(&syn)).unwrap().unwrap();
        let syn_ack = parse_response(&syn_ack_raw);

        let ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1001)
            .ack(syn_ack.header.seq.wrapping_add(1))
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();
        conn.process_segment(&parse_segment(&ack)).unwrap();

        let fin = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1001)
            .ack(syn_ack.header.seq.wrapping_add(1))
            .flags(TcpFlags {
                fin: true,
                ack: true,
                ..TcpFlags::default()
            })
            .build();

        let response = conn.process_segment(&parse_segment(&fin)).unwrap();
        assert!(response.is_some());
        assert_eq!(conn.tcb.state, TcbState::CloseWait);

        let ack_resp = parse_response(response.as_ref().unwrap());
        assert!(ack_resp.header.flags.ack);
    }
}
