#![allow(dead_code)]

use crate::error::Result;
use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
use crate::tcp::recv_buffer::RecvBuffer;
use crate::tcp::send_buffer::SendBuffer;
use crate::tcp::tcb::{Tcb, TcbState, ack_acceptable};
use tracing::{info, warn};

pub struct Connection {
    pub tcb: Tcb,
    send_buf: SendBuffer,
    recv_buf: Option<RecvBuffer>,
}

impl Connection {
    pub fn new(tcb: Tcb) -> Self {
        let iss = tcb.snd.iss;
        Self {
            send_buf: SendBuffer::new(iss),
            recv_buf: None,
            tcb,
        }
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

    pub fn write_data(&mut self, data: &[u8]) -> usize {
        self.send_buf.write(data)
    }

    pub fn next_segment_to_send(&mut self, max_payload: usize) -> Option<Vec<u8>> {
        let (seq, payload) = self.send_buf.next_segment(max_payload)?;
        let n = payload.len();
        self.send_buf.advance_nxt(n);
        self.tcb.snd.nxt = self.send_buf.nxt();
        Some(
            SegmentBuilder::new(
                self.tcb.local_ip,
                self.tcb.remote_ip,
                self.tcb.local_port,
                self.tcb.remote_port,
            )
            .seq(seq)
            .ack(self.tcb.rcv.nxt)
            .flags(TcpFlags {
                ack: true,
                psh: true,
                ..TcpFlags::default()
            })
            .window(self.current_window())
            .payload(&payload)
            .build(),
        )
    }

    pub fn read_received(&mut self, buf: &mut [u8]) -> usize {
        self.recv_buf.as_mut().map(|rb| rb.read(buf)).unwrap_or(0)
    }

    pub fn received_available(&self) -> usize {
        self.recv_buf.as_ref().map(|rb| rb.available()).unwrap_or(0)
    }

    fn current_window(&self) -> u16 {
        self.recv_buf
            .as_ref()
            .map(|rb| rb.window())
            .unwrap_or(65535)
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

        self.recv_buf = Some(RecvBuffer::new(seg.header.seq));
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
        self.send_buf.acknowledge(seg.header.ack_num);
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
                self.send_buf.acknowledge(seg.header.ack_num);
            }
            self.tcb.snd.wnd = seg.header.window;
        }

        if !seg.payload.is_empty() {
            if let Some(rb) = &mut self.recv_buf {
                rb.insert(seg.header.seq, seg.payload);
                self.tcb.rcv.nxt = rb.next_expected();
            }
            if !seg.header.flags.fin {
                return Ok(Some(self.build_ack()));
            }
        }

        if seg.header.flags.fin {
            let data_len = seg.payload.len() as u32;
            self.tcb.rcv.nxt = seg.header.seq.wrapping_add(data_len).wrapping_add(1);
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
        .window(self.current_window())
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
        .window(self.current_window())
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
    const CLIENT_ISN: u32 = 1000;

    fn make_connection() -> Connection {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        Connection::new(tcb)
    }

    fn parse_segment(raw: &[u8]) -> TcpSegment<'_> {
        TcpSegment::parse(raw, CLIENT_IP, SERVER_IP).unwrap()
    }

    fn parse_response(raw: &[u8]) -> TcpSegment<'_> {
        TcpSegment::parse(raw, SERVER_IP, CLIENT_IP).unwrap()
    }

    fn establish_connection() -> (Connection, u32) {
        let mut conn = make_connection();
        let syn = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(CLIENT_ISN)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();
        let syn_ack_raw = conn.process_segment(&parse_segment(&syn)).unwrap().unwrap();
        let server_isn = parse_response(&syn_ack_raw).header.seq;

        let ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(CLIENT_ISN + 1)
            .ack(server_isn.wrapping_add(1))
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();
        conn.process_segment(&parse_segment(&ack)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::Established);
        (conn, server_isn)
    }

    fn client_data_seg(seq: u32, server_isn: u32, data: &[u8]) -> Vec<u8> {
        SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(seq)
            .ack(server_isn.wrapping_add(1))
            .flags(TcpFlags {
                ack: true,
                psh: true,
                ..TcpFlags::default()
            })
            .payload(data)
            .build()
    }

    // ── original handshake tests ──────────────────────────────────────────────

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

    // ── data transfer tests ───────────────────────────────────────────────────

    #[test]
    fn receives_data_in_established() {
        let (mut conn, server_isn) = establish_connection();

        let seg_raw = client_data_seg(CLIENT_ISN + 1, server_isn, b"hello world");
        let response = conn.process_segment(&parse_segment(&seg_raw)).unwrap();

        assert!(response.is_some());
        let ack = parse_response(response.as_ref().unwrap());
        assert!(ack.header.flags.ack);
        assert_eq!(ack.header.ack_num, CLIENT_ISN + 1 + 11);

        assert_eq!(conn.received_available(), 11);
        let mut out = [0u8; 11];
        conn.read_received(&mut out);
        assert_eq!(&out, b"hello world");
    }

    #[test]
    fn sends_data_in_established() {
        let (mut conn, server_isn) = establish_connection();

        conn.write_data(b"hello server");
        let seg_raw = conn.next_segment_to_send(1400).unwrap();
        let seg = parse_response(&seg_raw);

        assert!(seg.header.flags.ack);
        assert!(seg.header.flags.psh);
        assert_eq!(seg.payload, b"hello server");
        assert_eq!(seg.header.seq, server_isn.wrapping_add(1));

        assert!(conn.next_segment_to_send(1400).is_none());

        let client_ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(CLIENT_ISN + 1)
            .ack(server_isn.wrapping_add(1 + 12))
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();
        conn.process_segment(&parse_segment(&client_ack)).unwrap();

        assert!(conn.send_buf.is_empty());
    }

    #[test]
    fn out_of_order_data_reassembled() {
        let (mut conn, server_isn) = establish_connection();

        let seg2 = client_data_seg(CLIENT_ISN + 1 + 5, server_isn, b"world");
        let seg1 = client_data_seg(CLIENT_ISN + 1, server_isn, b"hello");

        conn.process_segment(&parse_segment(&seg2)).unwrap();
        assert_eq!(conn.received_available(), 0);

        let resp = conn.process_segment(&parse_segment(&seg1)).unwrap();
        assert!(resp.is_some());
        let ack = parse_response(resp.as_ref().unwrap());
        assert_eq!(ack.header.ack_num, CLIENT_ISN + 1 + 10);

        assert_eq!(conn.received_available(), 10);
        let mut out = [0u8; 10];
        conn.read_received(&mut out);
        assert_eq!(&out, b"helloworld");
    }

    #[test]
    fn large_transfer_receive_1mb() {
        let (mut conn, server_isn) = establish_connection();
        let payload: Vec<u8> = (0..=255u8).cycle().take(1024 * 1024).collect();
        let chunk_size = 1400;
        let mut seq: u32 = CLIENT_ISN + 1;
        let mut received: Vec<u8> = Vec::with_capacity(payload.len());
        let mut tmp = vec![0u8; 65536];

        for chunk in payload.chunks(chunk_size) {
            let seg = client_data_seg(seq, server_isn, chunk);
            conn.process_segment(&parse_segment(&seg)).unwrap();
            seq = seq.wrapping_add(chunk.len() as u32);

            let n = conn.read_received(&mut tmp);
            received.extend_from_slice(&tmp[..n]);
        }

        loop {
            let n = conn.read_received(&mut tmp);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&tmp[..n]);
        }

        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }

    #[test]
    fn large_transfer_send_1mb() {
        use crate::tcp::send_buffer::SEND_BUF_SIZE;

        let (mut conn, _) = establish_connection();
        let payload: Vec<u8> = (0..=255u8).cycle().take(1024 * 1024).collect();
        let mut write_offset = 0usize;
        let mut sent: Vec<u8> = Vec::with_capacity(payload.len());

        while write_offset < payload.len() || !conn.send_buf.is_empty() {
            let space = SEND_BUF_SIZE.saturating_sub(conn.send_buf.buffered());
            let to_write = (payload.len().saturating_sub(write_offset)).min(space);
            if to_write > 0 {
                conn.write_data(&payload[write_offset..write_offset + to_write]);
                write_offset += to_write;
            }

            if let Some(seg_raw) = conn.next_segment_to_send(1400) {
                let seg = parse_response(&seg_raw);
                sent.extend_from_slice(seg.payload);
                let new_ack = seg.header.seq.wrapping_add(seg.payload.len() as u32);
                let client_ack =
                    SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
                        .seq(CLIENT_ISN + 1)
                        .ack(new_ack)
                        .flags(TcpFlags {
                            ack: true,
                            ..TcpFlags::default()
                        })
                        .build();
                conn.process_segment(&parse_segment(&client_ack)).unwrap();
            }
        }

        assert_eq!(sent.len(), payload.len());
        assert_eq!(sent, payload);
    }
}
