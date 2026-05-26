#![allow(dead_code)]

use std::time::{Duration, Instant};

use crate::error::Result;
use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
use crate::tcp::recv_buffer::RecvBuffer;
use crate::tcp::retransmit::{MSS, RetransmitQueue};
use crate::tcp::send_buffer::SendBuffer;
use crate::tcp::tcb::{Tcb, TcbState, ack_acceptable, seq_le};
use tracing::{info, warn};

const TWO_MSL: Duration = Duration::from_secs(60);

pub struct Connection {
    pub tcb: Tcb,
    send_buf: SendBuffer,
    recv_buf: Option<RecvBuffer>,
    retransmit_queue: RetransmitQueue,
    time_wait_start: Option<Instant>,
}

impl Connection {
    pub fn new(tcb: Tcb) -> Self {
        let iss = tcb.snd.iss;
        Self {
            send_buf: SendBuffer::new(iss),
            recv_buf: None,
            retransmit_queue: RetransmitQueue::new(),
            time_wait_start: None,
            tcb,
        }
    }

    pub fn process_segment(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        match self.tcb.state {
            TcbState::Listen => self.handle_listen(seg),
            TcbState::SynReceived => self.handle_syn_received(seg),
            TcbState::Established => self.handle_established(seg),
            TcbState::CloseWait => self.handle_close_wait(seg),
            TcbState::FinWait1 => self.handle_fin_wait_1(seg),
            TcbState::FinWait2 => self.handle_fin_wait_2(seg),
            TcbState::Closing => self.handle_closing(seg),
            TcbState::LastAck => self.handle_last_ack(seg),
            TcbState::TimeWait => self.handle_time_wait(seg),
            TcbState::SynSent | TcbState::Closed => {
                warn!(state = ?self.tcb.state, "segment in unhandled state dropped");
                Ok(None)
            }
        }
    }

    pub fn write_data(&mut self, data: &[u8]) -> usize {
        self.send_buf.write(data)
    }

    pub fn next_segment_to_send(&mut self, max_payload: usize) -> Option<Vec<u8>> {
        let snd_wnd = self.tcb.snd.wnd as u32;
        let effective_window = self.tcb.cwnd.min(snd_wnd);
        let inflight = self.tcb.snd.nxt.wrapping_sub(self.tcb.snd.una);
        if inflight >= effective_window {
            return None;
        }
        let window_avail = (effective_window - inflight) as usize;
        let max_len = max_payload.min(window_avail);

        let (seq, payload) = self.send_buf.next_segment(max_len)?;
        let n = payload.len();
        self.send_buf.advance_nxt(n);
        self.retransmit_queue.push(seq, payload.clone());
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

    pub fn take_retransmits(&mut self) -> Vec<Vec<u8>> {
        let expired = self.retransmit_queue.expired_segments();
        if !expired.is_empty() {
            self.tcb.ssthresh = (self.tcb.cwnd / 2).max(2 * MSS);
            self.tcb.cwnd = MSS;
            warn!(
                ssthresh = self.tcb.ssthresh,
                cwnd = self.tcb.cwnd,
                count = expired.len(),
                "RTO: slow start restart"
            );
        }
        expired
            .into_iter()
            .map(|(seq, payload)| {
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
                .build()
            })
            .collect()
    }

    pub fn initiate_close(&mut self) -> Option<Vec<u8>> {
        match self.tcb.state {
            TcbState::Established => {
                let fin = self.build_fin_ack();
                self.tcb.snd.nxt = self.tcb.snd.nxt.wrapping_add(1);
                self.tcb.state = TcbState::FinWait1;
                info!(
                    local_port = self.tcb.local_port,
                    "ESTABLISHED -> FIN_WAIT_1"
                );
                Some(fin)
            }
            TcbState::CloseWait => {
                let fin = self.build_fin_ack();
                self.tcb.snd.nxt = self.tcb.snd.nxt.wrapping_add(1);
                self.tcb.state = TcbState::LastAck;
                info!(local_port = self.tcb.local_port, "CLOSE_WAIT -> LAST_ACK");
                Some(fin)
            }
            _ => None,
        }
    }

    pub fn tick_time_wait(&mut self, now: Instant) -> bool {
        if self.tcb.state != TcbState::TimeWait {
            return false;
        }
        if let Some(start) = self.time_wait_start
            && now.duration_since(start) >= TWO_MSL
        {
            self.tcb.state = TcbState::Closed;
            info!(local_port = self.tcb.local_port, "TIME_WAIT -> CLOSED");
            return true;
        }
        false
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
            let new_ack = seg.header.ack_num;
            if ack_acceptable(self.tcb.snd.una, new_ack, self.tcb.snd.nxt) {
                let bytes_acked = new_ack.wrapping_sub(self.tcb.snd.una);
                // RFC 5681 §3.1: slow start or congestion avoidance
                if self.tcb.cwnd < self.tcb.ssthresh {
                    self.tcb.cwnd = self.tcb.cwnd.saturating_add(bytes_acked.min(MSS));
                } else {
                    self.tcb.cwnd = self.tcb.cwnd.saturating_add(MSS * MSS / self.tcb.cwnd);
                }
                self.tcb.snd.una = new_ack;
                self.send_buf.acknowledge(new_ack);
                self.retransmit_queue.acknowledge_and_sample_rtt(new_ack);
                self.tcb.snd.wnd = seg.header.window;
                self.tcb.dup_ack_count = 0;
            } else if new_ack == self.tcb.snd.una && self.tcb.snd.una != self.tcb.snd.nxt {
                // RFC 5681 §3.2: duplicate ACK with data in flight
                self.tcb.dup_ack_count = self.tcb.dup_ack_count.saturating_add(1);
                if self.tcb.dup_ack_count == 3 {
                    // RFC 5681 §3.2: fast retransmit
                    self.tcb.ssthresh = (self.tcb.cwnd / 2).max(2 * MSS);
                    self.tcb.cwnd = self.tcb.ssthresh + 3 * MSS;
                    warn!(
                        cwnd = self.tcb.cwnd,
                        ssthresh = self.tcb.ssthresh,
                        "fast retransmit triggered"
                    );
                    if let Some(retransmit) = self.fast_retransmit_segment() {
                        return Ok(Some(retransmit));
                    }
                } else if self.tcb.dup_ack_count > 3 {
                    // RFC 5681 §3.2: fast recovery — inflate window per dup ACK
                    self.tcb.cwnd = self.tcb.cwnd.saturating_add(MSS);
                }
            }
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
        warn!("segment in CLOSE_WAIT dropped (awaiting application FIN)");
        Ok(None)
    }

    fn handle_fin_wait_1(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            info!("FIN_WAIT_1 -> CLOSED (RST)");
            return Ok(None);
        }

        if seg.header.flags.ack
            && ack_acceptable(self.tcb.snd.una, seg.header.ack_num, self.tcb.snd.nxt)
        {
            let fin_acked = seq_le(self.tcb.snd.nxt, seg.header.ack_num);
            self.tcb.snd.una = seg.header.ack_num;
            self.send_buf.acknowledge(seg.header.ack_num);
            self.retransmit_queue
                .acknowledge_and_sample_rtt(seg.header.ack_num);
            self.tcb.snd.wnd = seg.header.window;

            if fin_acked && seg.header.flags.fin {
                self.tcb.rcv.nxt = seg
                    .header
                    .seq
                    .wrapping_add(seg.payload.len() as u32)
                    .wrapping_add(1);
                self.tcb.state = TcbState::TimeWait;
                self.time_wait_start = Some(Instant::now());
                info!("FIN_WAIT_1 -> TIME_WAIT");
                return Ok(Some(self.build_ack()));
            }

            if fin_acked {
                self.tcb.state = TcbState::FinWait2;
                info!("FIN_WAIT_1 -> FIN_WAIT_2");
                return Ok(None);
            }
        }

        if seg.header.flags.fin {
            let data_len = seg.payload.len() as u32;
            self.tcb.rcv.nxt = seg.header.seq.wrapping_add(data_len).wrapping_add(1);
            self.tcb.state = TcbState::Closing;
            info!("FIN_WAIT_1 -> CLOSING (simultaneous close)");
            return Ok(Some(self.build_ack()));
        }

        Ok(None)
    }

    fn handle_fin_wait_2(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            info!("FIN_WAIT_2 -> CLOSED (RST)");
            return Ok(None);
        }
        if seg.header.flags.fin {
            let data_len = seg.payload.len() as u32;
            self.tcb.rcv.nxt = seg.header.seq.wrapping_add(data_len).wrapping_add(1);
            self.tcb.state = TcbState::TimeWait;
            self.time_wait_start = Some(Instant::now());
            info!("FIN_WAIT_2 -> TIME_WAIT");
            return Ok(Some(self.build_ack()));
        }
        Ok(None)
    }

    fn handle_closing(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            info!("CLOSING -> CLOSED (RST)");
            return Ok(None);
        }
        if seg.header.flags.ack
            && ack_acceptable(self.tcb.snd.una, seg.header.ack_num, self.tcb.snd.nxt)
        {
            self.tcb.snd.una = seg.header.ack_num;
            self.tcb.state = TcbState::TimeWait;
            self.time_wait_start = Some(Instant::now());
            info!("CLOSING -> TIME_WAIT");
        }
        Ok(None)
    }

    fn handle_last_ack(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.rst {
            self.tcb.state = TcbState::Closed;
            info!("LAST_ACK -> CLOSED (RST)");
            return Ok(None);
        }
        if seg.header.flags.ack
            && ack_acceptable(self.tcb.snd.una, seg.header.ack_num, self.tcb.snd.nxt)
        {
            self.tcb.snd.una = seg.header.ack_num;
            self.tcb.state = TcbState::Closed;
            info!("LAST_ACK -> CLOSED");
        }
        Ok(None)
    }

    fn handle_time_wait(&mut self, seg: &TcpSegment<'_>) -> Result<Option<Vec<u8>>> {
        if seg.header.flags.fin {
            return Ok(Some(self.build_ack()));
        }
        Ok(None)
    }

    fn fast_retransmit_segment(&mut self) -> Option<Vec<u8>> {
        let (seq, payload) = self.retransmit_queue.first_unacked()?;
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

    fn build_fin_ack(&self) -> Vec<u8> {
        SegmentBuilder::new(
            self.tcb.local_ip,
            self.tcb.remote_ip,
            self.tcb.local_port,
            self.tcb.remote_port,
        )
        .seq(self.tcb.snd.nxt)
        .ack(self.tcb.rcv.nxt)
        .flags(TcpFlags {
            fin: true,
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
    use std::time::Duration;

    use super::*;
    use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
    use crate::tcp::send_buffer::SEND_BUF_SIZE;
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

    fn client_ack(ack_num: u32) -> Vec<u8> {
        SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(CLIENT_ISN + 1)
            .ack(ack_num)
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build()
    }

    fn client_fin(seq: u32, ack_num: u32) -> Vec<u8> {
        SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(seq)
            .ack(ack_num)
            .flags(TcpFlags {
                fin: true,
                ack: true,
                ..TcpFlags::default()
            })
            .build()
    }

    // ── handshake tests ───────────────────────────────────────────────────────

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

        let client_ack_raw = client_ack(server_isn.wrapping_add(1 + 12));
        conn.process_segment(&parse_segment(&client_ack_raw))
            .unwrap();

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
                let ack_raw = client_ack(new_ack);
                conn.process_segment(&parse_segment(&ack_raw)).unwrap();
            }
        }

        assert_eq!(sent.len(), payload.len());
        assert_eq!(sent, payload);
    }

    // ── active close tests ────────────────────────────────────────────────────

    #[test]
    fn active_close_fin_wait_path() {
        let (mut conn, server_isn) = establish_connection();
        let fin_raw = conn.initiate_close().unwrap();
        assert_eq!(conn.tcb.state, TcbState::FinWait1);
        let fin_seg = parse_response(&fin_raw);
        assert!(fin_seg.header.flags.fin && fin_seg.header.flags.ack);

        // Client ACKs our FIN → FIN_WAIT_2
        let fin_seq_acked = server_isn.wrapping_add(2);
        let ack_raw = client_ack(fin_seq_acked);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::FinWait2);

        // Client sends its FIN → TIME_WAIT
        let client_fin_raw = client_fin(CLIENT_ISN + 1, fin_seq_acked);
        let ack_resp = conn
            .process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert!(ack_resp.is_some());
        assert_eq!(conn.tcb.state, TcbState::TimeWait);
        let ack_seg = parse_response(ack_resp.as_ref().unwrap());
        assert!(ack_seg.header.flags.ack);
        assert_eq!(ack_seg.header.ack_num, CLIENT_ISN + 2);
    }

    #[test]
    fn passive_close_last_ack_to_closed() {
        let (mut conn, server_isn) = establish_connection();

        // Client sends FIN → CLOSE_WAIT
        let client_fin_raw = client_fin(CLIENT_ISN + 1, server_isn.wrapping_add(1));
        conn.process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert_eq!(conn.tcb.state, TcbState::CloseWait);

        // Application sends FIN → LAST_ACK
        let fin_raw = conn.initiate_close().unwrap();
        assert_eq!(conn.tcb.state, TcbState::LastAck);
        let fin_seg = parse_response(&fin_raw);
        assert!(fin_seg.header.flags.fin && fin_seg.header.flags.ack);

        // Client ACKs our FIN → CLOSED
        let fin_ack_seq = server_isn.wrapping_add(2);
        let ack_raw = client_ack(fin_ack_seq);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::Closed);
    }

    #[test]
    fn time_wait_transitions_to_closed_after_2msl() {
        let (mut conn, server_isn) = establish_connection();
        conn.initiate_close().unwrap();

        let fin_acked = server_isn.wrapping_add(2);
        let ack_raw = client_ack(fin_acked);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::FinWait2);

        let client_fin_raw = client_fin(CLIENT_ISN + 1, fin_acked);
        conn.process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert_eq!(conn.tcb.state, TcbState::TimeWait);

        let not_yet = Instant::now() + Duration::from_secs(30);
        assert!(!conn.tick_time_wait(not_yet));
        assert_eq!(conn.tcb.state, TcbState::TimeWait);

        let past_2msl = Instant::now() + Duration::from_secs(61);
        assert!(conn.tick_time_wait(past_2msl));
        assert_eq!(conn.tcb.state, TcbState::Closed);
    }

    #[test]
    fn simultaneous_close_via_closing_state() {
        let (mut conn, server_isn) = establish_connection();
        let our_fin_raw = conn.initiate_close().unwrap();
        assert_eq!(conn.tcb.state, TcbState::FinWait1);
        let our_fin = parse_response(&our_fin_raw);

        // Client sends FIN without ACKing ours → CLOSING
        let client_fin_raw = client_fin(CLIENT_ISN + 1, server_isn.wrapping_add(1));
        let ack_resp = conn
            .process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert!(ack_resp.is_some());
        assert_eq!(conn.tcb.state, TcbState::Closing);

        // Client ACKs our FIN → TIME_WAIT
        let our_fin_acked = our_fin.header.seq.wrapping_add(1);
        let ack_raw = client_ack(our_fin_acked);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();
        assert_eq!(conn.tcb.state, TcbState::TimeWait);
    }

    #[test]
    fn fin_plus_ack_in_fin_wait_1_goes_to_time_wait() {
        let (mut conn, _server_isn) = establish_connection();
        let our_fin_raw = conn.initiate_close().unwrap();
        let our_fin = parse_response(&our_fin_raw);
        assert_eq!(conn.tcb.state, TcbState::FinWait1);

        // Client sends FIN+ACK (acking our FIN too) → TIME_WAIT directly
        let fin_ack = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(CLIENT_ISN + 1)
            .ack(our_fin.header.seq.wrapping_add(1))
            .flags(TcpFlags {
                fin: true,
                ack: true,
                ..TcpFlags::default()
            })
            .build();
        let resp = conn.process_segment(&parse_segment(&fin_ack)).unwrap();
        assert!(resp.is_some());
        assert_eq!(conn.tcb.state, TcbState::TimeWait);
    }

    // ── congestion control tests ──────────────────────────────────────────────

    #[test]
    fn slow_start_cwnd_grows_per_ack() {
        let (mut conn, server_isn) = establish_connection();
        let initial_cwnd = conn.tcb.cwnd;
        assert!(conn.tcb.cwnd < conn.tcb.ssthresh);

        conn.write_data(&vec![0u8; 1400]);
        conn.next_segment_to_send(1400).unwrap();

        let new_ack = server_isn.wrapping_add(1 + 1400);
        let ack_raw = client_ack(new_ack);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();

        assert!(
            conn.tcb.cwnd > initial_cwnd,
            "cwnd should grow in slow start"
        );
        assert_eq!(
            conn.tcb.cwnd,
            initial_cwnd + 1400.min(MSS),
            "slow start: cwnd += min(bytes_acked, MSS)"
        );
    }

    #[test]
    fn congestion_avoidance_cwnd_grows_below_one_mss_per_ack() {
        let (mut conn, server_isn) = establish_connection();
        conn.tcb.ssthresh = 1460;
        conn.tcb.cwnd = 2 * 1460;

        conn.write_data(&vec![0u8; 1400]);
        conn.next_segment_to_send(1400).unwrap();

        let before = conn.tcb.cwnd;
        let new_ack = server_isn.wrapping_add(1 + 1400);
        let ack_raw = client_ack(new_ack);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();

        let growth = conn.tcb.cwnd - before;
        assert!(growth > 0, "cwnd should grow in CA");
        assert!(
            growth < MSS,
            "CA growth per ACK should be less than 1 MSS when cwnd > MSS"
        );
    }

    #[test]
    fn fast_retransmit_on_triple_dup_ack() {
        let (mut conn, server_isn) = establish_connection();

        conn.write_data(b"segment data here");
        conn.next_segment_to_send(1400).unwrap();

        let dup_ack_raw = client_ack(server_isn.wrapping_add(1));
        for i in 0..3u8 {
            let resp = conn.process_segment(&parse_segment(&dup_ack_raw)).unwrap();
            if i == 2 {
                assert!(
                    resp.is_some(),
                    "3rd dup ACK should trigger fast retransmit response"
                );
                let retransmit = parse_response(resp.as_ref().unwrap());
                assert!(retransmit.header.flags.ack && retransmit.header.flags.psh);
                assert_eq!(retransmit.payload, b"segment data here");
            } else {
                assert!(resp.is_none());
            }
        }

        assert_eq!(conn.tcb.dup_ack_count, 3);
        assert!(conn.tcb.cwnd > conn.tcb.ssthresh);
    }

    #[test]
    fn fast_recovery_cwnd_inflates_past_3_dup_acks() {
        let (mut conn, server_isn) = establish_connection();
        conn.write_data(&vec![0u8; 1400]);
        conn.next_segment_to_send(1400).unwrap();

        let dup_ack_raw = client_ack(server_isn.wrapping_add(1));
        for _ in 0..3 {
            conn.process_segment(&parse_segment(&dup_ack_raw)).unwrap();
        }
        let cwnd_after_3 = conn.tcb.cwnd;

        conn.process_segment(&parse_segment(&dup_ack_raw)).unwrap();
        assert_eq!(
            conn.tcb.cwnd,
            cwnd_after_3 + MSS,
            "cwnd inflates by MSS per extra dup ACK in fast recovery"
        );
    }

    #[test]
    fn dup_ack_count_resets_on_new_ack() {
        let (mut conn, server_isn) = establish_connection();
        conn.write_data(&vec![0u8; 1400]);
        conn.next_segment_to_send(1400).unwrap();

        let dup = client_ack(server_isn.wrapping_add(1));
        conn.process_segment(&parse_segment(&dup)).unwrap();
        conn.process_segment(&parse_segment(&dup)).unwrap();
        assert_eq!(conn.tcb.dup_ack_count, 2);

        let new_ack_raw = client_ack(server_isn.wrapping_add(1 + 1400));
        conn.process_segment(&parse_segment(&new_ack_raw)).unwrap();
        assert_eq!(conn.tcb.dup_ack_count, 0);
    }

    // ── retransmit tests ──────────────────────────────────────────────────────

    #[test]
    fn retransmit_on_rto_expiry() {
        let (mut conn, server_isn) = establish_connection();
        conn.retransmit_queue.rto = Duration::from_millis(2);

        conn.write_data(b"retransmit me");
        conn.next_segment_to_send(1400).unwrap();

        std::thread::sleep(Duration::from_millis(3));
        let retransmits = conn.take_retransmits();
        assert_eq!(retransmits.len(), 1);

        let seg = parse_response(&retransmits[0]);
        assert_eq!(seg.payload, b"retransmit me");
        assert_eq!(seg.header.seq, server_isn.wrapping_add(1));
    }

    #[test]
    fn rto_expiry_resets_cwnd_to_slow_start() {
        let (mut conn, _) = establish_connection();
        conn.retransmit_queue.rto = Duration::from_millis(2);
        conn.tcb.cwnd = 10 * MSS;
        conn.tcb.ssthresh = 65535;

        conn.write_data(&vec![0u8; 1400]);
        conn.next_segment_to_send(1400).unwrap();

        std::thread::sleep(Duration::from_millis(3));
        conn.take_retransmits();

        assert_eq!(conn.tcb.cwnd, MSS, "cwnd should reset to 1 MSS on RTO");
        assert_eq!(conn.tcb.ssthresh, 5 * MSS, "ssthresh should halve on RTO");
    }

    #[test]
    fn retransmit_completes_transfer() {
        let (mut conn, _server_isn) = establish_connection();
        conn.retransmit_queue.rto = Duration::from_millis(2);

        let data = b"hello retransmit world";
        conn.write_data(data);
        let original = conn.next_segment_to_send(1400).unwrap();
        let original_seg = parse_response(&original);

        // Simulate drop: do NOT send ACK
        assert!(!conn.send_buf.is_empty());

        std::thread::sleep(Duration::from_millis(4));
        let retransmits = conn.take_retransmits();
        assert_eq!(retransmits.len(), 1);

        // ACK the retransmit
        let new_ack = original_seg
            .header
            .seq
            .wrapping_add(original_seg.payload.len() as u32);
        let ack_raw = client_ack(new_ack);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();

        assert!(conn.send_buf.is_empty());
        assert!(conn.retransmit_queue.is_empty());
    }

    #[test]
    fn time_wait_retransmits_ack_on_fin() {
        let (mut conn, server_isn) = establish_connection();
        conn.initiate_close().unwrap();

        let fin_acked = server_isn.wrapping_add(2);
        let ack_raw = client_ack(fin_acked);
        conn.process_segment(&parse_segment(&ack_raw)).unwrap();

        let client_fin_raw = client_fin(CLIENT_ISN + 1, fin_acked);
        conn.process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert_eq!(conn.tcb.state, TcbState::TimeWait);

        // Retransmitted FIN from client while in TIME_WAIT — should re-ACK
        let resp = conn
            .process_segment(&parse_segment(&client_fin_raw))
            .unwrap();
        assert!(resp.is_some());
        let ack_seg = parse_response(resp.as_ref().unwrap());
        assert!(ack_seg.header.flags.ack);
    }
}
