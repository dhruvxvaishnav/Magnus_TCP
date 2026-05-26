#![allow(dead_code)]

use std::time::{Duration, Instant};

use crate::tcp::tcb::seq_le;

pub const MSS: u32 = 1460;
pub const RETRANSMIT_QUEUE_MAX: usize = 128;

const INITIAL_RTO: Duration = Duration::from_millis(1000);
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(60);
const ALPHA: f64 = 0.125;
const BETA: f64 = 0.25;

struct RetransmitEntry {
    seq: u32,
    data: Vec<u8>,
    sent_at: Instant,
    retransmitted: bool,
}

pub struct RetransmitQueue {
    entries: Vec<RetransmitEntry>,
    pub rto: Duration,
    srtt: Option<f64>,
    rttvar: f64,
}

impl RetransmitQueue {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            rto: INITIAL_RTO,
            srtt: None,
            rttvar: 0.0,
        }
    }

    pub fn push(&mut self, seq: u32, data: Vec<u8>) {
        if self.entries.len() < RETRANSMIT_QUEUE_MAX {
            self.entries.push(RetransmitEntry {
                seq,
                data,
                sent_at: Instant::now(),
                retransmitted: false,
            });
        }
    }

    pub fn acknowledge_and_sample_rtt(&mut self, ack: u32) {
        let now = Instant::now();
        let mut rtt_samples: Vec<Duration> = Vec::new();
        self.entries.retain(|e| {
            let end_seq = e.seq.wrapping_add(e.data.len() as u32);
            if fully_acked(end_seq, ack) {
                if !e.retransmitted {
                    // RFC 6298 §4: only sample RTT from non-retransmitted segments
                    rtt_samples.push(now.duration_since(e.sent_at));
                }
                false
            } else {
                true
            }
        });
        for rtt in rtt_samples {
            self.update_rto(rtt);
        }
    }

    // RFC 6298 §2.3: RTTVAR and SRTT update
    fn update_rto(&mut self, rtt: Duration) {
        let r = rtt.as_secs_f64();
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2.0;
            }
            Some(srtt) => {
                let diff = (srtt - r).abs();
                self.rttvar = (1.0 - BETA) * self.rttvar + BETA * diff;
                self.srtt = Some((1.0 - ALPHA) * srtt + ALPHA * r);
            }
        }
        let srtt = self.srtt.unwrap();
        let rto_secs =
            (srtt + 4.0 * self.rttvar).clamp(MIN_RTO.as_secs_f64(), MAX_RTO.as_secs_f64());
        self.rto = Duration::from_secs_f64(rto_secs);
    }

    pub fn expired_segments(&mut self) -> Vec<(u32, Vec<u8>)> {
        let now = Instant::now();
        let rto = self.rto;
        let mut expired = Vec::new();
        for e in &mut self.entries {
            if now.duration_since(e.sent_at) >= rto {
                expired.push((e.seq, e.data.clone()));
                e.sent_at = now;
                e.retransmitted = true;
            }
        }
        if !expired.is_empty() {
            // RFC 6298 §5.5: exponential backoff on retransmit
            self.rto = (self.rto * 2).min(MAX_RTO);
        }
        expired
    }

    pub fn first_unacked(&self) -> Option<(u32, Vec<u8>)> {
        self.entries.first().map(|e| (e.seq, e.data.clone()))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn fully_acked(end_seq: u32, ack: u32) -> bool {
    seq_le(end_seq, ack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_acknowledge_removes_entry() {
        let mut rq = RetransmitQueue::new();
        rq.push(1000, b"hello".to_vec());
        assert_eq!(rq.len(), 1);
        rq.acknowledge_and_sample_rtt(1005);
        assert!(rq.is_empty());
    }

    #[test]
    fn partial_ack_keeps_entry() {
        let mut rq = RetransmitQueue::new();
        rq.push(1000, b"hello world".to_vec());
        rq.acknowledge_and_sample_rtt(1005);
        assert_eq!(rq.len(), 1);
        rq.acknowledge_and_sample_rtt(1011);
        assert!(rq.is_empty());
    }

    #[test]
    fn first_unacked_returns_first_entry() {
        let mut rq = RetransmitQueue::new();
        rq.push(100, b"abc".to_vec());
        rq.push(103, b"def".to_vec());
        let (seq, data) = rq.first_unacked().unwrap();
        assert_eq!(seq, 100);
        assert_eq!(&data, b"abc");
    }

    #[test]
    fn expired_segments_returns_timed_out_entries() {
        let mut rq = RetransmitQueue::new();
        rq.rto = Duration::from_nanos(1);
        rq.push(500, b"data".to_vec());
        std::thread::sleep(Duration::from_millis(1));
        let expired = rq.expired_segments();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, 500);
        assert_eq!(&expired[0].1, b"data");
    }

    #[test]
    fn rto_doubles_on_retransmit() {
        let mut rq = RetransmitQueue::new();
        rq.rto = Duration::from_millis(1);
        rq.push(1, b"x".to_vec());
        std::thread::sleep(Duration::from_millis(2));
        rq.expired_segments();
        assert_eq!(rq.rto, Duration::from_millis(2));
    }

    #[test]
    fn multiple_entries_independently_acknowledged() {
        let mut rq = RetransmitQueue::new();
        rq.push(100, b"aaa".to_vec());
        rq.push(103, b"bbb".to_vec());
        rq.push(106, b"ccc".to_vec());
        rq.acknowledge_and_sample_rtt(103);
        assert_eq!(rq.len(), 2);
        rq.acknowledge_and_sample_rtt(109);
        assert!(rq.is_empty());
    }
}
