#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct ChaosConfig {
    pub drop_rate: f64,
    pub reorder_rate: f64,
    pub max_jitter_ms: u64,
}

impl ChaosConfig {
    pub fn packet_loss(rate: f64) -> Self {
        Self {
            drop_rate: rate.clamp(0.0, 1.0),
            reorder_rate: 0.0,
            max_jitter_ms: 0,
        }
    }

    pub fn none() -> Self {
        Self {
            drop_rate: 0.0,
            reorder_rate: 0.0,
            max_jitter_ms: 0,
        }
    }
}

pub struct ChaosMiddleware {
    config: ChaosConfig,
    pending: VecDeque<(Vec<u8>, Instant)>,
    rng: u64,
}

impl ChaosMiddleware {
    pub fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            pending: VecDeque::new(),
            rng: 0x123456789abcdef0,
        }
    }

    pub fn intercept(&mut self, packet: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        if self.next_f64() < self.config.drop_rate {
            return vec![];
        }

        let delay_ms = if self.config.max_jitter_ms > 0 {
            self.next_u64() % (self.config.max_jitter_ms + 1)
        } else {
            0
        };

        let reorder = self.next_f64() < self.config.reorder_rate;

        if delay_ms > 0 || reorder {
            let release = now + Duration::from_millis(delay_ms);
            self.pending.push_back((packet, release));
            return self.flush_ready(now);
        }

        let mut out = self.flush_ready(now);
        out.push(packet);
        out
    }

    pub fn flush_ready(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while self
            .pending
            .front()
            .map(|(_, t)| *t <= now)
            .unwrap_or(false)
        {
            if let Some((pkt, _)) = self.pending.pop_front() {
                out.push(pkt);
            }
        }
        out
    }

    fn next_u64(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_drop_rate_passes_all() {
        let mut chaos = ChaosMiddleware::new(ChaosConfig::none());
        let now = Instant::now();
        for _ in 0..100 {
            let out = chaos.intercept(vec![1, 2, 3], now);
            assert_eq!(out.len(), 1);
        }
    }

    #[test]
    fn full_drop_rate_drops_all() {
        let mut chaos = ChaosMiddleware::new(ChaosConfig {
            drop_rate: 1.0,
            reorder_rate: 0.0,
            max_jitter_ms: 0,
        });
        let now = Instant::now();
        for _ in 0..100 {
            let out = chaos.intercept(vec![1, 2, 3], now);
            assert!(out.is_empty());
        }
    }

    #[test]
    fn ten_percent_drop_rate_is_approximate() {
        let mut chaos = ChaosMiddleware::new(ChaosConfig::packet_loss(0.10));
        let now = Instant::now();
        let mut passed = 0usize;
        for _ in 0..10_000 {
            let out = chaos.intercept(vec![1], now);
            passed += out.len();
        }
        assert!(passed > 8700 && passed < 9300, "passed = {passed}");
    }

    #[test]
    fn reordered_packets_released_when_time_advances() {
        let mut chaos = ChaosMiddleware::new(ChaosConfig {
            drop_rate: 0.0,
            reorder_rate: 1.0,
            max_jitter_ms: 100,
        });
        let t0 = Instant::now();
        chaos.intercept(vec![1], t0);
        chaos.intercept(vec![2], t0);
        let early = chaos.flush_ready(t0);
        assert!(early.is_empty());
        let late = chaos.flush_ready(t0 + Duration::from_millis(200));
        assert_eq!(late.len(), 2);
    }
}
