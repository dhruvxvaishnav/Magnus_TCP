#![allow(dead_code)]

use std::collections::BTreeMap;

use super::tcb::seq_lt;

pub const RECV_BUF_SIZE: usize = 65536;

pub struct RecvBuffer {
    buf: Box<[u8; RECV_BUF_SIZE]>,
    head: usize,
    len: usize,
    nxt: u32,
    ooo: BTreeMap<u32, Vec<u8>>,
}

impl RecvBuffer {
    pub fn new(irs: u32) -> Self {
        Self {
            buf: Box::new([0u8; RECV_BUF_SIZE]),
            head: 0,
            len: 0,
            nxt: irs.wrapping_add(1),
            ooo: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, seq: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let trim = if seq_lt(seq, self.nxt) {
            let past = self.nxt.wrapping_sub(seq) as usize;
            if past >= data.len() {
                return;
            }
            past
        } else {
            0
        };

        let effective_seq = seq.wrapping_add(trim as u32);
        let effective_data = &data[trim..];

        if effective_seq == self.nxt {
            self.commit(effective_data);
            self.drain_ooo();
        } else {
            self.ooo
                .entry(effective_seq)
                .or_insert_with(|| effective_data.to_vec());
        }
    }

    fn commit(&mut self, data: &[u8]) {
        let space = RECV_BUF_SIZE - self.len;
        let n = data.len().min(space);
        let tail = (self.head + self.len) % RECV_BUF_SIZE;
        for (i, &b) in data[..n].iter().enumerate() {
            self.buf[(tail + i) % RECV_BUF_SIZE] = b;
        }
        self.len += n;
        self.nxt = self.nxt.wrapping_add(n as u32);
    }

    fn drain_ooo(&mut self) {
        while let Some(key) = self.ooo.keys().next().copied() {
            if key != self.nxt {
                break;
            }
            let data = self.ooo.remove(&key).unwrap();
            self.commit(&data);
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len);
        for (i, slot) in buf.iter_mut().enumerate().take(n) {
            *slot = self.buf[(self.head + i) % RECV_BUF_SIZE];
        }
        self.head = (self.head + n) % RECV_BUF_SIZE;
        self.len -= n;
        n
    }

    pub fn next_expected(&self) -> u32 {
        self.nxt
    }

    pub fn window(&self) -> u16 {
        (RECV_BUF_SIZE - self.len).min(u16::MAX as usize) as u16
    }

    pub fn available(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_insert_and_read() {
        let mut rb = RecvBuffer::new(0);
        rb.insert(1, b"hello");
        assert_eq!(rb.available(), 5);
        let mut out = [0u8; 5];
        let n = rb.read(&mut out);
        assert_eq!(n, 5);
        assert_eq!(&out, b"hello");
        assert!(rb.is_empty());
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut rb = RecvBuffer::new(0);
        rb.insert(6, b"world");
        assert_eq!(rb.available(), 0);
        rb.insert(1, b"hello");
        assert_eq!(rb.available(), 10);
        let mut out = [0u8; 10];
        let n = rb.read(&mut out);
        assert_eq!(n, 10);
        assert_eq!(&out, b"helloworld");
    }

    #[test]
    fn next_expected_advances() {
        let mut rb = RecvBuffer::new(99);
        assert_eq!(rb.next_expected(), 100);
        rb.insert(100, b"abc");
        assert_eq!(rb.next_expected(), 103);
    }

    #[test]
    fn window_shrinks_as_buffer_fills() {
        let mut rb = RecvBuffer::new(0);
        assert_eq!(rb.window(), u16::MAX); // capped at u16::MAX since RECV_BUF_SIZE > u16::MAX
        rb.insert(1, &vec![0u8; 1000]);
        assert_eq!(rb.window() as usize, RECV_BUF_SIZE - 1000);
    }

    #[test]
    fn partial_read() {
        let mut rb = RecvBuffer::new(0);
        rb.insert(1, b"helloworld");
        let mut out = [0u8; 5];
        assert_eq!(rb.read(&mut out), 5);
        assert_eq!(&out, b"hello");
        assert_eq!(rb.available(), 5);
        let mut out2 = [0u8; 5];
        assert_eq!(rb.read(&mut out2), 5);
        assert_eq!(&out2, b"world");
    }

    #[test]
    fn large_transfer_in_order() {
        let mut rb = RecvBuffer::new(0);
        let payload: Vec<u8> = (0..255u8).cycle().take(1024 * 1024).collect();
        let chunk = 1400;
        let mut seq: u32 = 1;
        let mut total_read = 0usize;
        let mut readback = Vec::new();

        for chunk_data in payload.chunks(chunk) {
            rb.insert(seq, chunk_data);
            seq = seq.wrapping_add(chunk_data.len() as u32);

            let mut tmp = vec![0u8; rb.available()];
            let n = rb.read(&mut tmp);
            readback.extend_from_slice(&tmp[..n]);
            total_read += n;
        }

        assert_eq!(total_read, payload.len());
        assert_eq!(readback, payload);
    }

    #[test]
    fn large_transfer_out_of_order() {
        let mut rb = RecvBuffer::new(0);
        let payload: Vec<u8> = (0..255u8).cycle().take(4096).collect();
        let chunks: Vec<(u32, Vec<u8>)> = payload
            .chunks(256)
            .scan(1u32, |seq, chunk| {
                let s = *seq;
                *seq = seq.wrapping_add(chunk.len() as u32);
                Some((s, chunk.to_vec()))
            })
            .collect();

        for (seq, data) in chunks.iter().step_by(2) {
            rb.insert(*seq, data);
        }
        for (seq, data) in chunks.iter().skip(1).step_by(2) {
            rb.insert(*seq, data);
        }

        let mut out = vec![0u8; 4096];
        let n = rb.read(&mut out);
        assert_eq!(n, 4096);
        assert_eq!(out, payload);
    }

    #[test]
    fn duplicate_segment_ignored() {
        let mut rb = RecvBuffer::new(0);
        rb.insert(1, b"hello");
        rb.insert(1, b"hello");
        assert_eq!(rb.available(), 5);
    }

    #[test]
    fn partial_overlap_trimmed() {
        let mut rb = RecvBuffer::new(0);
        rb.insert(1, b"hello");
        // seq=4, nxt=6 → trim 2 bytes → effective "world" committed at nxt
        rb.insert(4, b"loworld");
        assert_eq!(rb.available(), 10);
        let mut out = [0u8; 10];
        rb.read(&mut out);
        assert_eq!(&out, b"helloworld");
    }
}
