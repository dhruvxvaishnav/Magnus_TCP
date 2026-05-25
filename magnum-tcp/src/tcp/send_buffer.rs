#![allow(dead_code)]

pub const SEND_BUF_SIZE: usize = 65536;

pub struct SendBuffer {
    buf: Box<[u8; SEND_BUF_SIZE]>,
    head: usize,
    len: usize,
    una: u32,
    nxt: u32,
}

impl SendBuffer {
    pub fn new(iss: u32) -> Self {
        Self {
            buf: Box::new([0u8; SEND_BUF_SIZE]),
            head: 0,
            len: 0,
            una: iss.wrapping_add(1),
            nxt: iss.wrapping_add(1),
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let space = SEND_BUF_SIZE - self.len;
        let n = data.len().min(space);
        let tail = (self.head + self.len) % SEND_BUF_SIZE;
        for (i, &b) in data[..n].iter().enumerate() {
            self.buf[(tail + i) % SEND_BUF_SIZE] = b;
        }
        self.len += n;
        n
    }

    pub fn next_segment(&self, max_len: usize) -> Option<(u32, Vec<u8>)> {
        let inflight = self.nxt.wrapping_sub(self.una) as usize;
        if inflight >= self.len {
            return None;
        }
        let available = self.len - inflight;
        let n = available.min(max_len);
        if n == 0 {
            return None;
        }
        let start = (self.head + inflight) % SEND_BUF_SIZE;
        let mut seg = Vec::with_capacity(n);
        for i in 0..n {
            seg.push(self.buf[(start + i) % SEND_BUF_SIZE]);
        }
        Some((self.nxt, seg))
    }

    pub fn advance_nxt(&mut self, n: usize) {
        self.nxt = self.nxt.wrapping_add(n as u32);
    }

    pub fn acknowledge(&mut self, ack: u32) {
        let newly_acked = ack.wrapping_sub(self.una) as usize;
        if newly_acked == 0 || newly_acked > self.len {
            return;
        }
        self.head = (self.head + newly_acked) % SEND_BUF_SIZE;
        self.len -= newly_acked;
        self.una = ack;
    }

    pub fn una(&self) -> u32 {
        self.una
    }

    pub fn nxt(&self) -> u32 {
        self.nxt
    }

    pub fn buffered(&self) -> usize {
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
    fn write_and_read_single_segment() {
        let mut sb = SendBuffer::new(0);
        sb.write(b"hello");
        let (seq, data) = sb.next_segment(1024).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn acknowledge_advances_una() {
        let mut sb = SendBuffer::new(0);
        sb.write(b"hello");
        let (seq, data) = sb.next_segment(1024).unwrap();
        sb.advance_nxt(data.len());
        sb.acknowledge(seq.wrapping_add(data.len() as u32));
        assert!(sb.next_segment(1024).is_none());
        assert!(sb.is_empty());
    }

    #[test]
    fn partial_acknowledge() {
        let mut sb = SendBuffer::new(0);
        sb.write(b"helloworld");
        let (seq, data) = sb.next_segment(5).unwrap();
        assert_eq!(&data, b"hello");
        sb.advance_nxt(5);
        sb.acknowledge(seq.wrapping_add(5));

        let (seq2, data2) = sb.next_segment(1024).unwrap();
        assert_eq!(&data2, b"world");
        sb.advance_nxt(5);
        sb.acknowledge(seq2.wrapping_add(5));
        assert!(sb.is_empty());
    }

    #[test]
    fn respects_max_len() {
        let mut sb = SendBuffer::new(99);
        sb.write(b"abcdefgh");
        let (_, data) = sb.next_segment(4).unwrap();
        assert_eq!(&data, b"abcd");
    }

    #[test]
    fn write_respects_capacity() {
        let mut sb = SendBuffer::new(0);
        let big = vec![0u8; SEND_BUF_SIZE + 100];
        let n = sb.write(&big);
        assert_eq!(n, SEND_BUF_SIZE);
    }

    #[test]
    fn wraparound_write() {
        let mut sb = SendBuffer::new(0);
        let half = vec![b'a'; SEND_BUF_SIZE / 2];
        sb.write(&half);
        let (seq, data) = sb.next_segment(SEND_BUF_SIZE / 2).unwrap();
        sb.advance_nxt(data.len());
        sb.acknowledge(seq.wrapping_add(data.len() as u32));

        let second = vec![b'b'; SEND_BUF_SIZE / 2 + 10];
        let written = sb.write(&second);
        assert_eq!(written, SEND_BUF_SIZE / 2 + 10);
        let (_, seg) = sb.next_segment(SEND_BUF_SIZE).unwrap();
        assert_eq!(seg.len(), SEND_BUF_SIZE / 2 + 10);
        assert!(seg.iter().all(|&b| b == b'b'));
    }

    #[test]
    fn seq_starts_after_iss() {
        let mut sb = SendBuffer::new(999);
        sb.write(b"x");
        let (seq, _) = sb.next_segment(1).unwrap();
        assert_eq!(seq, 1000);
        assert_eq!(sb.una(), 1000);
    }
}
