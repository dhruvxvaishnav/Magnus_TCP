#![allow(dead_code)]

use crate::error::{MagnumError, Result};

pub const TCP_MIN_HEADER_LEN: usize = 20;
pub const RECV_WINDOW: u16 = 65535;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn from_byte(b: u8) -> Self {
        Self {
            urg: b & 0x20 != 0,
            ack: b & 0x10 != 0,
            psh: b & 0x08 != 0,
            rst: b & 0x04 != 0,
            syn: b & 0x02 != 0,
            fin: b & 0x01 != 0,
        }
    }

    pub fn to_byte(self) -> u8 {
        ((self.urg as u8) << 5)
            | ((self.ack as u8) << 4)
            | ((self.psh as u8) << 3)
            | ((self.rst as u8) << 2)
            | ((self.syn as u8) << 1)
            | (self.fin as u8)
    }
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug)]
pub struct TcpSegment<'a> {
    pub header: TcpHeader,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(raw: &'a [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Result<Self> {
        if raw.len() < TCP_MIN_HEADER_LEN {
            return Err(MagnumError::TcpHeaderTooShort {
                got: raw.len(),
                need: TCP_MIN_HEADER_LEN,
            });
        }

        let data_offset = (raw[12] >> 4) & 0x0F;

        if data_offset < 5 {
            return Err(MagnumError::TcpDataOffsetTooSmall(data_offset));
        }

        let header_len = (data_offset as usize) * 4;

        if raw.len() < header_len {
            return Err(MagnumError::TcpHeaderTooShort {
                got: raw.len(),
                need: header_len,
            });
        }

        let stored_checksum = u16::from_be_bytes([raw[16], raw[17]]);
        let computed = tcp_checksum(raw, src_ip, dst_ip);

        if computed != 0 {
            return Err(MagnumError::TcpChecksumMismatch {
                computed,
                got: stored_checksum,
            });
        }

        let header = TcpHeader {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            seq: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            ack_num: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            data_offset,
            flags: TcpFlags::from_byte(raw[13]),
            window: u16::from_be_bytes([raw[14], raw[15]]),
            checksum: stored_checksum,
            urgent_ptr: u16::from_be_bytes([raw[18], raw[19]]),
        };

        Ok(Self {
            header,
            payload: &raw[header_len..],
        })
    }
}

pub fn tcp_checksum(tcp_segment: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> u16 {
    let tcp_len = tcp_segment.len() as u32;
    let mut sum: u32 = 0;

    // RFC 793 pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += u32::from(crate::ipv4::PROTO_TCP);
    sum += tcp_len;

    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub struct SegmentBuilder {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_num: u32,
    flags: TcpFlags,
    window: u16,
    payload: Vec<u8>,
}

impl SegmentBuilder {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq: 0,
            ack_num: 0,
            flags: TcpFlags::default(),
            window: RECV_WINDOW,
            payload: Vec::new(),
        }
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    pub fn ack(mut self, ack_num: u32) -> Self {
        self.ack_num = ack_num;
        self
    }

    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    pub fn build(self) -> Vec<u8> {
        let total = TCP_MIN_HEADER_LEN + self.payload.len();
        let mut buf = vec![0u8; total];

        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        buf[12] = 0x50;
        buf[13] = self.flags.to_byte();
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[TCP_MIN_HEADER_LEN..].copy_from_slice(&self.payload);

        let csum = tcp_checksum(&buf, self.src_ip, self.dst_ip);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
    const SERVER_IP: [u8; 4] = [192, 168, 100, 2];
    const CLIENT_PORT: u16 = 54321;
    const SERVER_PORT: u16 = 80;

    fn build_syn(seq: u32) -> Vec<u8> {
        SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(seq)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build()
    }

    #[test]
    fn flags_roundtrip() {
        let original = TcpFlags {
            urg: false,
            ack: true,
            psh: false,
            rst: false,
            syn: true,
            fin: false,
        };
        let encoded = original.to_byte();
        let decoded = TcpFlags::from_byte(encoded);
        assert_eq!(decoded.ack, original.ack);
        assert_eq!(decoded.syn, original.syn);
        assert!(!decoded.rst);
        assert!(!decoded.fin);
    }

    #[test]
    fn parse_valid_syn() {
        let raw = build_syn(1000);
        let seg = TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP).unwrap();
        assert_eq!(seg.header.src_port, CLIENT_PORT);
        assert_eq!(seg.header.dst_port, SERVER_PORT);
        assert_eq!(seg.header.seq, 1000);
        assert!(seg.header.flags.syn);
        assert!(!seg.header.flags.ack);
        assert!(seg.payload.is_empty());
    }

    #[test]
    fn reject_bad_checksum() {
        let mut raw = build_syn(500);
        raw[16] ^= 0xFF;
        assert!(matches!(
            TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP),
            Err(MagnumError::TcpChecksumMismatch { .. })
        ));
    }

    #[test]
    fn reject_too_short() {
        let raw = [0u8; 10];
        assert!(matches!(
            TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP),
            Err(MagnumError::TcpHeaderTooShort { .. })
        ));
    }

    #[test]
    fn reject_small_data_offset() {
        let mut raw = build_syn(0);
        raw[12] = 0x30; // data_offset = 3, below minimum of 5
        assert!(matches!(
            TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP),
            Err(MagnumError::TcpDataOffsetTooSmall(3))
        ));
    }

    #[test]
    fn syn_ack_has_valid_checksum() {
        let syn_ack = SegmentBuilder::new(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
            .seq(9999)
            .ack(1001)
            .flags(TcpFlags {
                syn: true,
                ack: true,
                ..TcpFlags::default()
            })
            .build();

        assert_eq!(tcp_checksum(&syn_ack, SERVER_IP, CLIENT_IP), 0);
    }

    #[test]
    fn checksum_verify_over_syn() {
        let raw = build_syn(42);
        assert_eq!(tcp_checksum(&raw, CLIENT_IP, SERVER_IP), 0);
    }
}
