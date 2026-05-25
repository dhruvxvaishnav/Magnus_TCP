use crate::error::{MagnumError, Result};

pub const IPV4_MIN_HEADER_LEN: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub ihl: u8,
    pub dscp: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: u8,
    pub frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub header: Ipv4Header,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < IPV4_MIN_HEADER_LEN {
            return Err(MagnumError::Ipv4HeaderTooShort {
                got: raw.len(),
                need: IPV4_MIN_HEADER_LEN,
            });
        }

        let ihl = raw[0] & 0x0F;

        if ihl < 5 {
            return Err(MagnumError::Ipv4IhlTooSmall(ihl));
        }

        let header_len = (ihl as usize) * 4;

        if raw.len() < header_len {
            return Err(MagnumError::Ipv4HeaderTooShort {
                got: raw.len(),
                need: header_len,
            });
        }

        let stored_checksum = u16::from_be_bytes([raw[10], raw[11]]);
        let computed = checksum(&raw[..header_len]);

        if computed != 0 {
            return Err(MagnumError::Ipv4ChecksumMismatch {
                computed,
                got: stored_checksum,
            });
        }

        let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;

        if total_len > raw.len() {
            return Err(MagnumError::Ipv4TruncatedPacket {
                total_len,
                buf_len: raw.len(),
            });
        }

        let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);

        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&raw[12..16]);
        dst.copy_from_slice(&raw[16..20]);

        let header = Ipv4Header {
            ihl,
            dscp: (raw[1] >> 2) & 0x3F,
            total_len: total_len as u16,
            id: u16::from_be_bytes([raw[4], raw[5]]),
            flags: ((flags_frag >> 13) & 0x07) as u8,
            frag_offset: flags_frag & 0x1FFF,
            ttl: raw[8],
            protocol: raw[9],
            checksum: stored_checksum,
            src,
            dst,
        };

        Ok(Self {
            header,
            payload: &raw[header_len..total_len],
        })
    }
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn format_ip(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_ipv4_header(protocol: u8, payload_len: u16) -> Vec<u8> {
        let total_len = (IPV4_MIN_HEADER_LEN as u16) + payload_len;
        let mut hdr = vec![
            0x45, 0x00,
            (total_len >> 8) as u8, total_len as u8,
            0x00, 0x01,
            0x40, 0x00,
            0x40, protocol,
            0x00, 0x00,
            192, 168, 1, 1,
            10, 0, 0, 1,
        ];
        let csum = checksum(&hdr);
        hdr[10] = (csum >> 8) as u8;
        hdr[11] = csum as u8;
        hdr
    }

    #[test]
    fn parses_valid_header() {
        let mut pkt = valid_ipv4_header(PROTO_TCP, 4);
        pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let parsed = Ipv4Packet::parse(&pkt).unwrap();
        assert_eq!(parsed.header.protocol, PROTO_TCP);
        assert_eq!(parsed.header.src, [192, 168, 1, 1]);
        assert_eq!(parsed.header.dst, [10, 0, 0, 1]);
        assert_eq!(parsed.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut pkt = valid_ipv4_header(PROTO_TCP, 0);
        pkt[10] ^= 0xFF;
        assert!(matches!(
            Ipv4Packet::parse(&pkt),
            Err(MagnumError::Ipv4ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_too_short() {
        let pkt = [0u8; 10];
        assert!(matches!(
            Ipv4Packet::parse(&pkt),
            Err(MagnumError::Ipv4HeaderTooShort { .. })
        ));
    }

    #[test]
    fn rejects_small_ihl() {
        let mut pkt = valid_ipv4_header(PROTO_TCP, 0);
        pkt[0] = (pkt[0] & 0xF0) | 0x03;
        assert!(matches!(
            Ipv4Packet::parse(&pkt),
            Err(MagnumError::Ipv4IhlTooSmall(3))
        ));
    }

    #[test]
    fn checksum_of_valid_header_is_zero() {
        let pkt = valid_ipv4_header(PROTO_ICMP, 0);
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn checksum_known_value() {
        let data: &[u8] = &[0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                             0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                             0xac, 0x10, 0x0a, 0x0c];
        let csum = checksum(data);
        assert_eq!(checksum(&{
            let mut v = data.to_vec();
            v[10] = (csum >> 8) as u8;
            v[11] = csum as u8;
            v
        }), 0);
    }
}
