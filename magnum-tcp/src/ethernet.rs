use crate::error::{MagnumError, Result};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < ETHERNET_HEADER_LEN {
            return Err(MagnumError::EthernetFrameTooShort {
                got: raw.len(),
                need: ETHERNET_HEADER_LEN,
            });
        }

        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

        if ethertype != ETHERTYPE_IPV4 {
            return Err(MagnumError::NonIpv4EtherType(ethertype));
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&raw[0..6]);
        src_mac.copy_from_slice(&raw[6..12]);

        Ok(Self {
            dst_mac,
            src_mac,
            ethertype,
            payload: &raw[ETHERNET_HEADER_LEN..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
        frame[12] = (ethertype >> 8) as u8;
        frame[13] = ethertype as u8;
        frame[ETHERNET_HEADER_LEN..].copy_from_slice(payload);
        frame
    }

    #[test]
    fn accepts_ipv4() {
        let frame = make_frame(ETHERTYPE_IPV4, &[0xDE, 0xAD]);
        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.payload, &[0xDE, 0xAD]);
    }

    #[test]
    fn drops_arp() {
        let frame = make_frame(0x0806, &[]);
        assert!(matches!(
            EthernetFrame::parse(&frame),
            Err(MagnumError::NonIpv4EtherType(0x0806))
        ));
    }

    #[test]
    fn drops_ipv6() {
        let frame = make_frame(0x86DD, &[]);
        assert!(matches!(
            EthernetFrame::parse(&frame),
            Err(MagnumError::NonIpv4EtherType(0x86DD))
        ));
    }

    #[test]
    fn too_short() {
        let frame = [0u8; 10];
        assert!(matches!(
            EthernetFrame::parse(&frame),
            Err(MagnumError::EthernetFrameTooShort { .. })
        ));
    }
}
