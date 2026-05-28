#![allow(dead_code)]

use crate::ethernet::ETHERNET_HEADER_LEN;

const ARP_PAYLOAD_LEN: usize = 28;
const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN;

const HTYPE_ETHERNET: [u8; 2] = [0x00, 0x01];
const PTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const HLEN_MAC: u8 = 6;
const PLEN_IP: u8 = 4;
const OPER_REQUEST: [u8; 2] = [0x00, 0x01];
const OPER_REPLY: [u8; 2] = [0x00, 0x02];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];

pub struct ArpRequest {
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_ip: [u8; 4],
}

pub fn parse_arp_request(raw_frame: &[u8]) -> Option<ArpRequest> {
    if raw_frame.len() < ARP_FRAME_LEN {
        return None;
    }

    let arp = &raw_frame[ETHERNET_HEADER_LEN..];

    if arp[0..2] != HTYPE_ETHERNET {
        return None;
    }
    if arp[2..4] != PTYPE_IPV4 {
        return None;
    }
    if arp[4] != HLEN_MAC || arp[5] != PLEN_IP {
        return None;
    }
    if arp[6..8] != OPER_REQUEST {
        return None;
    }

    let mut sender_mac = [0u8; 6];
    let mut sender_ip = [0u8; 4];
    let mut target_ip = [0u8; 4];
    sender_mac.copy_from_slice(&arp[8..14]);
    sender_ip.copy_from_slice(&arp[14..18]);
    target_ip.copy_from_slice(&arp[24..28]);

    Some(ArpRequest {
        sender_mac,
        sender_ip,
        target_ip,
    })
}

pub fn build_arp_reply_frame(
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    requester_mac: [u8; 6],
    requester_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = vec![0u8; ARP_FRAME_LEN];

    frame[0..6].copy_from_slice(&requester_mac);
    frame[6..12].copy_from_slice(&our_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP);

    let arp = &mut frame[ETHERNET_HEADER_LEN..];
    arp[0..2].copy_from_slice(&HTYPE_ETHERNET);
    arp[2..4].copy_from_slice(&PTYPE_IPV4);
    arp[4] = HLEN_MAC;
    arp[5] = PLEN_IP;
    arp[6..8].copy_from_slice(&OPER_REPLY);
    arp[8..14].copy_from_slice(&our_mac);
    arp[14..18].copy_from_slice(&our_ip);
    arp[18..24].copy_from_slice(&requester_mac);
    arp[24..28].copy_from_slice(&requester_ip);

    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_request_frame(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut frame = vec![0u8; ARP_FRAME_LEN];
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP);
        let arp = &mut frame[ETHERNET_HEADER_LEN..];
        arp[0..2].copy_from_slice(&HTYPE_ETHERNET);
        arp[2..4].copy_from_slice(&PTYPE_IPV4);
        arp[4] = HLEN_MAC;
        arp[5] = PLEN_IP;
        arp[6..8].copy_from_slice(&OPER_REQUEST);
        arp[8..14].copy_from_slice(&sender_mac);
        arp[14..18].copy_from_slice(&sender_ip);
        arp[24..28].copy_from_slice(&target_ip);
        frame
    }

    #[test]
    fn parse_valid_arp_request() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let sender_ip = [10, 0, 0, 1];
        let target_ip = [192, 168, 100, 2];
        let frame = make_arp_request_frame(mac, sender_ip, target_ip);
        let req = parse_arp_request(&frame).unwrap();
        assert_eq!(req.sender_mac, mac);
        assert_eq!(req.sender_ip, sender_ip);
        assert_eq!(req.target_ip, target_ip);
    }

    #[test]
    fn reject_arp_reply_as_not_request() {
        let mut frame = make_arp_request_frame([0u8; 6], [0u8; 4], [0u8; 4]);
        frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8].copy_from_slice(&OPER_REPLY);
        assert!(parse_arp_request(&frame).is_none());
    }

    #[test]
    fn arp_reply_frame_has_correct_fields() {
        let our_mac = [0x0a, 0xb1, 0xe9, 0x00, 0x00, 0x01];
        let our_ip = [192, 168, 100, 2];
        let req_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let req_ip = [10, 0, 0, 1];

        let reply = build_arp_reply_frame(our_mac, our_ip, req_mac, req_ip);

        assert_eq!(reply.len(), ARP_FRAME_LEN);
        assert_eq!(&reply[0..6], &req_mac);
        assert_eq!(&reply[6..12], &our_mac);
        assert_eq!(&reply[12..14], &ETHERTYPE_ARP);

        let arp = &reply[ETHERNET_HEADER_LEN..];
        assert_eq!(&arp[6..8], &OPER_REPLY);
        assert_eq!(&arp[8..14], &our_mac);
        assert_eq!(&arp[14..18], &our_ip);
        assert_eq!(&arp[18..24], &req_mac);
        assert_eq!(&arp[24..28], &req_ip);
    }
}
