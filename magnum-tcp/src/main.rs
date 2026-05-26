mod chaos;
mod error;
mod ethernet;
mod ipv4;
mod tcp;
mod tun;

use tracing::error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        error!("Magnum-TCP requires Linux or macOS");
        std::process::exit(1);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        info!("Magnum-TCP starting");
        run();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run() {
    use crate::tcp::Stack;
    use tracing::warn;

    #[cfg(target_os = "linux")]
    const TUN_NAME: &str = "tun0";
    #[cfg(target_os = "macos")]
    const TUN_NAME: &str = "utun5";

    const LISTEN_PORT: u16 = 80;
    const MTU: usize = 1500;
    const STAGING_BUF: usize = MTU * 2;

    let mut tun = match tun::Tun::open(TUN_NAME) {
        Ok(t) => {
            info!("interface {} opened", t.name());
            t
        }
        Err(e) => {
            error!("failed to open device: {}", e);
            std::process::exit(1);
        }
    };

    let mut stack = Stack::new();
    stack.listen(LISTEN_PORT);

    let mut buf = [0u8; STAGING_BUF];

    loop {
        let n = match tun.recv(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) => {
                error!("read error: {}", e);
                break;
            }
        };

        match dispatch(&buf[..n], &mut stack) {
            Some(response) => {
                if let Err(e) = tun.send(&response) {
                    warn!("write error: {}", e);
                }
            }
            None => {}
        }
    }
}

// Linux dispatch: TAP delivers full Ethernet frames.
// Response is an Ethernet frame wrapping the IP reply.
#[cfg(target_os = "linux")]
fn dispatch(raw: &[u8], stack: &mut tcp::Stack) -> Option<Vec<u8>> {
    use crate::error::MagnumError;
    use crate::ethernet::EthernetFrame;
    use crate::ipv4::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, build_packet, format_ip};
    use crate::tcp::OutboundPacket;
    use crate::tcp::header::TcpSegment;
    use tracing::warn;

    let frame = match EthernetFrame::parse(raw) {
        Ok(f) => f,
        Err(MagnumError::NonIpv4EtherType(et)) => {
            warn!(
                ethertype = format!("0x{:04X}", et),
                "dropped non-IPv4 frame"
            );
            return None;
        }
        Err(e) => {
            warn!(error = %e, "malformed ethernet frame dropped");
            return None;
        }
    };

    let packet = match Ipv4Packet::parse(frame.payload) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "malformed IPv4 packet dropped");
            return None;
        }
    };

    match packet.header.protocol {
        PROTO_ICMP => {
            info!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                "ICMP received"
            );
            None
        }
        PROTO_TCP => {
            let seg = match TcpSegment::parse(packet.payload, packet.header.src, packet.header.dst)
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "malformed TCP segment dropped");
                    return None;
                }
            };

            info!(
                src = format!("{}:{}", format_ip(&packet.header.src), seg.header.src_port),
                dst = format!("{}:{}", format_ip(&packet.header.dst), seg.header.dst_port),
                flags = format!("{:08b}", seg.header.flags.to_byte()),
                seq = seg.header.seq,
                "TCP segment"
            );

            let OutboundPacket {
                src_ip,
                dst_ip,
                tcp_bytes,
            } = stack.process(packet.header.src, packet.header.dst, &seg)?;

            let ip_bytes = build_packet(src_ip, dst_ip, PROTO_TCP, &tcp_bytes);
            Some(EthernetFrame::build(
                frame.src_mac,
                frame.dst_mac,
                &ip_bytes,
            ))
        }
        proto => {
            warn!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                protocol = proto,
                "unknown protocol dropped"
            );
            None
        }
    }
}

// macOS dispatch: utun delivers raw IP packets (no Ethernet header).
// Tun::recv already strips the 4-byte AF prefix; Tun::send re-adds it.
// Response is a plain IP packet.
#[cfg(target_os = "macos")]
fn dispatch(raw: &[u8], stack: &mut tcp::Stack) -> Option<Vec<u8>> {
    use crate::ipv4::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, build_packet, format_ip};
    use crate::tcp::OutboundPacket;
    use crate::tcp::header::TcpSegment;
    use tracing::warn;

    let packet = match Ipv4Packet::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "malformed IPv4 packet dropped");
            return None;
        }
    };

    match packet.header.protocol {
        PROTO_ICMP => {
            info!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                "ICMP received"
            );
            None
        }
        PROTO_TCP => {
            let seg = match TcpSegment::parse(packet.payload, packet.header.src, packet.header.dst)
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "malformed TCP segment dropped");
                    return None;
                }
            };

            info!(
                src = format!("{}:{}", format_ip(&packet.header.src), seg.header.src_port),
                dst = format!("{}:{}", format_ip(&packet.header.dst), seg.header.dst_port),
                flags = format!("{:08b}", seg.header.flags.to_byte()),
                seq = seg.header.seq,
                "TCP segment"
            );

            let OutboundPacket {
                src_ip,
                dst_ip,
                tcp_bytes,
            } = stack.process(packet.header.src, packet.header.dst, &seg)?;

            Some(build_packet(src_ip, dst_ip, PROTO_TCP, &tcp_bytes))
        }
        proto => {
            warn!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                protocol = proto,
                "unknown protocol dropped"
            );
            None
        }
    }
}
