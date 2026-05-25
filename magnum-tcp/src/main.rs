mod error;
mod ethernet;
mod ipv4;
mod tun;

use error::MagnumError;
use ethernet::EthernetFrame;
use ipv4::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, format_ip};
use tracing::{error, info, warn};

const TUN_NAME: &str = "tun0";
const MTU: usize = 1500;
const STAGING_BUF: usize = MTU * 2;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Magnum-TCP starting on interface {}", TUN_NAME);

    #[cfg(not(target_os = "linux"))]
    {
        error!("Magnum-TCP requires Linux for TUN/TAP support");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    run();
}

#[cfg(target_os = "linux")]
fn run() {
    let mut tun = match tun::Tun::open(TUN_NAME) {
        Ok(t) => {
            info!("TUN interface {} opened", t.name());
            t
        }
        Err(e) => {
            error!("Failed to open TUN device: {}", e);
            std::process::exit(1);
        }
    };

    let mut buf = [0u8; STAGING_BUF];

    loop {
        let n = match tun.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                error!("TUN read error: {}", e);
                break;
            }
        };

        dispatch(&buf[..n]);
    }
}

fn dispatch(raw: &[u8]) {
    let frame = match EthernetFrame::parse(raw) {
        Ok(f) => f,
        Err(MagnumError::NonIpv4EtherType(et)) => {
            warn!(
                ethertype = format!("0x{:04X}", et),
                "dropped non-IPv4 frame"
            );
            return;
        }
        Err(e) => {
            warn!(error = %e, "malformed ethernet frame dropped");
            return;
        }
    };

    let packet = match Ipv4Packet::parse(frame.payload) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "malformed IPv4 packet dropped");
            return;
        }
    };

    let src = format_ip(&packet.header.src);
    let dst = format_ip(&packet.header.dst);

    match packet.header.protocol {
        PROTO_ICMP => {
            info!(
                src = src,
                dst = dst,
                payload_len = packet.payload.len(),
                "ICMP packet received"
            );
        }
        PROTO_TCP => {
            info!(
                src = src,
                dst = dst,
                payload_len = packet.payload.len(),
                "TCP segment received (unhandled)"
            );
        }
        proto => {
            warn!(
                src = src,
                dst = dst,
                protocol = proto,
                "unknown protocol dropped"
            );
        }
    }
}
