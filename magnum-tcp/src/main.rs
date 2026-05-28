mod arp;
mod chaos;
mod error;
mod ethernet;
mod ipv4;
mod pcap;
mod tcp;
mod tun;

use clap::Parser;
use tracing::error;

#[derive(Parser)]
#[command(
    name = "magnum-tcp",
    about = "Zero-dependency userspace TCP/IPv4 stack"
)]
struct Cli {
    #[arg(long, action = clap::ArgAction::Append, default_value = "80")]
    port: Vec<u16>,

    #[arg(long, default_value = "192.168.100.2")]
    bind_ip: String,

    #[arg(long, default_value_t = 0.0, help = "Packet drop rate [0.0-1.0]")]
    chaos: f64,

    #[arg(long, default_value_t = 0.0, help = "Packet reorder rate [0.0-1.0]")]
    chaos_reorder: f64,

    #[arg(
        long,
        default_value_t = 0,
        help = "Max outbound jitter in milliseconds"
    )]
    chaos_jitter_ms: u64,
}

#[tokio::main]
async fn main() {
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
        use tracing::info;
        let args = Cli::parse();
        info!("Magnum-TCP starting on ports {:?}", args.port);
        if let Err(e) = run(args).await {
            error!("fatal: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_ip(s: &str) -> crate::error::Result<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(crate::error::MagnumError::InvalidIp(s.to_string()));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p
            .parse::<u8>()
            .map_err(|_| crate::error::MagnumError::InvalidIp(s.to_string()))?;
    }
    Ok(out)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run(args: Cli) -> crate::error::Result<()> {
    use crate::chaos::{ChaosConfig, ChaosMiddleware};
    use crate::tcp::AsyncDispatch;
    use crate::tcp::task::OutboundMsg;
    use std::time::Instant;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    #[cfg(target_os = "linux")]
    const TUN_NAME: &str = "tap0";
    #[cfg(target_os = "macos")]
    const TUN_NAME: &str = "utun5";

    const MTU: usize = 1500;
    const STAGING_BUF: usize = MTU * 2;

    let our_ip = parse_ip(&args.bind_ip)?;

    let tun_device = tun::Tun::open(TUN_NAME)?;
    tun_device.set_nonblocking()?;

    #[cfg(target_os = "linux")]
    let our_mac = tun_device
        .mac_address()
        .unwrap_or([0x0a, 0xb1, 0xe9, 0x00, 0x00, 0x01]);
    #[cfg(target_os = "macos")]
    let our_mac = [0u8; 6];

    info!("interface {} opened (async)", TUN_NAME);

    let async_tun = AsyncFd::new(tun_device)?;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundMsg>(256);
    let mut dispatch = AsyncDispatch::new(outbound_tx);
    for port in &args.port {
        dispatch.listen(*port);
    }

    #[cfg(target_os = "linux")]
    let pcap_linktype = pcap::LINKTYPE_ETHERNET;
    #[cfg(target_os = "macos")]
    let pcap_linktype = pcap::LINKTYPE_IPV4;

    let mut pcap_writer = pcap::create_file_writer("capture.pcap", pcap_linktype)
        .map_err(|e| warn!("pcap disabled: {e}"))
        .ok();

    let mut chaos = (args.chaos > 0.0 || args.chaos_reorder > 0.0 || args.chaos_jitter_ms > 0)
        .then(|| {
            info!(
                drop_rate = args.chaos,
                reorder = args.chaos_reorder,
                jitter_ms = args.chaos_jitter_ms,
                "chaos middleware active"
            );
            ChaosMiddleware::new(ChaosConfig {
                drop_rate: args.chaos,
                reorder_rate: args.chaos_reorder,
                max_jitter_ms: args.chaos_jitter_ms,
            })
        });

    let mut buf = [0u8; STAGING_BUF];

    loop {
        tokio::select! {
            guard_result = async_tun.readable() => {
                let mut guard = guard_result?;
                match guard.try_io(|inner| inner.get_ref().try_recv_nb(&mut buf)) {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => {
                        if let Some(ref mut pw) = pcap_writer {
                            let _ = pw.write_packet(&buf[..n]);
                        }
                        let arp_reply = inbound_dispatch(&buf[..n], &mut dispatch, our_ip, our_mac);
                        if let Some(reply_frame) = arp_reply {
                            if let Err(e) = async_tun.get_ref().write_frame_nb(&reply_frame) {
                                warn!("ARP reply write error: {}", e);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                    Err(_would_block) => {}
                }
            }

            Some(msg) = outbound_rx.recv() => {
                let framed = frame_outbound(&msg);
                if let Some(ref mut pw) = pcap_writer {
                    let _ = pw.write_packet(&framed);
                }
                let packets = match chaos {
                    Some(ref mut c) => c.intercept(framed, Instant::now()),
                    None => vec![framed],
                };
                for pkt in packets {
                    if let Err(e) = async_tun.get_ref().write_frame_nb(&pkt) {
                        warn!("TUN write error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn inbound_dispatch(
    raw: &[u8],
    dispatch: &mut tcp::AsyncDispatch,
    our_ip: [u8; 4],
    our_mac: [u8; 6],
) -> Option<Vec<u8>> {
    use crate::arp;
    use crate::error::MagnumError;
    use crate::ethernet::EthernetFrame;
    use crate::ipv4::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, format_ip};
    use crate::tcp::header::TcpSegment;
    use tracing::{info, warn};

    let frame = match EthernetFrame::parse(raw) {
        Ok(f) => f,
        Err(MagnumError::NonIpv4EtherType(0x0806)) => {
            if let Some(req) = arp::parse_arp_request(raw) {
                if req.target_ip == our_ip {
                    let reply =
                        arp::build_arp_reply_frame(our_mac, our_ip, req.sender_mac, req.sender_ip);
                    return Some(reply);
                }
            }
            return None;
        }
        Err(MagnumError::NonIpv4EtherType(et)) => {
            warn!(
                ethertype = format!("0x{:04X}", et),
                "dropped non-IPv4 frame"
            );
            return None;
        }
        Err(e) => {
            warn!(error = %e, "malformed ethernet frame");
            return None;
        }
    };

    let packet = match Ipv4Packet::parse(frame.payload) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "malformed IPv4 packet");
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
        }
        PROTO_TCP => {
            let seg = match TcpSegment::parse(packet.payload, packet.header.src, packet.header.dst)
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "malformed TCP segment");
                    return None;
                }
            };

            info!(
                src = format!("{}:{}", format_ip(&packet.header.src), seg.header.src_port),
                dst = format!("{}:{}", format_ip(&packet.header.dst), seg.header.dst_port),
                flags = format!("{:08b}", seg.header.flags.to_byte()),
                seq = seg.header.seq,
                "TCP"
            );

            if let Some(handle) = dispatch.dispatch(
                packet.header.src,
                packet.header.dst,
                frame.dst_mac,
                frame.src_mac,
                &seg,
            ) {
                tokio::spawn(handle_connection(handle));
            }
        }
        proto => {
            warn!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                protocol = proto,
                "unknown protocol dropped"
            );
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn inbound_dispatch(
    raw: &[u8],
    dispatch: &mut tcp::AsyncDispatch,
    _our_ip: [u8; 4],
    _our_mac: [u8; 6],
) -> Option<Vec<u8>> {
    use crate::ipv4::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, format_ip};
    use crate::tcp::header::TcpSegment;
    use tracing::{info, warn};

    let packet = match Ipv4Packet::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "malformed IPv4 packet");
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
        }
        PROTO_TCP => {
            let seg = match TcpSegment::parse(packet.payload, packet.header.src, packet.header.dst)
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "malformed TCP segment");
                    return None;
                }
            };

            info!(
                src = format!("{}:{}", format_ip(&packet.header.src), seg.header.src_port),
                dst = format!("{}:{}", format_ip(&packet.header.dst), seg.header.dst_port),
                flags = format!("{:08b}", seg.header.flags.to_byte()),
                seq = seg.header.seq,
                "TCP"
            );

            if let Some(handle) = dispatch.dispatch(
                packet.header.src,
                packet.header.dst,
                [0u8; 6],
                [0u8; 6],
                &seg,
            ) {
                tokio::spawn(handle_connection(handle));
            }
        }
        proto => {
            warn!(
                src = format_ip(&packet.header.src),
                dst = format_ip(&packet.header.dst),
                protocol = proto,
                "unknown protocol dropped"
            );
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn frame_outbound(msg: &tcp::task::OutboundMsg) -> Vec<u8> {
    use crate::ethernet::EthernetFrame;
    use crate::ipv4::{PROTO_TCP, build_packet};
    let ip = build_packet(msg.src_ip, msg.dst_ip, PROTO_TCP, &msg.tcp_bytes);
    EthernetFrame::build(msg.ether_dst, msg.ether_src, &ip)
}

#[cfg(target_os = "macos")]
fn frame_outbound(msg: &tcp::task::OutboundMsg) -> Vec<u8> {
    use crate::ipv4::{PROTO_TCP, build_packet};
    build_packet(msg.src_ip, msg.dst_ip, PROTO_TCP, &msg.tcp_bytes)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_connection(mut handle: tcp::NewConnectionHandle) {
    use tracing::info;

    let mut request_buf: Vec<u8> = Vec::new();
    let mut responded = false;

    while let Some(chunk) = handle.data_rx.recv().await {
        request_buf.extend_from_slice(&chunk);

        if responded {
            continue;
        }

        let is_http = request_buf.starts_with(b"GET ")
            || request_buf.starts_with(b"POST ")
            || request_buf.starts_with(b"HEAD ")
            || request_buf.starts_with(b"PUT ")
            || request_buf.starts_with(b"DELETE ");

        let headers_complete = request_buf.windows(4).any(|w| w == b"\r\n\r\n");

        if is_http && headers_complete {
            let body = b"Hello from Magnum-TCP!\r\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut resp_bytes = response.into_bytes();
            resp_bytes.extend_from_slice(body);
            info!(key = ?handle.key, "HTTP response sent");
            let _ = handle.send_tx.send(resp_bytes).await;
            responded = true;
        } else if !is_http && request_buf.len() > 0 {
            let echo = request_buf.clone();
            info!(key = ?handle.key, bytes = echo.len(), "echo response sent");
            let _ = handle.send_tx.send(echo).await;
            responded = true;
        }
    }

    let _ = handle.close_tx.send(()).await;
}
