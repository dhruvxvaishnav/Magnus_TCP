#![allow(dead_code)]

use std::time::Instant;

use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::warn;

use crate::tcp::connection::Connection;
use crate::tcp::header::TcpSegmentOwned;
use crate::tcp::tcb::TcbState;

const RETRANSMIT_INTERVAL_MS: u64 = 100;
const ZWP_INTERVAL_SECS: u64 = 1;

pub struct InboundMsg {
    pub seg: TcpSegmentOwned,
}

pub struct OutboundMsg {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub tcp_bytes: Vec<u8>,
    pub ether_src: [u8; 6],
    pub ether_dst: [u8; 6],
}

pub async fn run_connection_task(
    mut conn: Connection,
    mut inbound_rx: mpsc::Receiver<InboundMsg>,
    outbound_tx: mpsc::Sender<OutboundMsg>,
    ether_src: [u8; 6],
    ether_dst: [u8; 6],
) {
    let mut retransmit_tick = interval(Duration::from_millis(RETRANSMIT_INTERVAL_MS));
    retransmit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut zwp_tick = interval(Duration::from_secs(ZWP_INTERVAL_SECS));
    zwp_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            maybe_msg = inbound_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                let seg = msg.seg.as_seg();
                match conn.process_segment(&seg) {
                    Ok(Some(tcp_bytes)) => {
                        let _ = outbound_tx.send(OutboundMsg {
                            src_ip: conn.tcb.local_ip,
                            dst_ip: conn.tcb.remote_ip,
                            tcp_bytes,
                            ether_src,
                            ether_dst,
                        }).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "segment processing error");
                    }
                }
            }

            _ = retransmit_tick.tick() => {
                for tcp_bytes in conn.take_retransmits() {
                    let _ = outbound_tx.send(OutboundMsg {
                        src_ip: conn.tcb.local_ip,
                        dst_ip: conn.tcb.remote_ip,
                        tcp_bytes,
                        ether_src,
                        ether_dst,
                    }).await;
                }
            }

            _ = zwp_tick.tick() => {
                if let Some(tcp_bytes) = conn.zero_window_probe() {
                    let _ = outbound_tx.send(OutboundMsg {
                        src_ip: conn.tcb.local_ip,
                        dst_ip: conn.tcb.remote_ip,
                        tcp_bytes,
                        ether_src,
                        ether_dst,
                    }).await;
                }
            }
        }

        if conn.tick_time_wait(Instant::now()) {
            break;
        }

        if conn.tcb.state == TcbState::Closed {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::connection::Connection;
    use crate::tcp::header::{SegmentBuilder, TcpFlags, TcpSegment};
    use crate::tcp::tcb::Tcb;

    const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
    const SERVER_IP: [u8; 4] = [192, 168, 100, 2];
    const CLIENT_PORT: u16 = 12345;
    const SERVER_PORT: u16 = 80;
    const ZERO_MAC: [u8; 6] = [0u8; 6];

    fn make_syn_owned() -> TcpSegmentOwned {
        let raw = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(1000)
            .flags(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            })
            .build();
        let seg = TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP).unwrap();
        TcpSegmentOwned::from(&seg)
    }

    #[tokio::test]
    async fn task_sends_syn_ack_on_syn() {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        let conn = Connection::new(tcb);

        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);

        tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
        ));

        inbound_tx
            .send(InboundMsg {
                seg: make_syn_owned(),
            })
            .await
            .unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
            .await
            .expect("timed out waiting for SYN-ACK")
            .expect("outbound channel closed");

        assert_eq!(resp.src_ip, SERVER_IP);
        assert_eq!(resp.dst_ip, CLIENT_IP);

        let parsed = TcpSegment::parse(&resp.tcp_bytes, resp.src_ip, resp.dst_ip).unwrap();
        assert!(parsed.header.flags.syn);
        assert!(parsed.header.flags.ack);
    }

    #[tokio::test]
    async fn task_exits_when_inbound_channel_closed() {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        let conn = Connection::new(tcb);

        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (outbound_tx, _outbound_rx) = mpsc::channel(16);

        let handle = tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
        ));

        drop(inbound_tx);

        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("task did not exit within 500ms")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn retransmit_and_zwp_timers_run_without_panic() {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        let conn = Connection::new(tcb);

        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);

        let handle = tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
        ));

        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.abort();
    }
}
