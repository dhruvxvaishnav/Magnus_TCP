#![allow(dead_code)]

use std::time::Instant;

use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::warn;

use crate::tcp::connection::Connection;
use crate::tcp::header::TcpSegmentOwned;
use crate::tcp::retransmit::MSS;
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

#[allow(clippy::too_many_arguments)]
pub async fn run_connection_task(
    mut conn: Connection,
    mut inbound_rx: mpsc::Receiver<InboundMsg>,
    outbound_tx: mpsc::Sender<OutboundMsg>,
    ether_src: [u8; 6],
    ether_dst: [u8; 6],
    app_data_tx: mpsc::Sender<Vec<u8>>,
    mut app_send_rx: mpsc::Receiver<Vec<u8>>,
    mut close_rx: mpsc::Receiver<()>,
) {
    let mut retransmit_tick = interval(Duration::from_millis(RETRANSMIT_INTERVAL_MS));
    retransmit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut zwp_tick = interval(Duration::from_secs(ZWP_INTERVAL_SECS));
    zwp_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut close_initiated = false;

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
                forward_received_data(&mut conn, &app_data_tx).await;
                flush_send_buf(&mut conn, &outbound_tx, ether_src, ether_dst).await;
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

            Some(data) = app_send_rx.recv() => {
                conn.write_data(&data);
                flush_send_buf(&mut conn, &outbound_tx, ether_src, ether_dst).await;
            }

            _ = close_rx.recv(), if !close_initiated => {
                close_initiated = true;
                if let Some(fin) = conn.initiate_close() {
                    let _ = outbound_tx.send(OutboundMsg {
                        src_ip: conn.tcb.local_ip,
                        dst_ip: conn.tcb.remote_ip,
                        tcp_bytes: fin,
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

async fn flush_send_buf(
    conn: &mut Connection,
    outbound_tx: &mpsc::Sender<OutboundMsg>,
    ether_src: [u8; 6],
    ether_dst: [u8; 6],
) {
    while let Some(tcp_bytes) = conn.next_segment_to_send(MSS as usize) {
        let _ = outbound_tx
            .send(OutboundMsg {
                src_ip: conn.tcb.local_ip,
                dst_ip: conn.tcb.remote_ip,
                tcp_bytes,
                ether_src,
                ether_dst,
            })
            .await;
    }
}

async fn forward_received_data(conn: &mut Connection, app_data_tx: &mpsc::Sender<Vec<u8>>) {
    let available = conn.received_available();
    if available > 0 {
        let mut buf = vec![0u8; available];
        let n = conn.read_received(&mut buf);
        if n > 0 {
            buf.truncate(n);
            let _ = app_data_tx.send(buf).await;
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

    fn dummy_app_channels() -> (
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<()>,
        mpsc::Receiver<()>,
    ) {
        let (app_data_tx, _app_data_rx) = mpsc::channel(16);
        let (_app_send_tx, app_send_rx) = mpsc::channel(16);
        let (close_tx, close_rx) = mpsc::channel(1);
        (app_data_tx, app_send_rx, close_tx, close_rx)
    }

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

    fn make_ack_owned(seq: u32, ack: u32) -> TcpSegmentOwned {
        let raw = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(seq)
            .ack(ack)
            .flags(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            })
            .build();
        let seg = TcpSegment::parse(&raw, CLIENT_IP, SERVER_IP).unwrap();
        TcpSegmentOwned::from(&seg)
    }

    fn make_data_owned(seq: u32, ack: u32, data: &[u8]) -> TcpSegmentOwned {
        let raw = SegmentBuilder::new(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
            .seq(seq)
            .ack(ack)
            .flags(TcpFlags {
                ack: true,
                psh: true,
                ..TcpFlags::default()
            })
            .payload(data)
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
        let (app_data_tx, _app_data_rx) = mpsc::channel(16);
        let (_app_send_tx, app_send_rx) = mpsc::channel(16);
        let (_close_tx, close_rx) = mpsc::channel(1);

        tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
            app_data_tx,
            app_send_rx,
            close_rx,
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
        let (app_data_tx, _app_data_rx) = mpsc::channel(16);
        let (_app_send_tx, app_send_rx) = mpsc::channel(16);
        let (_close_tx, close_rx) = mpsc::channel(1);

        let handle = tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
            app_data_tx,
            app_send_rx,
            close_rx,
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
        let (app_data_tx, _app_data_rx) = mpsc::channel(1);
        let (_app_send_tx, app_send_rx) = mpsc::channel(1);
        let (_close_tx, close_rx) = mpsc::channel(1);

        let handle = tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
            app_data_tx,
            app_send_rx,
            close_rx,
        ));

        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn app_data_forwarded_on_data_segment() {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        let conn = Connection::new(tcb);

        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
        let (app_data_tx, mut app_data_rx) = mpsc::channel(16);
        let (_app_send_tx, app_send_rx) = mpsc::channel(16);
        let (_close_tx, close_rx) = mpsc::channel(1);

        tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
            app_data_tx,
            app_send_rx,
            close_rx,
        ));

        // 3-way handshake: SYN
        inbound_tx
            .send(InboundMsg {
                seg: make_syn_owned(),
            })
            .await
            .unwrap();
        let syn_ack = tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack_parsed = TcpSegment::parse(&syn_ack.tcp_bytes, SERVER_IP, CLIENT_IP).unwrap();

        // ACK the SYN-ACK (seq=ISN+1, ack=server_ISS+1)
        inbound_tx
            .send(InboundMsg {
                seg: make_ack_owned(1001, syn_ack_parsed.header.seq + 1),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send data segment
        let payload = b"hello";
        inbound_tx
            .send(InboundMsg {
                seg: make_data_owned(1001, syn_ack_parsed.header.seq + 1, payload),
            })
            .await
            .unwrap();

        // Expect ACK on outbound and data on app_data_rx
        let _ack = tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
            .await
            .expect("timed out waiting for ACK")
            .expect("channel closed");

        let received = tokio::time::timeout(Duration::from_millis(200), app_data_rx.recv())
            .await
            .expect("timed out waiting for app data")
            .expect("app channel closed");

        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn app_send_triggers_data_segment() {
        let tcb = Tcb::new_for_listen(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT);
        let conn = Connection::new(tcb);

        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
        let (app_data_tx, _app_data_rx) = mpsc::channel(16);
        let (app_send_tx, app_send_rx) = mpsc::channel(16);
        let (_close_tx, close_rx) = mpsc::channel(1);

        tokio::spawn(run_connection_task(
            conn,
            inbound_rx,
            outbound_tx,
            ZERO_MAC,
            ZERO_MAC,
            app_data_tx,
            app_send_rx,
            close_rx,
        ));

        // 3-way handshake
        inbound_tx
            .send(InboundMsg {
                seg: make_syn_owned(),
            })
            .await
            .unwrap();
        let syn_ack = tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack_parsed = TcpSegment::parse(&syn_ack.tcp_bytes, SERVER_IP, CLIENT_IP).unwrap();
        inbound_tx
            .send(InboundMsg {
                seg: make_ack_owned(1001, syn_ack_parsed.header.seq + 1),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Application pushes data to send
        app_send_tx.send(b"world".to_vec()).await.unwrap();

        let data_seg = tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
            .await
            .expect("timed out waiting for data segment")
            .expect("channel closed");

        let parsed = TcpSegment::parse(&data_seg.tcp_bytes, SERVER_IP, CLIENT_IP).unwrap();
        assert_eq!(parsed.payload, b"world");
    }
}
