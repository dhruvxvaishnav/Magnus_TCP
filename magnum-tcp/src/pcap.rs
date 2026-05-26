#![allow(dead_code)]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_IPV4: u32 = 228;

const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;

pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W, linktype: u32) -> std::io::Result<Self> {
        writer.write_all(&PCAP_MAGIC_LE.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
        writer.write_all(&linktype.to_le_bytes())?;
        Ok(Self { writer })
    }

    pub fn write_packet(&mut self, data: &[u8]) -> std::io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();
        let len = data.len() as u32;

        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(data)?;
        self.writer.flush()
    }
}

pub fn create_file_writer(
    path: &str,
    linktype: u32,
) -> std::io::Result<PcapWriter<BufWriter<File>>> {
    let file = File::create(path)?;
    PcapWriter::new(BufWriter::new(file), linktype)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_writer(linktype: u32) -> PcapWriter<Vec<u8>> {
        PcapWriter::new(Vec::new(), linktype).unwrap()
    }

    #[test]
    fn global_header_magic_and_version() {
        let pw = make_writer(LINKTYPE_ETHERNET);
        let buf = pw.writer;
        assert_eq!(buf.len(), 24, "global header must be 24 bytes");
        assert_eq!(&buf[0..4], &PCAP_MAGIC_LE.to_le_bytes(), "magic mismatch");
        assert_eq!(&buf[4..6], &2u16.to_le_bytes(), "version_major");
        assert_eq!(&buf[6..8], &4u16.to_le_bytes(), "version_minor");
        assert_eq!(&buf[20..24], &LINKTYPE_ETHERNET.to_le_bytes(), "linktype");
    }

    #[test]
    fn packet_record_length_and_payload() {
        let mut pw = make_writer(LINKTYPE_ETHERNET);
        let data = b"hello pcap";
        pw.write_packet(data).unwrap();

        let buf = pw.writer;
        let record = &buf[24..];
        let incl_len = u32::from_le_bytes(record[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(record[12..16].try_into().unwrap());
        assert_eq!(incl_len, data.len() as u32);
        assert_eq!(orig_len, data.len() as u32);
        assert_eq!(&record[16..], data);
    }

    #[test]
    fn two_packets_appended_sequentially() {
        let mut pw = make_writer(LINKTYPE_IPV4);
        pw.write_packet(b"first").unwrap();
        pw.write_packet(b"second").unwrap();

        let buf = pw.writer;
        let first_start = 24;
        let first_len =
            u32::from_le_bytes(buf[first_start + 8..first_start + 12].try_into().unwrap()) as usize;
        let second_start = first_start + 16 + first_len;
        let second_len =
            u32::from_le_bytes(buf[second_start + 8..second_start + 12].try_into().unwrap())
                as usize;
        assert_eq!(first_len, 5);
        assert_eq!(second_len, 6);
        assert_eq!(
            &buf[first_start + 16..first_start + 16 + first_len],
            b"first"
        );
        assert_eq!(
            &buf[second_start + 16..second_start + 16 + second_len],
            b"second"
        );
    }

    #[test]
    fn linktype_ipv4_in_header() {
        let pw = make_writer(LINKTYPE_IPV4);
        let linktype = u32::from_le_bytes(pw.writer[20..24].try_into().unwrap());
        assert_eq!(linktype, LINKTYPE_IPV4);
    }
}
