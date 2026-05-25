use thiserror::Error;

#[derive(Debug, Error)]
pub enum MagnumError {
    #[error("I/O error on TUN device: {0}")]
    Tun(#[from] std::io::Error),

    #[error("Ethernet frame too short: got {got} bytes, need {need}")]
    EthernetFrameTooShort { got: usize, need: usize },

    #[error("Non-IPv4 EtherType: 0x{0:04X}")]
    NonIpv4EtherType(u16),

    #[error("IPv4 header too short: got {got} bytes, need {need}")]
    Ipv4HeaderTooShort { got: usize, need: usize },

    #[error("IPv4 IHL field too small: {0}")]
    Ipv4IhlTooSmall(u8),

    #[error("IPv4 checksum mismatch: computed 0x{computed:04X}, got 0x{got:04X}")]
    Ipv4ChecksumMismatch { computed: u16, got: u16 },

    #[error("IPv4 total length exceeds buffer: total_len={total_len}, buf_len={buf_len}")]
    Ipv4TruncatedPacket { total_len: usize, buf_len: usize },

    #[error("TCP header too short: got {got} bytes, need {need}")]
    TcpHeaderTooShort { got: usize, need: usize },

    #[error("TCP data offset too small: {0}")]
    TcpDataOffsetTooSmall(u8),

    #[error("TCP checksum mismatch: computed 0x{computed:04X}, got 0x{got:04X}")]
    TcpChecksumMismatch { computed: u16, got: u16 },
}

pub type Result<T> = std::result::Result<T, MagnumError>;
