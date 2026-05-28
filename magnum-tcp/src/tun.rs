#![allow(dead_code)]

use crate::error::{MagnumError, Result};

#[cfg(target_os = "linux")]
mod linux {
    use crate::error::{MagnumError, Result};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    const TUNSETIFF: libc::c_ulong = 0x400454CA;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    impl Ifreq {
        fn new(name: &str, flags: libc::c_short) -> Self {
            let mut ifr_name = [0u8; 16];
            let bytes = name.as_bytes();
            let len = bytes.len().min(15);
            ifr_name[..len].copy_from_slice(&bytes[..len]);
            Self {
                ifr_name,
                ifr_flags: flags,
                _pad: [0u8; 22],
            }
        }
    }

    pub struct Tun {
        file: File,
        name: String,
    }

    impl Tun {
        pub fn open(name: &str) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?;

            let mut req = Ifreq::new(name, IFF_TAP | IFF_NO_PI);

            let ret = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    TUNSETIFF,
                    &mut req as *mut Ifreq as *mut libc::c_void,
                )
            };

            if ret < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }

            Ok(Self {
                file,
                name: name.to_string(),
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            Ok(self.file.read(buf)?)
        }

        pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(self.file.write(buf)?)
        }

        pub fn set_nonblocking(&self) -> Result<()> {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        pub fn try_recv_nb(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            Ok((&self.file).read(buf)?)
        }

        pub fn write_frame_nb(&self, buf: &[u8]) -> std::io::Result<usize> {
            Ok((&self.file).write(buf)?)
        }
    }

    impl std::os::unix::io::AsRawFd for Tun {
        fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
            use std::os::unix::io::AsRawFd;
            self.file.as_raw_fd()
        }
    }
}

// ── macOS utun ────────────────────────────────────────────────────────────────
// macOS does not have /dev/net/tun or TAP devices in modern kernels.
// Instead we use the kernel utun driver (Layer 3) accessed via a PF_SYSTEM
// control socket.  Each read/write is prefixed with a 4-byte big-endian
// address-family word (0x00000002 for AF_INET).  We strip/prepend that here
// so the caller always sees and provides plain IP packets.
#[cfg(target_os = "macos")]
mod macos {
    use crate::error::{MagnumError, Result};
    use std::fs::File;
    use std::io::{IoSlice, Read, Write};
    use std::os::unix::io::FromRawFd;

    const PF_SYSTEM: libc::c_int = 32;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const AF_SYSTEM: u8 = 32;
    const AF_SYS_CONTROL: u16 = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xC064_4E03;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const IFNAMSIZ: usize = 16;
    const MAX_KCTL_NAME: usize = 96;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; MAX_KCTL_NAME],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    pub struct Tun {
        file: File,
        name: String,
    }

    impl Tun {
        pub fn open(name: &str) -> Result<Self> {
            // "utun0" -> sc_unit=1, "utun1" -> sc_unit=2, etc. (0 = auto-assign)
            let unit: u32 = name
                .strip_prefix("utun")
                .and_then(|n| n.parse::<u32>().ok())
                .map(|n| n + 1)
                .unwrap_or(0);

            let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }

            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0u8; MAX_KCTL_NAME],
            };
            let ctrl = b"com.apple.net.utun_control";
            info.ctl_name[..ctrl.len()].copy_from_slice(ctrl);

            if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _ as *mut libc::c_void) } < 0
            {
                unsafe { libc::close(fd) };
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }

            let addr = SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0u32; 5],
            };

            if unsafe {
                libc::connect(
                    fd,
                    &addr as *const SockaddrCtl as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                )
            } < 0
            {
                unsafe { libc::close(fd) };
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }

            let actual_name = Self::query_ifname(fd).unwrap_or_else(|| name.to_string());
            let file = unsafe { File::from_raw_fd(fd) };
            Ok(Self {
                file,
                name: actual_name,
            })
        }

        fn query_ifname(fd: libc::c_int) -> Option<String> {
            let mut buf = [0u8; IFNAMSIZ];
            let mut len = IFNAMSIZ as libc::socklen_t;
            let ok = unsafe {
                libc::getsockopt(
                    fd,
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    &mut len,
                )
            };
            if ok < 0 {
                return None;
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(len as usize);
            Some(String::from_utf8_lossy(&buf[..end]).into_owned())
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            // Frame layout: [u32 AF_INET big-endian] [IP packet]
            let n = self.file.read(buf)?;
            if n <= 4 {
                return Ok(0);
            }
            buf.copy_within(4..n, 0);
            Ok(n - 4)
        }

        pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
            // AF_INET = 2 in big-endian
            let hdr = [0u8, 0, 0, 2];
            let iov = [IoSlice::new(&hdr), IoSlice::new(buf)];
            self.file.write_vectored(&iov)?;
            Ok(buf.len())
        }

        pub fn set_nonblocking(&self) -> Result<()> {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(MagnumError::Tun(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        pub fn try_recv_nb(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (&self.file).read(buf)?;
            if n <= 4 {
                return Ok(0);
            }
            buf.copy_within(4..n, 0);
            Ok(n - 4)
        }

        pub fn write_frame_nb(&self, buf: &[u8]) -> std::io::Result<usize> {
            let hdr = [0u8, 0, 0, 2];
            let iov = [IoSlice::new(&hdr), IoSlice::new(buf)];
            (&self.file).write_vectored(&iov)?;
            Ok(buf.len())
        }
    }

    impl std::os::unix::io::AsRawFd for Tun {
        fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
            use std::os::unix::io::AsRawFd;
            self.file.as_raw_fd()
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::Tun;

#[cfg(target_os = "macos")]
pub use macos::Tun;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct Tun;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Tun {
    pub fn open(_name: &str) -> Result<Self> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        )))
    }

    pub fn name(&self) -> &str {
        ""
    }

    pub fn recv(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        )))
    }

    pub fn send(&mut self, _buf: &[u8]) -> Result<usize> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        )))
    }

    pub fn set_nonblocking(&self) -> Result<()> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        )))
    }

    pub fn try_recv_nb(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        ))
    }

    pub fn write_frame_nb(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux and macOS",
        ))
    }
}
