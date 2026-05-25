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
    }
}

#[cfg(target_os = "linux")]
pub use linux::Tun;

#[cfg(not(target_os = "linux"))]
pub struct Tun;

#[cfg(not(target_os = "linux"))]
impl Tun {
    pub fn open(_name: &str) -> Result<Self> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux",
        )))
    }

    pub fn name(&self) -> &str {
        ""
    }

    pub fn recv(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux",
        )))
    }

    pub fn send(&mut self, _buf: &[u8]) -> Result<usize> {
        Err(MagnumError::Tun(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is only supported on Linux",
        )))
    }
}
