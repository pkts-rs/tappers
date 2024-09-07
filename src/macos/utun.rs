use core::str;
use std::os::fd::{AsRawFd, RawFd};
use std::{array, io, mem, ptr};

use crate::{DeviceState, Interface};

const UTUN_PREFIX: &[u8] = b"utun";
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

const SIOCGIFDEVMTU: libc::c_ulong = 0xc0206944;
const SIOCIFDESTROY: libc::c_ulong = 0x80206979;

// We use a custom `iovec` struct here because we don't want to do a *const to *mut conversion
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct iovec_send {
    pub iov_base: *const ::c_void,
    pub iov_len: ::size_t,
}

pub struct Utun {
    fd: RawFd,
}

impl Utun {
    /// Creates a new TUN device.
    ///
    /// The interface name associated with this TUN device is chosen by the system, and can be
    /// retrieved via the [`name()`](Self::name) method.
    pub fn new() -> io::Result<Self> {
        Self::new_internal(0)
    }

    /// Opens a TUN device with the given interface name `if_name`.
    ///
    /// If no TUN device exists for the given interface name, this method will create a new one.
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let len = if_name.name.iter().position(|b| *b == 0).unwrap_or(0);

        if len < 5 || &if_name.name[..4] != UTUN_PREFIX {
            return Err(io::ErrorKind::InvalidInput.into());
        }

        // The numeral following must be composed of ascii 0-9, so this should pass
        let Ok(s) = str::from_utf8(&if_name.name[4..len]) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };

        let n: u32 = s
            .parse()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Self::new_numbered(n)
    }

    /// Opens a TUN device with the given tun number `utun_number`.
    ///
    /// If no TUN device exists for the given interface name, this method will create a new one.
    pub fn new_numbered(utun_number: u32) -> io::Result<Self> {
        Self::new_internal(utun_number.checked_add(1).ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "utun_number out of range",
        ))?)
    }

    fn new_internal(sc_unit: u32) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut utun_ctrl_iter = UTUN_CONTROL_NAME.iter();
        let mut info = libc::ctl_info {
            ctl_id: 0u32,
            ctl_name: array::from_fn(|_| utun_ctrl_iter.next().cloned().unwrap_or(0)),
        };

        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &info) } != 0 {
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        let addrlen = mem::size_of::<libc::sockaddr_ctl>();
        let mut addr = libc::sockaddr_ctl {
            sc_len: addrlen as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit,
            sc_reserved: [0u32; 5],
        };

        if unsafe {
            libc::connect(
                fd,
                ptr::addr_of!(addr) as *const libc::sockaddr,
                addrlen as u32,
            )
        } != 0
        {
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    pub fn name(&self) -> io::Result<Interface> {
        let mut name_buf = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
        let name_ptr = ptr::addr_of_mut!(name_buf) as *mut libc::c_void;
        let mut name_len = Interface::MAX_INTERFACE_NAME_LEN + 1;

        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name_ptr,
                name_len,
            )
        } {
            0 => Ok(Interface {
                name: name_buf,
                is_catchall: false,
            }),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn mtu(&self) -> io::Result<usize> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        unsafe {
            match libc::ioctl(self.fd, SIOCGIFDEVMTU, ptr::addr_of_mut!(req)) {
                0 => Ok(unsafe { req.ifr_ifru.ifru_devmtu.ifdm_current as usize }),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the current state of the TAP device (i.e. "up" or "down").
    pub fn state(&self) -> io::Result<DeviceState> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, libc::SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_UP as i16 > 0 } {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Sets the state of the TAP device (i.e. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, libc::SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
            }
        }

        if unsafe { libc::ioctl(self.fd, libc::SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet must not be empty"))
        }

        let family_prefix = match buf[0] & 0x0f {
            0x04 => [0u8, 0, 0, 2],
            0x06 => [0u8, 0, 0, 10],
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "only IPv4 and IPv6 packets are supported over utun")),
        };

        let iov = [
            iovec_const {
                iov_base: family_prefix.as_ptr() as *const libc::c_void,
                iov_len: family_prefix.len(),
            },
            iovec_const {
                iov_base: buf.as_ptr() as *const libc::c_void,
                iov_len: buf.len(),
            },
        ];

        unsafe {
            match libc::writev(self.fd, iov.as_ptr() as *const libc::iovec, iov.len()) {
                r @ 0.. => Ok((r as usize).saturating_sub(family_prefix.len())),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut family_prefix = [0u8; 4];
        let mut iov = [
            libc::iovec {
                iov_base: family_prefix.as_mut_ptr() as *mut libc::c_void,
                iov_len: family_previx.len(),
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];

        unsafe {
            match libc::readv(self.fd, iov.as_mut_ptr(), iov.len()) {
                r @ 4.. => Ok((r - 4) as usize),
                0..4 => Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient bytes received from utun to form packet")),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the UTUN device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the UTUN device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = match nonblocking {
            true => flags | libc::O_NONBLOCK,
            false => flags & !libc::O_NONBLOCK,
        };

        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        } else {
            Ok(())
        }
    }

    pub fn destroy(self) -> io::Result<()> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let res = match unsafe { libc::ioctl(self.fd, SIOCIFDESTROY, ptr::addr_of_mut!(req)) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error())
        };

        Self::close_fd(self.fd);

        res
    }

    fn destroy_iface(sockfd: RawFd, if_name: Interface) {
        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            debug_assert_eq!(
                libc::ioctl(sockfd, SIOCIFDESTROY, ptr::addr_of_mut!(req)),
                0
            );
        }
    }

    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        if let Ok(if_name) = self.name() {
            Self::destroy_iface(self.fd, if_name);
        }
        Self::close_fd(self.fd);
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl io::Read for Utun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        unsafe {
            match libc::readv(self.fd, bufs.as_mut_ptr().cast(), bufs.len() as i32) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
}

impl io::Write for Utun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, buf.as_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        unsafe {
            match libc::writev(self.fd, bufs.as_ptr().cast(), bufs.len() as i32) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
}
