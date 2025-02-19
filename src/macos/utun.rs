// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::{array, io, mem, ptr, str};

use crate::libc_extra::*;
use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface};

const UTUN_PREFIX: &[u8] = b"utun";
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/*
const SIOCDIFPHYADDR: libc::c_ulong = 0x80206941;
const SIOCGIFDEVMTU: libc::c_ulong = 0xc0206944;
const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;

const SIOCGIFDSTADDR: libc::c_ulong = 0xc0206922;
const SIOCSIFDSTADDR: libc::c_ulong = 0x8020690e;

const SIOCGIFNETMASK: libc::c_ulong = 0xc0206925;
const SIOCSIFNETMASK: libc::c_ulong = 0x80206916;
*/

// We use a custom `iovec` struct here because we don't want to do a *const to *mut conversion
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct iovec_const {
    pub iov_base: *const libc::c_void,
    pub iov_len: libc::size_t,
}

pub struct Utun {
    fd: RawFd,
}

/// A UTUN interface that includes MacOS-specific TUN functionality.
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
            ctl_name: array::from_fn(|_| {
                utun_ctrl_iter
                    .next()
                    .map(|b| *b as libc::c_char)
                    .unwrap_or(0)
            }),
        };

        if unsafe {
            libc::ioctl(
                fd,
                libc::CTLIOCGINFO,
                ptr::addr_of_mut!(info) as *mut libc::c_void,
            )
        } != 0
        {
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        let addrlen = mem::size_of::<libc::sockaddr_ctl>();
        let addr = libc::sockaddr_ctl {
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

    /// Retrieves the network-layer addresses assigned to the interface.
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.name()?.addrs()
    }

    /// Adds the specified network-layer address to the interface.
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.name()?.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.name()?.remove_addr(addr)
    }

    /// Retrieves the name of the interface.
    pub fn name(&self) -> io::Result<Interface> {
        let mut name_buf = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
        let name_ptr = ptr::addr_of_mut!(name_buf) as *mut libc::c_void;
        let mut name_len: u32 = Interface::MAX_INTERFACE_NAME_LEN as u32 + 1;

        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name_ptr,
                ptr::addr_of_mut!(name_len),
            )
        } {
            0 => Ok(Interface {
                name: name_buf,
                is_catchall: false,
            }),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    pub fn mtu(&self) -> io::Result<usize> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
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
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_current as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the current state of the TUN device (i.e. "up" or "down").
    pub fn state(&self) -> io::Result<DeviceState> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_UP as i16 > 0 } {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
            }
        }

        if unsafe { libc::ioctl(self.fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sends a packet out over the TUN device.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet must not be empty",
            ));
        }

        let family_prefix = match buf[0] & 0xf0 {
            0x40 => [0u8, 0, 0, 2],
            0x60 => [0u8, 0, 0, 10],
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only IPv4 and IPv6 packets are supported over utun",
                ))
            }
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
            match libc::writev(self.fd, iov.as_ptr() as *const libc::iovec, 2) {
                r @ 0.. => Ok((r as usize).saturating_sub(family_prefix.len())),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Receives a packet over the TUN device.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut family_prefix = [0u8; 4];
        let mut iov = [
            libc::iovec {
                iov_base: family_prefix.as_mut_ptr() as *mut libc::c_void,
                iov_len: family_prefix.len(),
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];

        unsafe {
            match libc::readv(self.fd, iov.as_mut_ptr(), 2) {
                0..=3 => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "insufficient bytes received from utun to form packet",
                )),
                r @ 4.. => Ok((r - 4) as usize),
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
        self.destroy_impl()
    }

    /*
    fn delete_all_routes(&self) -> io::Result<()> {
        let route_fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
        if route_fd < 0 {
            return Err(io::Error::last_os_error())
        }

        let msg = rtmsg {
            m_rtm: rt_msghdr {
                rtm_msglen: 0,
                rtm_version: libc::RTM_VERSION,
                rtm_type: libc::RTM_DELETE,
                rtm_index: self.name()?.index()? as u16,
                rtm_flags: 0i32, // `RTF_STATIC` | `RTF_UP` | (`RTF_HOST` || `RTF_GATEWAY`??)
                rtm_addrs: 0i32, // `RTA_NETMASK`??
                rtm_pid: 0,
                rtm_seq: 0,
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: 0, // TODO: populate with `RTV_*` flags
                rtm_rmx: libc::rt_metrics {
                    rmx_locks: 0u32,
                    rmx_mtu: 0u32,
                    rmx_hopcount: 0u32,
                    rmx_expire: 0i32,
                    rmx_recvpipe: 0u32,
                    rmx_sendpipe: 0u32,
                    rmx_ssthresh: 0u32,
                    rmx_rtt: 0u32,
                    rmx_rttvar: 0u32,
                    rmx_pksent: 0u32,
                    rmx_filler: [0u32; 4],
                },
            },
            m_space: [0u8; 512],
        };

        // TODO: write() `rtmsg` as an array of bytes, check return less than 0

        // return success!

        // Alternatively: delete addresses using SIOCDIFADDR?
        // Specifically
    }
    */

    #[inline]
    fn destroy_impl(&self) -> io::Result<()> {
        self.set_state(DeviceState::Down)?;
        Self::close_fd(self.fd);

        // NOTE: MacOS has strange behavior for `utun` interfaces.
        //
        // They don't conform to the usual `SIOCIFDESTROY` ioctl used generally to remove
        // interfaces. Instead, a given `utun` interface will only disappear once all routes that
        // make use of it have been deleted. This has caused issues elsewhere:
        //
        // https://forums.developer.apple.com/forums/thread/682767
        // https://serverfault.com/questions/1129536/how-to-delete-utun0-in-my-macos
        //
        // So it seems that manually deleting routes causes a `utun` device to go away. The MacOS
        // implementation of `ifconfig` uses `SIOCDIFPHYADDR`, but that hasn't worked well...
        // If further bugs arise, keep chasing this thread; for now, just doing nothing works for
        // the general case.
        Ok(())
    }

    #[inline]
    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for Utun {
    fn as_fd(&self) -> BorrowedFd {
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        self.destroy_impl().unwrap();
    }
}
