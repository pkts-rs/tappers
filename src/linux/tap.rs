// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::CStr;
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::{io, ptr};

use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface};

use super::DEV_NET_TUN;

// Need to add to libc

#[cfg(not(doc))]
const TUNGETIFF: libc::Ioctl = 0x800454D2;
#[cfg(not(doc))]
const TUNSETDEBUG: libc::Ioctl = 0x400454C9;
#[cfg(not(doc))]
const TUNSETGROUP: libc::Ioctl = 0x400454CE;
#[cfg(not(doc))]
const TUNSETLINK: libc::Ioctl = 0x400454CD;
#[cfg(not(doc))]
const TUNSETIFF: libc::Ioctl = 0x400454CA;
#[cfg(not(doc))]
const TUNSETOWNER: libc::Ioctl = 0x400454CC;
#[cfg(not(doc))]
const TUNSETPERSIST: libc::Ioctl = 0x400454CB;

/// A TAP interface that includes Linux-specific functionality.
pub struct Tap {
    fd: RawFd,
}

impl Tap {
    /// Creates a new, unique TAP device.
    ///
    /// The interface name associated with this TAP device is chosen by the system, and can be
    /// retrieved via the [`name()`](Self::name) method.
    pub fn new() -> io::Result<Self> {
        let flags = libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL;

        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        Ok(Self { fd })
    }

    /// Opens or creates a TTAP device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        Ok(Self { fd })
    }

    /// Creates a new TTAP device, failing if a device of the given name already exists.
    pub fn create_named(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        Ok(Self { fd })
    }

    /// Sets the persistence of the TAP interface.
    ///
    /// If set to `false`, the TAP device will be destroyed once all file descriptor handles to it
    /// have been closed (e.g. on `Drop`). If set to `true`, the TAP device will persist until it
    /// is explicitly closed or the system reboots. By default, persistence is set to `false`.
    pub fn set_persistent(&self, persistent: bool) -> io::Result<()> {
        let persist = match persistent {
            true => 1,
            false => 0,
        };

        unsafe {
            match libc::ioctl(self.fd, TUNSETPERSIST, persist) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the interface name associated with the TAP device.
    pub fn name(&self) -> io::Result<Interface> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            match libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) {
                0.. => Interface::from_cstr(CStr::from_ptr(req.ifr_name.as_ptr())),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Changes the interface name associated with the TAP device to `if_name`.
    pub fn set_name(&self, if_name: Interface) -> io::Result<()> {
        let old_if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: old_if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_newname: if_name.name_raw_char(),
            },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { libc::ioctl(ctrl_fd, libc::SIOCSIFNAME, ptr::addr_of_mut!(req)) };
        let err = io::Error::last_os_error();
        Self::close_fd(ctrl_fd);
        match res {
            0 => Ok(()),
            _ => Err(err),
        }
    }

    /// Retrieves the current state of the TAP device (i.e. "up" or "down").
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            match libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) {
                0.. => {
                    if (req.ifr_ifru.ifru_flags & libc::IFF_UP as i16) == 0 {
                        Ok(DeviceState::Down)
                    } else {
                        Ok(DeviceState::Up)
                    }
                }
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets the adapter state of the TAP device (e.g. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
            }
        }

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { libc::ioctl(ctrl_fd, libc::SIOCSIFFLAGS, ptr::addr_of_mut!(req)) };
        let err = io::Error::last_os_error();
        Self::close_fd(ctrl_fd);
        match res {
            0 => Ok(()),
            _ => Err(err),
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn mtu(&self) -> io::Result<usize> {
        let ifr_name = self.name()?.name_raw_char();

        let mut req = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { libc::ioctl(ctrl_fd, libc::SIOCGIFMTU, ptr::addr_of_mut!(req)) };
        let err = io::Error::last_os_error();
        Self::close_fd(ctrl_fd);
        match res {
            0 => {
                if unsafe { req.ifr_ifru.ifru_mtu < 0 } {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected negative MTU",
                    ));
                }

                Ok(unsafe { req.ifr_ifru.ifru_mtu as usize })
            }
            _ => Err(err),
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        if mtu > i32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU too large"));
        }

        let ifr_name = self.name()?.name_raw_char();

        let mut req = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_mtu: mtu as i32,
            },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { libc::ioctl(ctrl_fd, libc::SIOCSIFMTU, ptr::addr_of_mut!(req)) };
        let err = io::Error::last_os_error();
        Self::close_fd(ctrl_fd);
        match res {
            0 => Ok(()),
            _ => Err(err),
        }
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TAP device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TAP device.
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
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Sets the Ethernet link type for the TAP device (see libc ARPHRD_* constants).
    ///
    /// The device must be down (see [`set_state`](Self::set_state)) for this method to succeed.
    /// TAP devices have a default Ethernet link type of `ARPHRD_ETHER`.
    pub fn set_linktype(&self, linktype: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETLINK, linktype) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets debug mode for the TAP device.
    pub fn set_debug(&self, debug: bool) -> io::Result<()> {
        let debug = match debug {
            true => 1,
            false => 0,
        };

        unsafe {
            match libc::ioctl(self.fd, TUNSETDEBUG, debug) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TAP device to the given user ID, thereby enabling the user to perform operations
    /// on the device.
    pub fn set_owner(&self, owner_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETOWNER, owner_id) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TAP device to the given group ID, thereby enabling users in that group to
    /// perform operations on the device.
    pub fn set_group(&self, group_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETGROUP, group_id) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
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

    /// Receives a packet over the TAP device.
    pub fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, data.as_mut_ptr() as *mut libc::c_void, data.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sends a packet out over the TAP device.
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, data.as_ptr() as *const libc::c_void, data.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    #[inline]
    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for Tap {
    fn as_fd(&self) -> BorrowedFd {
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
