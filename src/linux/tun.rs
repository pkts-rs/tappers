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

/// A TUN interface that includes Linux-specific functionality.
pub struct Tun {
    fd: RawFd,
}

impl Tun {
    /// Creates a new, unique persistent TUN device, returning its interface name.
    /// 
    /// The created TUN device may subsequently be opened using [`Tun::open`]. To atomically create
    /// and open a TUN device in one operation, the `Tun::new()` function may be used, though it is
    /// only supported on certain platforms.
    #[inline]
    pub fn create() -> io::Result<Interface> {
        let flags = libc::IFF_TUN_EXCL | libc::IFF_TUN | libc::IFF_NO_PI;

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
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        let tun = Self { fd };
        tun.set_persistent()?;
        drop(tun);

        Ok(Interface::from_raw(req.ifr_name))
    }

    /// Creates a new persistent TUN device of the given name.
    /// 
    /// The created TUN device may subsequently be opened using [`open()`](Tun::open). To atomically
    /// create and open a named TUN device in one operation, the [`new_named()`](Self::new_named)
    /// function may be used, though it is only supported on certain platforms.
    #[inline]
    pub fn create_named(if_name: Interface) -> io::Result<()> {
        let tun = Self::new_named(if_name)?;
        tun.set_persistent()?;
        Ok(())
    }

    /// Creates a new persistent TUN device of the given device number, erroring if the device
    /// already exists.
    /// 
    /// A handle to the created TUN device may subsequently be opened using [`Tun::new_named`] (or
    /// [`Tun::open`] if the `portable-racy` feature is enabled). The created TUN device is
    /// persistent until OS reboot unless it is explicitly destroyed.
    #[cfg(not(target_os = "macos"))]
    #[inline]
    pub fn create_numbered(device_num: u32) -> io::Result<Self> {
        Ok(Self {
            inner: TunImpl::create_numbered(device_num)?,
        })
    }

    /// Opens an existing TUN device of the given name.
    #[cfg(feature = "portable-racy")]
    #[inline]
    pub fn open(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TUN | libc::IFF_NO_PI;

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

        // TUNSETIFF will always create a new device if one doesn't already exist. This is contrary
        // to the intended behavior of `open()`. We check for interface existence here before
        // opening the TUN device. There remains a TOCTOU weakness here, but it's about as close as
        // we can get to conforming behavior.
        if if_name.index().is_err() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "TUN device does not exist"));
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Creates a new, unique TUN device and returns a handle to it.
    ///
    /// The interface name associated with this TUN device is chosen by the system, and can be
    /// retrieved via the [`name()`](Self::name) method. The returned TUN device is not persistent;
    /// it will be destroyed when the returned `Tun` object goes out of scope unless its persistence
    /// is changed via a call to [`Tun::set_persistent`].
    pub fn new() -> io::Result<Self> {
        let flags = libc::IFF_TUN | libc::IFF_NO_PI;

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
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Opens or creates a TUN device of the given name, returning an open handle to it.
    /// 
    /// if `exclusive` is set to `true`, this function will fail if a TUN device matching `if_name`
    /// already exists. A TUN device created (and not opened) via this method is not persistent; it
    /// will be destroyed when the returned `Tun` object goes out of scope unless its persistence is
    /// changed via a call to [`Tun::set_persistent`].
    #[inline]
    pub fn new_named(if_name: Interface, exclusive: bool) -> io::Result<Self> {
        let flags = if exclusive {
            libc::IFF_TUN_EXCL | libc::IFF_TUN | libc::IFF_NO_PI
        } else {
            libc::IFF_TUN | libc::IFF_NO_PI
        };

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
            Self::close_fd(fd);
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Opens or creates a TUN device of the given device number, returning an open handle to it.
    /// 
    /// If `exclusive` is set to `true`, this function will fail if a TUN device matching `if_name`
    /// already exists. A TUN device created (and not opened) via this method is not persistent; it
    /// will be destroyed when the returned `Tun` object goes out of scope unless its persistence is
    /// changed via a call to [`Tun::set_persistent`].
    #[inline]
    pub fn new_numbered(device_num: u32, exclusive: bool) -> io::Result<Self> {
        let label = format!("tun{}\0", n).into_bytes();
        let if_name = Interface::from_raw(array::from_fn(|i| label.get(i).unwrap_or(0x00)));
        Self::new_named(if_name, exclusive)
    }

    /// Sets the persistence of the TUN interface.
    ///
    /// If set to `false`, the TUN device will be destroyed once all file descriptor handles to it
    /// have been closed. If set to `true`, the TUN device will persist until it is explicitly
    /// closed or the system reboots. By default, persistence is set to `false`.
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

    /// Returns the persistence state of the TUN interface.
    /// 
    /// If `false`, the TUN device will be removed automatically on drop or on application exit.
    /// If `true`, the TUN device will persist between applications opening it unles explicitly
    /// destroyed.
    #[inline]
    pub fn is_persistent(&self) -> io::Result<bool> {
        const IFF_PERSIST: u16 = 0x800;

        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            match libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) {
                0.. => Ok(req.ifr_ifru.ifru_flags & IFF_PERSIST > 0),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the interface name associated with the TUN device.
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

    /// Changes the interface name associated with the TUN device to `if_name`.
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
            0.. => Ok(()),
            _ => Err(err),
        }
    }

    /// Retrieves the current state of the TUN device (i.e. "up" or "down").
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

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
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

    #[inline]
    pub fn state(&self, state: DeviceState) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & (libc::IFF_UP as i16) > 0 } {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
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
            0 => Ok(unsafe { req.ifr_ifru.ifru_mtu as usize }),
            _ => Err(err),
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the TUN device.
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

    /// Receives a packet over the TUN device.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sends a packet out over the TUN device.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TUN device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
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

    /// Sets the Ethernet link type for the TUN device (see libc ARPHRD_* constants).
    ///
    /// The device must be down (see [`set_state`](Self::set_state)) for this method to succeed.
    /// TUN devices have a default Ethernet link type of `ARPHRD_ETHER`.
    pub fn set_linktype(&self, linktype: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETLINK, linktype) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets debug mode for the TUN device.
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

    /// Assigns the TUN device to the given user ID, thereby enabling the user to perform operations
    /// on the device.
    pub fn set_owner(&self, owner_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETOWNER, owner_id) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TUN device to the given group ID, thereby enabling users in that group to
    /// perform operations on the device.
    pub fn set_group(&self, group_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETGROUP, group_id) {
                0.. => Ok(()),
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
impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd {
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        Self::close_fd(self.fd);
    }
}
