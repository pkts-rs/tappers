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
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface};

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
    inner: File,
}

impl Tap {
    /// Creates a new, unique persistent TAP device, returning its interface name.
    ///
    /// The created TAP device may subsequently be opened using [`Tap::open`]. To atomically create
    /// and open a TAP device in one operation, the [`Tap::new()`] function may be used.
    #[inline]
    pub fn create() -> io::Result<Interface> {
        let flags = libc::IFF_TUN_EXCL | libc::IFF_TAP | libc::IFF_NO_PI;

        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let inner = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        if unsafe { libc::ioctl(inner.as_raw_fd(), TUNSETIFF, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let tap = Self { inner };
        tap.set_persistent(true)?;
        drop(tap);

        Ok(unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) })
    }

    /// Creates a new persistent TAP device of the given name.
    ///
    /// The created TAP device may subsequently be opened using [`open()`](Self::open). To atomically
    /// create and open a named TAP device in one operation, the [`new_named()`](Self::new_named)
    /// function may be used, though it is only supported on certain platforms.
    #[inline]
    pub fn create_named(if_name: Interface) -> io::Result<()> {
        let tap = Self::new_named(if_name, true)?;
        tap.set_persistent(true)?;
        Ok(())
    }

    /// Creates a new persistent TAP device of the given device number, erroring if the device
    /// already exists.
    ///
    /// A handle to the created TAP device may subsequently be opened using [`Tap::new_named`] (or
    /// [`Tap::open`] if the `portable-racy` feature is enabled). The created TAP device is
    /// persistent until OS reboot unless it is explicitly destroyed.
    #[cfg(not(target_os = "macos"))]
    #[inline]
    pub fn create_numbered(device_num: u32) -> io::Result<()> {
        Self::create_named(Interface::new(format!("tap{}", device_num)).unwrap())
    }

    pub fn destroy(self) -> io::Result<()> {
        self.set_state(DeviceState::Down)?;
        self.set_persistent(false)?;
        Ok(())
    }

    /// Destroys the TAP device specified by the given interface name.
    #[inline]
    pub fn destroy_named(if_name: Interface) -> io::Result<()> {
        // TODO: switch to RTM_DELLINK in the future
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETPERSIST, 0 as libc::c_int) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Destroys the TAP device specified by the given interface number.
    #[inline]
    pub fn destroy_numbered(device_num: u32) -> io::Result<()> {
        Self::destroy_named(Interface::new(format!("tap{}", device_num)).unwrap())
    }

    #[inline]
    pub fn exists(if_name: Interface) -> io::Result<bool> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCGIFINDEX, &raw mut req) } < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::ENODEV)) {
                Ok(false)
            } else {
                Err(err)
            }
        } else {
            Ok(true)
        }
    }

    #[inline]
    pub fn exists_numbered(device_num: u32) -> io::Result<bool> {
        Self::exists(Interface::new(format!("tap{}", device_num)).unwrap())
    }

    /// Opens an existing TAP device of the given name.
    #[cfg(feature = "portable-racy")]
    #[inline]
    pub fn open_named(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TAP | libc::IFF_NO_PI;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        // TUNSETIFF will always create a new device if one doesn't already exist. This is contrary
        // to the intended behavior of `open()`. We check for interface existence here before
        // opening the TUN device. There remains a TOCTOU weakness here, but it's about as close as
        // we can get to conforming behavior.
        if if_name.index().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TAP device does not exist",
            ));
        }

        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { inner: file })
    }

    /// Opens an existing TAP device of the given name.
    #[cfg(feature = "portable-racy")]
    #[inline]
    pub fn open(device_num: u32) -> io::Result<Self> {
        let if_name = Interface::new(format!("tap{}", device_num)).unwrap();
        Self::open_named(if_name)
    }

    /// Creates a new, unique TAP device and returns a handle to it.
    ///
    /// The interface name associated with this TAP device is chosen by the system, and can be
    /// retrieved via the [`name()`](Self::name) method. The returned TAP device is not persistent;
    /// it will be destroyed when the returned `Tap` object goes out of scope unless its persistence
    /// is changed via a call to [`Tap::set_persistent`].
    pub fn new() -> io::Result<Self> {
        let flags = libc::IFF_TAP | libc::IFF_NO_PI;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { inner: file })
    }

    #[inline]
    pub(crate) fn new_compat(device_num: u32) -> io::Result<Self> {
        Self::new_numbered(device_num, false)
    }

    /// Opens or creates a TAP device of the given name, returning an open handle to it.
    ///
    /// if `exclusive` is set to `true`, this function will fail if a TAP device matching `if_name`
    /// already exists. A TAP device created (and not opened) via this method is not persistent; it
    /// will be destroyed when the returned `Tap` object goes out of scope unless its persistence is
    /// changed via a call to [`Tap::set_persistent`].
    #[inline]
    pub fn new_named(if_name: Interface, exclusive: bool) -> io::Result<Self> {
        let flags = if exclusive {
            libc::IFF_TUN_EXCL | libc::IFF_TAP | libc::IFF_NO_PI
        } else {
            libc::IFF_TAP | libc::IFF_NO_PI
        };

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { inner: file })
    }

    /// Opens or creates a TAP device of the given device number, returning an open handle to it.
    ///
    /// If `exclusive` is set to `true`, this function will fail if a TAP device matching `if_name`
    /// already exists. A TAP device created (and not opened) via this method is not persistent; it
    /// will be destroyed when the returned `Tap` object goes out of scope unless its persistence is
    /// changed via a call to [`Tap::set_persistent`].
    #[inline]
    pub fn new_numbered(device_num: u32, exclusive: bool) -> io::Result<Self> {
        Self::new_named(
            Interface::new(format!("tap{}", device_num)).unwrap(),
            exclusive,
        )
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
            match libc::ioctl(self.inner.as_raw_fd(), TUNSETPERSIST, persist) {
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
            match libc::ioctl(self.inner.as_raw_fd(), TUNGETIFF, &raw mut req) {
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

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCSIFNAME, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Retrieves the current state of the TAP device (i.e. "UP" or "DOWN").
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        match unsafe { libc::ioctl(self.inner.as_raw_fd(), TUNGETIFF, &raw mut req) } {
            0.. => {
                if (unsafe { req.ifr_ifru.ifru_flags } & libc::IFF_UP as i16) == 0 {
                    Ok(DeviceState::Down)
                } else {
                    Ok(DeviceState::Up)
                }
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Sets the adapter state of the TAP device (e.g. "UP" or "DOWN").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let mut req = libc::ifreq {
            ifr_name: [0; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.inner.as_raw_fd(), TUNGETIFF, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
            }
        }

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCSIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn mtu(&self) -> io::Result<usize> {
        let ifr_name = self.name()?.name_raw_char();

        let mut req = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCGIFMTU, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_mtu < 0 } {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected negative MTU",
            ));
        }

        Ok(unsafe { req.ifr_ifru.ifru_mtu as usize })
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

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCSIFMTU, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TAP device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.inner.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TAP device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.inner.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = match nonblocking {
            true => flags | libc::O_NONBLOCK,
            false => flags & !libc::O_NONBLOCK,
        };

        if unsafe { libc::fcntl(self.inner.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
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
        if unsafe { libc::ioctl(self.inner.as_raw_fd(), TUNSETLINK, linktype) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets debug mode for the TAP device.
    pub fn set_debug(&self, debug: bool) -> io::Result<()> {
        let debug = match debug {
            true => 1,
            false => 0,
        };

        unsafe {
            match libc::ioctl(self.inner.as_raw_fd(), TUNSETDEBUG, debug) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TAP device to the given user ID, thereby enabling the user to perform operations
    /// on the device.
    pub fn set_owner(&self, owner_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.inner.as_raw_fd(), TUNSETOWNER, owner_id) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TAP device to the given group ID, thereby enabling users in that group to
    /// perform operations on the device.
    pub fn set_group(&self, group_id: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.inner.as_raw_fd(), TUNSETGROUP, group_id) {
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
        (&self.inner).read(data)
    }

    /// Sends a packet out over the TAP device.
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        (&self.inner).write(data)
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for Tap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl IntoRawFd for Tap {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl FromRawFd for Tap {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            inner: File::from_raw_fd(fd),
        }
    }
}
