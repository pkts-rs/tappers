// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
use std::fs;

use std::{io, ptr};

#[cfg(not(doc))]
use super::ifreq_empty;

use crate::libc_extra::*;
use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface};

#[cfg(target_os = "openbsd")]
fn tap_major() -> u32 {
    #[cfg(any(target_arch = "powerpc64"))]
    {
        75
    }
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    ))]
    {
        93
    }
    #[cfg(target_arch = "x86")]
    {
        94
    }
    #[cfg(target_arch = "arm")]
    {
        104
    }
    #[cfg(any(target_arch = "sparc64"))]
    {
        135
    }
}

#[cfg(target_os = "netbsd")]
fn tap_major() -> u32 {
    unsafe { getdevmajor(c"tap".as_ptr(), libc::S_IFCHR) as u32 }
}

/// A TAP device interface that includes BSD-/Solaris-specific functionality.
pub struct Tap {
    inner: File,
}

// OpenBSD: only supports new_named() with file opening similar to tun
// NetBSD: has a cloning device at /dev/tap, but doesn't support opening named ones or cloned persistent, only named persistent.
// Dragonfly BSD: has a cloning device at /dev/tap but doesn't support opening named ones. Supports clone for persistent as well as open persistent and doesn't require manual mknod.

impl Tap {
    /// NetBSD will attach to an existing persistent TAP device if it is the next lowest number.
    /// This is of practical importance as NetBSD *also* creates persistent tap0-tap3 interfaces by
    /// default on startup.

    /// Creates a new, unique TAP device, returning its interface name.
    ///
    /// The created TAP device may subsequently be opened using [`Tap::open`]. To atomically create
    /// and open a TAP device in one operation, the `Tap::new()` function may be used, though it is
    /// only supported on certain platforms.
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    #[inline]
    pub fn create() -> io::Result<Interface> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        let if_name = Interface::new("tap").unwrap();
        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
            },
        };

        // FreeBSD and DragonFly BSD return ENXIO ("Device not configured") for SIOCIFCREATE and
        // use SIOCIFCREATE2 instead within their `ifconfig` implementation. It passes no argument
        // in the `ifr_ifru` field.
        #[cfg(not(any(target_os = "dragonfly", target_os = "freebsd")))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE;
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE2;

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), IOCTL_CREATE, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) })
    }

    /// Creates a new TAP device of the given name.
    ///
    /// The created TAP device may subsequently be opened using [`Tap::open`]. To atomically create
    /// and open a named TAP device in one operation, the `Tap::new_named()` function may be used,
    /// though it is only supported on certain platforms.
    #[inline]
    pub fn create_named(if_name: Interface) -> io::Result<()> {
        if &if_name.name_raw()[..3] != b"tap" || !if_name.name_raw()[3].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-TAP interface name provided",
            ));
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        {
            let unit = if_name
                .name_cstr()
                .to_str()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
                .and_then(|s| {
                    s.get(3..)
                        .unwrap_or("")
                        .parse::<u32>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
                })?;

            let dev = libc::makedev(tap_major(), unit);
            let path = PathBuf::from("/dev").join(if_name.name());
            let path_cstr = CString::new(path.as_os_str().as_bytes()).unwrap();

            if unsafe {
                libc::mknod(
                    path_cstr.as_ptr(),
                    libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                    dev,
                )
            } < 0
            {
                let e = io::Error::last_os_error();
                if !matches!(e.kind(), io::ErrorKind::AlreadyExists) {
                    return Err(e);
                }
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

        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
            },
        };

        // FreeBSD and DragonFly BSD return ENXIO ("Device not configured") for SIOCIFCREATE and
        // use SIOCIFCREATE2 instead within their `ifconfig` implementation. It passes no argument
        // in the `ifr_ifru` field.
        #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE;
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE2;

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), IOCTL_CREATE, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Creates a new persistent TAP device of the given device number, erroring if the device
    /// already exists.
    ///
    /// A handle to the created TAP device may subsequently be opened using [`Tap::new_numbered`]
    /// (or [`Tap::open_numbered`] if the `portable-racy` feature is enabled). The created TAP
    /// device is persistent until OS reboot unless it is explicitly destroyed.
    #[inline]
    pub fn create_numbered(device_num: u32) -> io::Result<()> {
        Self::create_named(Interface::new(format!("tap{}", device_num)).unwrap())
    }

    #[inline]
    pub fn destroy(self) -> io::Result<()> {
        let if_name = self.name()?;
        self.set_state(DeviceState::Down)?;

        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
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

        drop(self);

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFDESTROY, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        {
            let path = PathBuf::from("/dev").join(if_name.name());
            fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Opens an existing TAP device of the given device number.
    #[cfg(any(not(target_os = "freebsd"), feature = "portable-racy"))]
    #[inline]
    pub fn open(device_num: u32) -> io::Result<Self> {
        Self::open_impl(device_num)
    }

    #[cfg(any(target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
    #[inline]
    fn open_impl(device_num: u32) -> io::Result<Self> {
        let if_name = Interface::new(format!("tap{}", device_num)).unwrap();
        let path = PathBuf::from("/dev").join(if_name.name());

        let file = OpenOptions::new().read(true).write(true).open(path)?;

        Ok(Self { inner: file })
    }

    #[cfg(all(target_os = "freebsd", feature = "portable-racy"))]
    #[inline]
    fn open_impl(device_num: u32) -> io::Result<Self> {
        let if_name = Interface::new(format!("tap{}", device_num)).unwrap();

        if &if_name.name_raw()[..3] != b"tap" || !if_name.name_raw()[3].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-TAP interface name provided",
            ));
        }

        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
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

        // Check to make sure the device exists first (otherwise we'll be creating a new device).
        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Note: this is a TOCTOU race. If another thread or process destroys the device after the
        // above SIOCGIFFLAGS check occurs but before the below `open()` call, the below will create
        // a new (ephemeral) device rather than opening the existing (potentially persistent) one.
        // *BSD operating systems provide no mechanism for accomplishing this in a race-free manner.

        // TODO: unify `ErrorKind`s returned
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PathBuf::from("/dev").join(if_name.name()))?;

        Ok(Self { inner: file })
    }

    /// Destroys the TAP device specified by the given interface name.
    pub fn destroy_named(if_name: Interface) -> io::Result<()> {
        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
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

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFDESTROY, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        {
            let path = PathBuf::from("/dev").join(if_name.name());
            fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Destroys the TAP device specified by the given interface number.
    pub fn destroy_numbered(device_num: u32) -> io::Result<()> {
        Self::destroy_named(Interface::new(format!("tap{}", device_num)).unwrap())
    }

    /// Checks to see whether a TAP device of the given name exists.
    pub fn exists(if_name: Interface) -> io::Result<bool> {
        if &if_name.name_raw()[..3] != b"tap" || !if_name.name_raw()[3].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-TAP interface name provided",
            ));
        }

        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
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

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } == 0 {
            return Ok(true);
        }

        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENXIO)) {
            Ok(false)
        } else {
            Err(err)
        }
    }

    /// Checks to see whether a TAP device of the given device number exists.
    pub fn exists_numbered(device_num: u32) -> io::Result<bool> {
        let if_name = Interface::new(format!("tap{}", device_num)).unwrap();
        Self::exists(if_name)
    }

    /// Creates a new, unique TAP device.
    ///
    /// # Platform-Specific Considerations
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd"))]
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[inline]
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd"))]
    fn new_impl() -> io::Result<Self> {
        let file = match OpenOptions::new().read(true).write(true).open("/dev/tap") {
            Ok(file) => file,
            #[cfg(all(target_os = "freebsd", feature = "portable-racy"))]
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT)) => {
                return Self::new_impl_racy();
            }
            Err(e) => return Err(e),
        };

        Ok(Self { inner: file })
    }

    #[cfg(all(target_os = "freebsd", feature = "portable-racy"))]
    #[inline]
    fn new_impl_racy() -> io::Result<Self> {
        for device_num in 0..1000 {
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/dev/tap{}", device_num))
            {
                Ok(file) => file,
                Err(e) if matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EEXIST)) => continue,
                Err(e) => return Err(e),
            };

            return Ok(Self { inner: file });
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no unused TAP number could be found for use",
        ))
    }

    #[inline]
    pub(crate) fn new_compat(device_num: u32) -> io::Result<Self> {
        Self::new_compat_impl(device_num)
    }

    #[cfg(target_os = "freebsd")]
    #[inline]
    fn new_compat_impl(device_num: u32) -> io::Result<Self> {
        Self::new_numbered(device_num)
    }

    #[cfg(not(target_os = "freebsd"))]
    #[inline]
    fn new_compat_impl(device_num: u32) -> io::Result<Self> {
        if let Err(e) = Self::create_numbered(device_num) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(e);
            }
        }

        // If this races, this persistent TAP device will remain open, which some may consider a
        // resource leak. However, the reason for failure is that another process or thread opened
        // the TAP device first under the assumption that the TAP device is persistent, so it will
        // assume responsibility for cleaning up the persistent device. Thus, no big issue.
        Self::open(device_num)
    }

    /// Opens or creates a TAP device of the given name, returning an open handle to it.
    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        if &if_name.name_raw()[..3] != b"tap" || !if_name.name_raw()[3].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-TAP interface name provided",
            ));
        }

        let path = PathBuf::from("/dev").join(if_name.name());
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        Ok(Self { inner: file })
    }

    /// Opens or creates a TAP device of the given device number, returning an open handle to it.
    ///
    /// The created TAP device is not persistent, meaning that it will be destroyed when the
    /// returned `Tap` object goes out of scope.
    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn new_numbered(device_num: u32) -> io::Result<Self> {
        Self::new_named(Interface::new(format!("tap{}", device_num)).unwrap())
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

    /// Retrieves the interface name associated with the TAP device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        Self::name_impl(self.inner.as_raw_fd())
    }

    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    fn name_impl(fd: RawFd) -> io::Result<Interface> {
        #[cfg(target_os = "dragonfly")]
        let buflen = (Interface::MAX_INTERFACE_NAME_LEN + 1) as libc::size_t;
        #[cfg(target_os = "freebsd")]
        let buflen = (Interface::MAX_INTERFACE_NAME_LEN + 1) as i32;

        let mut buf = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
        let res = unsafe { fdevname_r(fd, buf.as_mut_ptr().cast::<libc::c_char>(), buflen) };

        #[cfg(target_os = "dragonfly")]
        if res != 0 {
            return Err(io::Error::from_raw_os_error(res));
        }
        #[cfg(target_os = "freebsd")]
        if res.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown error in fdevname_r()",
            ));
        }

        Ok(unsafe { Interface::from_raw(buf) })
    }

    // TAPGIFNAME only works in netbsd for tap devices created from /dev/tap rather than SIOCIFCREATE.
    /*
    #[cfg(any(target_os = "netbsd"))]
    fn name_impl(fd: RawFd) -> io::Result<Interface> {
        let mut req = libc::ifreq {
            ifr_name: [0i8; libc::IFNAMSIZ],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
            },
        };

        let res = unsafe { libc::ioctl(fd, TAPGIFNAME, &raw mut req) };
        if res != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) })
        }
    }
    */

    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    fn name_impl(fd: RawFd) -> io::Result<Interface> {
        let mut stats: libc::stat = unsafe { std::mem::zeroed() };

        let res = unsafe { libc::fstat(fd, &raw mut stats) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let minor_number = libc::minor(stats.st_rdev);
        Ok(Interface::new(format!("tap{}", minor_number)).unwrap())
    }

    /// Sets the adapter state of the TAP device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
                #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
                DeviceState::Down => req.ifr_ifru.ifru_flags[0] &= !(libc::IFF_UP as i16),
                #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
                DeviceState::Up => req.ifr_ifru.ifru_flags[0] |= libc::IFF_UP as i16,
            }
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Retrieves the current state of the TAP device (i.e. "UP" or "DOWN").
    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        let is_up = unsafe { req.ifr_ifru.ifru_flags & (libc::IFF_UP as i16) > 0 };
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        let is_up = unsafe { req.ifr_ifru.ifru_flags[0] & (libc::IFF_UP as i16) > 0 };

        if is_up {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCGIFMTU, &raw mut req) {
                0.. => {
                    let mtu = req.ifr_ifru.ifru_mtu;
                    if mtu < 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected negative MTU",
                        ));
                    }

                    Ok(mtu as usize)
                }
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        let Ok(mtu) = i32::try_from(mtu) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU too large"));
        };

        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();
        req.ifr_ifru.ifru_mtu = mtu;

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(
                match libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
                    ..=-1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                },
            )
        };

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCSIFMTU, &raw mut req) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Reads a single packet from the TAP device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }

    /// Writes a single packet to the TAP device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        (&self.inner).write(buf)
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TAP device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.inner.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TAP device.
    #[inline]
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
            return Err(io::Error::last_os_error());
        } else {
            Ok(())
        }
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
impl FromRawFd for Tap {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            inner: File::from_raw_fd(fd),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl IntoRawFd for Tap {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}
