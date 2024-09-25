// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::os::fd::RawFd;
use std::{array, io, ptr};

use crate::{DeviceState, Interface};

use super::ifreq_empty;
use crate::libc_extra::*;

pub struct Tap {
    fd: RawFd,
    persistent: bool,
    // TODO: is there some way to fetch the interface name from a `/dev/tapX` fd? It appears not.
    iface: Interface,
}

impl Tap {
    /// Creates a new, unique TAP device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    // OpenBSD has no `/dev/tap` cloning interface, so we loop through devices until we find one
    // that isn't in use.
    //
    // NetBSD/DragonFly BSD *do* have a `/dev/tap` cloned interface, but it makes only non-persistent TAP
    // devices so we don't make use of it.
    #[cfg(any(target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
    #[inline]
    fn new_impl() -> io::Result<Self> {
        Self::new_from_loop()
    }

    // FreeBSD does have a `/dev/tap` cloning interface, but its use can be disabled via sysctl. We
    // check this sysctl and either do or don't use `/dev/tap` accordingly.
    #[cfg(target_os = "freebsd")]
    #[inline]
    fn new_impl() -> io::Result<Self> {
        let mut buf = [0u8; 4];
        let mut buflen = 4usize;

        const DEVFS_CLONING: *const i8 = b"net.link.tap.devfs_cloning\0".as_ptr() as *const i8;

        if unsafe {
            libc::sysctlbyname(
                DEVFS_CLONING,
                buf.as_mut_ptr() as *mut libc::c_void,
                ptr::addr_of_mut!(buflen),
                ptr::null_mut(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        debug_assert_eq!(buflen, 4);
        match &buf[..buflen] {
            b"\x01\x00\x00\x00" => Self::new_from_cloned(), // TODO: endianness?
            _ => Self::new_from_loop(),
        }
    }

    /// Clones a new TAP interface from `/dev/tap`.
    #[cfg(target_os = "freebsd")]
    fn new_from_cloned() -> io::Result<Self> {
        let tap_ptr = b"/dev/tap\0".as_ptr() as *const i8;
        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(tap_ptr, libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let iface = match Self::tap_devname(fd) {
            Ok(i) => i,
            Err(e) => {
                Self::close_fd(fd);
                return Err(e);
            }
        };

        Ok(Self {
            fd,
            persistent: false,
            iface,
        })
    }

    /// Gets the name of the device that `tap_fd` is connected to.
    #[cfg(target_os = "freebsd")]
    fn tap_devname(tap_fd: RawFd) -> io::Result<Interface> {
        unsafe {
            let mut name = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
            if fdevname_r(
                tap_fd,
                name.as_mut_ptr() as *mut i8,
                Interface::MAX_INTERFACE_NAME_LEN as i32,
            )
            .is_null()
            {
                return Err(io::Error::last_os_error());
            }

            Ok(Interface::from_raw(name))
        }
    }

    /*
    #[cfg(target_os = "dragonfly")]
    fn tap_devname(tap_fd: RawFd) -> io::Result<Interface> {
        unsafe {
            let mut name = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
            if fdevname_r(
                tap_fd,
                name.as_mut_ptr() as *mut i8,
                Interface::MAX_INTERFACE_NAME_LEN as i32,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            Ok(Interface::from_raw(name))
        }
    }

    #[cfg(target_os = "netbsd")]
    fn tap_devname(tap_fd: RawFd) -> io::Result<Interface> {
        // NOTE: AIX does the same:
        // https://www.ibm.com/docs/en/aix/7.2?topic=files-tap-special-file

        const TAPGIFNAME: u64 = 0x40906500;

        let mut req = ifreq_empty();

        if unsafe { libc::ioctl(tap_fd, TAPGIFNAME, ptr::addr_of_mut!(req)) } < 0 {
            return Err(io::Error::last_os_error())
        }

        Ok(unsafe { Interface::from_raw(array::from_fn(|i| req.ifr_name[i] as u8)) })
    }
    */

    fn new_from_loop() -> io::Result<Self> {
        // Some BSD variants have no support for auto-selection of an unused TAP number, so we need
        // to loop here.

        for i in 4..1000 {
            // Max TAP number is 999
            match Self::new_numbered_impl(i, true) {
                Err(e)
                    if e.raw_os_error() == Some(libc::EBUSY)
                        || e.raw_os_error() == Some(libc::EEXIST) =>
                {
                    continue
                }
                t => return t,
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no unused TAP number could be found for use",
        ))
    }

    /// Opens or creates a TAP device of the given name.
    #[inline]
    pub fn new_named(iface: Interface) -> io::Result<Self> {
        Self::new_named_impl(iface, false)
    }

    pub fn new_named_impl(iface: Interface, unique: bool) -> io::Result<Self> {
        let tap_name = iface.name_raw();
        if &tap_name[..3] != b"tap" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid name for TAP device (must begin with \"tap\")",
            ));
        }

        let ctrl_fd = Self::ctrl_fd();

        let mut req = ifreq_empty();
        req.ifr_name = iface.name_raw_i8();

        // FreeBSD and DragonFly BSD return ENXIO ("Device not configured") for SIOCIFCREATE and
        // use SIOCIFCREATE2 instead within their `ifconfig` implementation. It passes no argument
        // in the `ifr_ifru` field.
        #[cfg(not(any(target_os = "dragonfly", target_os = "freebsd")))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE;
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE2;

        if unsafe { libc::ioctl(ctrl_fd, IOCTL_CREATE, ptr::addr_of_mut!(req)) } < 0 {
            let err = io::Error::last_os_error();
            if unique
                || (err.raw_os_error() != Some(libc::EBUSY)
                    && err.raw_os_error() != Some(libc::EEXIST))
            {
                Self::close_fd(ctrl_fd);
                return Err(err);
            }
        }

        let tap_path = [b"/dev/", iface.name_cstr().to_bytes_with_nul()].concat();
        let tap_ptr = tap_path.as_ptr() as *const i8;

        let fd = unsafe { libc::open(tap_ptr, libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(ctrl_fd, iface);
            Self::close_fd(ctrl_fd);
            return Err(err);
        }

        Self::close_fd(ctrl_fd);

        Ok(Self {
            fd,
            persistent: false,
            iface,
        })
    }

    /// Opens or creates a TAP device of the given number.
    #[inline]
    pub fn new_numbered(tap_number: u32) -> io::Result<Self> {
        Self::new_numbered_impl(tap_number, false)
    }

    #[inline]
    fn new_numbered_impl(tap_number: u32, unique: bool) -> io::Result<Self> {
        // "tap" + u32 + \0 won't overflow IFNAMSIZ
        let tap_number = tap_number.to_string();
        let tap_name = [b"tap", tap_number.as_bytes()].concat();

        let iface = unsafe {
            Interface::from_raw(array::from_fn(|i| {
                if i < tap_name.len() {
                    tap_name[i]
                } else {
                    0
                }
            }))
        };
        Self::new_named_impl(iface, unique)
    }

    /// Sets the persistence of the TAP interface.
    ///
    /// If set to `false`, the TAP device will be destroyed once all file descriptor handles to it
    /// have been closed. If set to `true`, the TAP device will persist until it is explicitly
    /// closed or the system reboots. By default, persistence is set to `true`.
    #[inline]
    pub fn set_persistent(&mut self, persistent: bool) -> io::Result<()> {
        self.persistent = persistent;
        Ok(())
    }

    /// Retrieves the interface name associated with the TAP device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.iface)
    }

    /// Retrieves the current state of the TAP device (i.e. "up" or "down").
    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        let ctrl_fd = Self::ctrl_fd();

        let mut req = ifreq_empty();
        req.ifr_name = self.iface.name_raw_i8();

        if unsafe { libc::ioctl(ctrl_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(ctrl_fd);
            return Err(err);
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        let is_up = unsafe { req.ifr_ifru.ifru_flags & libc::IFF_UP as i16 > 0 };
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        let is_up = unsafe { req.ifr_ifru.ifru_flags[0] & libc::IFF_UP as i16 > 0 };

        Self::close_fd(ctrl_fd);

        if is_up {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Sets the adapter state of the TAP device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let ctrl_fd = Self::ctrl_fd();

        let mut req = ifreq_empty();
        req.ifr_name = self.iface.name_raw_i8();

        if unsafe { libc::ioctl(ctrl_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(ctrl_fd);
            return Err(err);
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

        if unsafe { libc::ioctl(ctrl_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(ctrl_fd);
            return Err(err);
        }

        Self::close_fd(ctrl_fd);
        Ok(())
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        let mut req = ifreq_empty();
        req.ifr_name = self.iface.name_raw_i8();

        unsafe {
            match libc::ioctl(self.fd, SIOCGIFMTU, ptr::addr_of_mut!(req)) {
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
        req.ifr_name = self.iface.name_raw_i8();
        req.ifr_ifru.ifru_mtu = mtu;

        unsafe {
            match libc::ioctl(self.fd, SIOCSIFMTU, ptr::addr_of_mut!(req)) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Reads a single packet from the TAP device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Writes a single packet to the TAP device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TAP device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TAP device.
    #[inline]
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

    #[inline]
    fn destroy_iface(fd: RawFd, iface: Interface) {
        let mut req = ifreq_empty();
        req.ifr_name = iface.name_raw_i8();

        unsafe {
            debug_assert_eq!(libc::ioctl(fd, SIOCIFDESTROY, ptr::addr_of_mut!(req)), 0);
        }
    }

    #[inline]
    fn ctrl_fd() -> RawFd {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };

        debug_assert!(fd >= 0);
        fd
    }

    #[inline]
    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        Self::close_fd(self.fd);

        if !self.persistent {
            let ctrl_fd = Self::ctrl_fd();
            Self::destroy_iface(ctrl_fd, self.iface);
            Self::close_fd(ctrl_fd);
        }
    }
}
