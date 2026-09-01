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
use std::{array, io, ptr};

use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface};

#[cfg(not(doc))]
use super::ifreq_empty;
use crate::libc_extra::*;

// We use a custom `iovec` struct here because we don't want to do a *const to *mut conversion
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct iovec_const {
    pub iov_base: *const libc::c_void,
    pub iov_len: libc::size_t,
}

/// A TUN device interface that includes BSD- or Solaris-specific functionality.
#[repr(transparent)]
pub struct Tun {
    fd: RawFd,
}

impl Tun {
    /// Creates a new, unique TUN device, returning its interface name.
    /// 
    /// The created TUN device may subsequently be opened using [`Tun::open`]. To atomically create
    /// and open a TUN device in one operation, the `Tun::new()` function may be used, though it is
    /// only supported on certain platforms.
    #[cfg(not(target_os = "openbsd"))]
    #[inline]
    pub fn create() -> io::Result<Interface> {
        const CLONE_DEVICE: &[u8] = b"tun\0";

        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut req = libc::ifreq {
            ifr_name: [0x00; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };
        req.ifr_name[..CLONE_DEVICE.len()].copy_from_slice(CLONE_DEVICE);

        // FreeBSD and DragonFly BSD return ENXIO ("Device not configured") for SIOCIFCREATE and
        // use SIOCIFCREATE2 instead within their `ifconfig` implementation. It passes no argument
        // in the `ifr_ifru` field.
        #[cfg(not(any(target_os = "dragonfly", target_os = "freebsd")))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE;
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        #[cfg(not(doc))]
        const IOCTL_CREATE: u64 = SIOCIFCREATE2;

        if unsafe { libc::ioctl(inet_fd, IOCTL_CREATE, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(inet_fd);
            return Err(err);
        }

        Self::close_fd(inet_fd);
        Ok(Interface::from_raw(req.ifr_name))
    }

    /// Creates a new TUN device of the given name.
    /// 
    /// The created TUN device may subsequently be opened using [`Tun::open`]. To atomically create
    /// and open a named TUN device in one operation, the `Tun::new_named()` function may be used,
    /// though it is only supported on certain platforms.
    #[inline]
    pub fn create_named(if_name: Interface) -> io::Result<()> {
        if &if_name.name_raw()[..3] != b"tun" || !matches!(if_name.name_raw()[3], b'0'..=b'9') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "non-TUN interface name provided"))
        }

        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::SOCK_CLOEXEC) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(inet_fd, SIOCIFCREATE, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(inet_fd);
            return Err(err);
        }

        Self::close_fd(inet_fd);
        Ok(())
    }

    /// Creates a new persistent TUN device of the given device number, erroring if the device
    /// already exists.
    /// 
    /// A handle to the created TUN device may subsequently be opened using [`Tun::new_numbered`]
    /// (or [`Tun::open_numbered`] if the `portable-racy` feature is enabled). The created TUN
    /// device is persistent until OS reboot unless it is explicitly destroyed.
    #[inline]
    pub fn create_numbered(device_num: u32) -> io::Result<Self> {
        let label = format!("tun{}\0", n).into_bytes();
        let if_name = Interface::from_raw(array::from_fn(|i| label.get(i).unwrap_or(0x00)));
        Self::create_named(if_name)
    }

    /// Opens an existing TUN device of the given device number.
    #[cfg(feature = "portable-racy")]
    #[inline]
    pub fn open(device_num: u32) -> io::Result<Self> {
        let label = format!("tun{}\0", n).into_bytes();
        let if_name = Interface::from_raw(array::from_fn(|i| label.get(i).unwrap_or(0x00)));

        if &if_name.name_raw()[..3] != b"tun" || !matches!(if_name.name_raw()[3], b'0'..=b'9') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "non-TUN interface name provided"))
        }

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        // Check to make sure the device exists first (otherwise we'll be creating a new device).
        if unsafe { libc::ioctl(self.fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        // Note: this is a TOCTOU race. If another thread or process destroys the device after the
        // above SIOCGIFFLAGS check occurs but before the below `open()` call, the below will create
        // a new (ephemeral) device rather than opening the existing (potentially persistent) one.
        // *BSD operating systems provide no mechanism for accomplishing this in a race-free manner.

        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(if_name.name(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    pub fn exists(if_name: Interface) -> io::Result<bool> {
        if &if_name.name_raw()[..3] != b"tun" || !matches!(if_name.name_raw()[3], b'0'..=b'9') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "non-TUN interface name provided"))
        }

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let ctrl_fd = Self::ctrl_fd();

        if unsafe { libc::ioctl(ctrl_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } == 0 {
            return Ok(true);
        }

        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENXIO)) {
            Ok(false)
        } else {
            Err(err)
        }
    }

    /// Creates a new, unique TUN device.
    /// 
    /// # Platform-Specific Considerations
    /// 
    /// For FreeBSD, the `net.link.tun.devfs_cloning` systcl option may disable this
    /// functionality during runtime if it is set to `0`; in such cases, the function will return
    /// an error of type [`io::ErrorKind::NotFound`].
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd", feature = "portable-racy"))]
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[inline]
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd"))]
    fn new_impl() -> io::Result<Self> {
        let tun_ptr = b"/dev/tun\0".as_ptr() as *const libc::c_char;
        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(tun_ptr, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = io::Error::last_os_error();

            #[cfg(all(target_os = "freebsd", feature = "portable-racy"))]
            if matches!(err.raw_os_error(), Some(libc::ENOENT)) {
                // net.link.tun.devfs_cloning was set to 0
                // Fall back to iterating through possible TUN numbers
                return Self::new_impl_racy();
            }

            return Err(err);
        }

        Ok(Self { fd })
    }

    #[cfg(all(target_os = "openbsd", feature = "portable-racy"))]
    #[inline]
    fn new_impl() -> io::Result<Self> {
        Self::new_impl_racy()
    }

    #[cfg(all(any(target_os = "openbsd", target_os = "freebsd"), feature = "portable_racy"))]
    #[inline]
    fn new_impl_racy() -> io::Result<Self> {
        for i in 0..1000 {
            let label = format!("/dev/tun{}\0", n).into_bytes();
            let tun_ptr = tun_path.as_ptr() as *const libc::c_char;

            let fd = unsafe { libc::open(tun_ptr, libc::O_RDWR | libc::O_CLOEXEC) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EBUSY | libc::EEXIST)) {
                    continue;
                }

                return Err(err);
            }

            return Ok(Self { fd });
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no unused TUN number could be found for use",
        ))
    }

    /// Opens or creates a TUN device of the given name, returning an open handle to it.
    /// 
    /// if `exclusive` is set to `true`, this function will fail if a TUN device matching `if_name`
    /// already exists.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        if &if_name.name_raw()[..3] != b"tun" || !matches!(if_name.name_raw()[3], b'0'..=b'9') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "non-TUN interface name provided"))
        }

        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(if_name.name(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Opens or creates a TUN device of the given device number, returning an open handle to it.
    /// 
    /// The created TUN device is not persistent, meaning that it will be destroyed when the
    /// returned `Tun` object goes out of scope.
    #[inline]
    pub fn new_numbered(device_num: u32) -> io::Result<Self> {
        let label = format!("tun{}\0", n).into_bytes();
        let if_name = Interface::from_raw(array::from_fn(|i| label.get(i).unwrap_or(0x00)));
        Self::new_named(if_name)
    }

    #[cfg(target_os = "freebsd")]
    fn tun_devname(tun_fd: RawFd) -> io::Result<Interface> {
        unsafe {
            let mut name = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
            if fdevname_r(
                tun_fd,
                name.as_mut_ptr() as *mut libc::c_char,
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
    fn tun_devname(tun_fd: RawFd) -> io::Result<Interface> {
        unsafe {
            let mut name = [0u8; Interface::MAX_INTERFACE_NAME_LEN + 1];
            if fdevname_r(
                tun_fd,
                name.as_mut_ptr() as *mut libc::c_char,
                Interface::MAX_INTERFACE_NAME_LEN as i32,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            Ok(Interface::from_raw(name))
        }
    }
    */

    /// Opens or creates a TUN device of the given number.
    #[inline]
    pub fn new_numbered(tun_number: u32) -> io::Result<Self> {
        Self::new_numbered_impl(tun_number, false)
    }

    #[inline]
    fn new_numbered_impl(tun_number: u32, unique: bool) -> io::Result<Self> {
        // "tun" + u32 + \0 won't overflow IFNAMSIZ
        let tun_number = tun_number.to_string();
        let tun_name = [b"tun", tun_number.as_bytes()].concat();

        let iface = unsafe {
            Interface::from_raw(array::from_fn(|i| {
                if i < tun_name.len() {
                    tun_name[i]
                } else {
                    0
                }
            }))
        };
        Self::new_named_impl(iface, unique)
    }

    /// Retrieves the network-layer addresses assigned to the interface.
    ///
    /// OpenBSD automatically assigns a link-layer IPv6 address (in addition to the specified IPv6
    /// address) the first time an IPv6 address is assigned to a TUN device. As such, applications
    /// **should not** rely on the assumption that the only addresses returned from this method are
    /// those that were previously assigned via [`add_addr()`](Self::add_addr).
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

    /// Retrieves the interface name associated with the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.iface)
    }

    /// Retrieves the current state of the TUN device (i.e. "up" or "down").
    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        let ctrl_fd = Self::ctrl_fd();

        let mut req = ifreq_empty();
        req.ifr_name = self.iface.name_raw_char();

        if unsafe { libc::ioctl(ctrl_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(ctrl_fd);
            return Err(err);
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        let flags = unsafe { req.ifr_ifru.ifru_flags };
        #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
        let flags = unsafe { req.ifr_ifru.ifru_flags[0] };

        Self::close_fd(ctrl_fd);

        if flags & (libc::IFF_UP as i16) > 0 {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let ctrl_fd = Self::ctrl_fd();

        let mut req = ifreq_empty();
        req.ifr_name = self.iface.name_raw_char();

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

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();

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

    /// Sets the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        let Ok(mtu) = i32::try_from(mtu) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU too large"));
        };

        let mut req = ifreq_empty();
        req.ifr_name = self.name()?.name_raw_char();
        req.ifr_ifru.ifru_mtu = mtu;

        unsafe {
            match libc::ioctl(self.fd, SIOCSIFMTU, ptr::addr_of_mut!(req)) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Reads a single packet from the TUN device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf)
    }

    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    #[inline]
    pub fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    #[inline]
    pub fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
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

    /// Writes a single packet to the TUN device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_impl(buf)
    }

    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    #[inline]
    pub fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    #[inline]
    pub fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
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
                    "only IPv4 and IPv6 packets are supported over tun",
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

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TUN device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
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
        req.ifr_name = iface.name_raw_char();

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

        if !self.persistent {
            let ctrl_fd = Self::ctrl_fd();
            Self::destroy_iface(ctrl_fd, self.iface);
            Self::close_fd(ctrl_fd);
        }
    }
}
