// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io;
use std::net::IpAddr;

#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

#[cfg(not(target_os = "windows"))]
use crate::AddAddress;
use crate::{AddressInfo, DeviceState, Interface};

#[cfg(target_os = "linux")]
use crate::linux::TapImpl;
#[cfg(target_os = "macos")]
use crate::macos::TapImpl;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris"
))]
use crate::unix::TapImpl;

/// A cross-platform TAP interface, suitable for tunnelling link-layer packets.
pub struct Tap {
    inner: TapImpl,
}

impl Tap {
    /// Creates a new persistent TUN device with a unique device number assigned and returns its
    /// interface name.
    ///
    /// The created TUN device may subsequently be opened using [`Tun::open`] or [`Tun::new_named`]. The created TUN
    /// device is persistent until OS reboot unless it is explicitly destroyed.
    #[cfg(not(any(
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "windows"
    )))]
    #[inline]
    pub fn create() -> io::Result<Interface> {
        TapImpl::create()
    }

    /// Creates a new persistent TUN device of the given device number, erroring if the device
    /// already exists.
    ///
    /// A handle to the created TUN device may subsequently be opened using [`Tun::new_numbered`] (or
    /// [`Tun::open`] if the `portable-racy` feature is enabled). The created TUN device is
    /// persistent until OS reboot unless it is explicitly destroyed.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[inline]
    pub fn create_numbered(device_num: u32) -> io::Result<()> {
        TapImpl::create_numbered(device_num)
    }

    /// Destroys the provided TUN device, freeing its
    pub fn destroy(self) -> io::Result<()> {
        self.inner.destroy()
    }

    /// Destroys the TUN device specified by the given interface name.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub fn destroy_named(if_name: Interface) -> io::Result<()> {
        TapImpl::destroy_named(if_name)
    }

    /// Destroys the TUN device specified by the given interface number.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub fn destroy_numbered(device_num: u32) -> io::Result<()> {
        TapImpl::destroy_numbered(device_num)
    }

    /// Checks to see whether a TUN device of the given name exists.
    #[inline]
    pub fn exists(if_name: Interface) -> io::Result<bool> {
        TapImpl::exists(if_name)
    }

    /// Checks to see whether a TUN device of the given interface number exists.
    #[inline]
    pub fn exists_numbered(device_num: u32) -> io::Result<bool> {
        TapImpl::exists_numbered(device_num)
    }

    /// Opens an existing TUN device of the given device number.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "windows",
        all(feature = "portable-racy", not(target_os = "macos"))
    ))]
    #[inline]
    pub fn open(device_num: u32) -> io::Result<Self> {
        Ok(Self {
            inner: TapImpl::open(device_num)?,
        })
    }

    /// Creates a new, unique TUN device and returns an open handle to it.
    ///
    /// The interface name associated with this TUN device is chosen by the system, and can be
    /// retrieved via the [`name()`](Self::name) method. The created TUN device is not persistent,
    /// meaning that it will be destroyed when the returned `Tun` object goes out of scope.
    #[cfg(all(
        not(target_os = "macos"),
        not(target_os = "netbsd"),
        not(target_os = "openbsd"),
        any(feature = "portable-racy", not(target_os = "windows"))
    ))]
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            inner: TapImpl::new()?,
        })
    }

    pub fn new_compat(device_num: u32) -> io::Result<Self> {
        Ok(Self {
            inner: TapImpl::new_compat(device_num)?,
        })
    }

    /// Opens or creates a TUN device of the given device number, returning an open handle to it.
    ///
    /// The created TUN device is not persistent, meaning that it will be destroyed when the
    /// returned `Tun` object goes out of scope.
    #[cfg(not(any(
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    #[inline]
    pub fn new_numbered(device_num: u32) -> io::Result<Self> {
        Ok(Self {
            inner: TapImpl::new_numbered(device_num)?,
        })
    }

    /// Retrieves the interface name of the TAP device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.inner.name()
    }

    /// Retrieves the current adapter state of the TAP device (e.g. "UP" or "DOWN").
    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        self.inner.state()
    }

    /// Sets the adapter state of the TAP device (e.g. "UP" or "DOWN").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        self.inner.set_state(state)
    }

    /// Sets the adapter state of the TAP device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TAP device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Down)
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.inner.mtu()
    }

    /// Sets the blocking mode of the TAP device for reads/writes.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Retrieves the blocking mode of the TAP device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Retrieves the network-layer addresses assigned to the interface.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to TAP devices on creation.
    /// Developers should take this into account and avoid the incorrect assumption that `addrs()`
    /// will return only the addresses they have assigned via [`add_addr()`](Self::add_addr).
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.inner.addrs()
    }

    /// Assigns a network-layer address to the interface.
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.inner.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.inner.remove_addr(addr)
    }

    /// Sends a packet out over the TAP device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf)
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for Tap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let tap1 = Tap::new_compat(8).unwrap();
        let tap2 = Tap::new_compat(10).unwrap();
        let tap3 = Tap::new_compat(12).unwrap();

        let tap1_name = tap1.name().unwrap();
        let tap2_name = tap2.name().unwrap();
        let tap3_name = tap3.name().unwrap();

        assert!(tap1_name != tap2_name);
        assert!(tap1_name != tap3_name);
        assert!(tap2_name != tap3_name);

        tap1.destroy().unwrap();
        tap2.destroy().unwrap();
        tap3.destroy().unwrap();
    }

    /*
    #[cfg(target_os = "macos")]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"feth24\0".as_ptr() as *const libc::c_char) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tun = Tap::new_compat(24).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name_cstr());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"tap24\0".as_ptr() as *const libc::c_char) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tap = Tap::new_numbered(24).unwrap();
        let tap_iface = tap.name().unwrap();

        assert_eq!(chosen_name, tap_iface.name_cstr());
    }
    */

    #[test]
    fn up_down() {
        let mut tap1 = Tap::new_compat(7).unwrap();

        tap1.set_up().unwrap();
        tap1.set_down().unwrap();
        tap1.destroy().unwrap();
    }

    #[test]
    fn exists() {
        let tap1 = Tap::new_compat(7).unwrap();
        let tap1_name = tap1.name().unwrap();
        assert!(tap1_name.exists().unwrap());
        tap1.destroy().unwrap();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn not_exists() {
        use std::ffi::OsStr;
        let chosen_name = OsStr::new("tap24");
        let iface = Interface::new(chosen_name).unwrap();
        assert!(!Tap::exists(iface).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn not_exists() {
        use std::ffi::OsStr;
        let chosen_name = OsStr::new("feth24");
        let iface = Interface::new(chosen_name).unwrap();
        assert!(!Tap::exists(iface).unwrap());
    }

    #[test]
    fn not_persistent() {
        let tap1 = Tap::new_compat(8).unwrap();

        let tap1_name = tap1.name().unwrap();
        tap1.destroy().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!Tap::exists(tap1_name).unwrap());
    }

    #[test]
    fn nonblocking_switch() {
        let tap = Tap::new_compat(10).unwrap();

        assert_eq!(tap.nonblocking().unwrap(), false);
        tap.set_nonblocking(true).unwrap();
        assert_eq!(tap.nonblocking().unwrap(), true);
        tap.set_nonblocking(false).unwrap();
        assert_eq!(tap.nonblocking().unwrap(), false);

        tap.destroy().unwrap();
    }
}

#[cfg(not(target_os = "windows"))]
#[cfg(test)]
mod tests_unix {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn add_ipv4() {
        let tap1 = Tap::new_compat(7).unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(ip1).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        tap1.destroy().unwrap();
    }

    #[test]
    fn add_ipv4_multi() {
        let tap1 = Tap::new_compat(7).unwrap();

        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(ip1).unwrap();

        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        tap1.add_addr(ip2).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
        tap1.destroy().unwrap();
    }

    #[test]
    fn add_ipv6() {
        let tap1 = Tap::new_compat(77).unwrap();

        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        tap1.destroy().unwrap();
    }

    #[test]
    fn add_ipv6_multi() {
        let tap1 = Tap::new_compat(4).unwrap();
        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip2 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
        tap1.destroy().unwrap();
    }

    #[test]
    fn add_ipv4_ipv6_multi() {
        let tap1 = Tap::new_compat(10).unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let ip3 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip4 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.add_addr(ip3).unwrap();
        tap1.add_addr(ip4).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
        assert!(addrs.iter().any(|a| a.address() == ip3));
        assert!(addrs.iter().any(|a| a.address() == ip4));
        tap1.destroy().unwrap();
    }

    #[test]
    fn remove_ipv4() {
        let tap1 = Tap::new_compat(8).unwrap();
        let ipv4 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(IpAddr::V4(ipv4)).unwrap();
        tap1.remove_addr(IpAddr::V4(ipv4)).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ipv4));
        tap1.destroy().unwrap();
    }

    #[test]
    fn remove_ipv4_multi() {
        let tap1 = Tap::new_compat(11).unwrap();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 101, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 102, 0, 1));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
        tap1.destroy().unwrap();
    }

    #[test]
    fn remove_ipv6() {
        let tap1 = Tap::new_compat(8).unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8));
        tap1.add_addr(ip1).unwrap();
        tap1.remove_addr(ip1).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        tap1.destroy().unwrap();
    }

    #[test]
    fn remove_ipv6_multi() {
        let tap1 = Tap::new_compat(9).unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8));
        let ip2 = IpAddr::V6(Ipv6Addr::new(2, 5, 3, 4, 5, 6, 7, 8));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        tap1.destroy().unwrap();
    }

    #[test]
    fn remove_ipv4_ipv6_multi() {
        let tap1 = Tap::new_compat(6).unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        let ip2 = IpAddr::V6(Ipv6Addr::new(2, 5, 3, 4, 5, 6, 7, 8));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 101, 0, 1));
        let ip4 = IpAddr::V4(Ipv4Addr::new(10, 102, 0, 1));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.add_addr(ip3).unwrap();
        tap1.add_addr(ip4).unwrap();
        tap1.remove_addr(ip3).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip4).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
        assert!(!addrs.iter().any(|a| a.address() == ip3));
        assert!(!addrs.iter().any(|a| a.address() == ip4));
        tap1.destroy().unwrap();
    }
}
