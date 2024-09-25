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

use crate::{DeviceState, Interface};

#[cfg(target_os = "linux")]
use crate::linux::TunImpl;
#[cfg(target_os = "macos")]
use crate::macos::TunImpl;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris"
))]
use crate::unix::TunImpl;
#[cfg(target_os = "windows")]
use crate::wintun::TunImpl;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::HANDLE;

/// A cross-platform TUN interface.
pub struct Tun {
    inner: TunImpl,
}

// *BSD and MacOS all strictly name interfaces, so we can infer type from iface name.
// Linux doesn't strictly name interfaces, but there appears to be a netlink call based on
// `strace ip -details link show` that returns interface type information.
// We can just call open() for Wintun and then immediately close the tunnel.

// Note: Wintun TOCTOU? Only if other interface not created with Wintun but not `tappers`

impl Tun {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            inner: TunImpl::new()?,
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            inner: TunImpl::new_named(if_name)?,
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.inner.name()
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.inner.set_state(state)
    }

    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Down)
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.inner.mtu()
    }

    /// Sets the blocking mode of the TUN device for reads/writes.
    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Retrieves the blocking mode of the TUN device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Sends a packet over the TUN device.
    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf)
    }

    #[cfg(target_os = "windows")]
    #[inline]
    pub fn read_handle(&mut self) -> HANDLE {
        self.inner.read_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let tun1 = Tun::new().unwrap();
        let tun2 = Tun::new().unwrap();
        let tun3 = Tun::new().unwrap();

        let tun1_name = tun1.name().unwrap();
        let tun2_name = tun2.name().unwrap();
        let tun3_name = tun3.name().unwrap();

        assert!(tun1_name != tun2_name);
        assert!(tun1_name != tun3_name);
        assert!(tun2_name != tun3_name);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"utun24\0".as_ptr() as *const i8) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tun = Tun::new_named(iface).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name_cstr());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn given_name() {
        use std::ffi::OsStr;

        let chosen_name = OsStr::new("tun24");

        let iface = Interface::new(chosen_name).unwrap();
        let tun = Tun::new_named(iface).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name());
    }

    #[test]
    fn up_down() {
        let mut tun1 = Tun::new().unwrap();

        tun1.set_up().unwrap();
        tun1.set_down().unwrap();
    }

    #[test]
    fn exists() {
        let tun1 = Tun::new().unwrap();
        let tun1_name = tun1.name().unwrap();
        assert!(tun1_name.exists().unwrap());
    }

    #[test]
    fn not_exists() {
        use std::ffi::OsStr;
        let chosen_name = OsStr::new("tun24");
        let iface = Interface::new(chosen_name).unwrap();
        assert!(!iface.exists().unwrap());
    }

    #[test]
    fn not_persistent() {
        let tun1 = Tun::new().unwrap();

        let tun1_name = tun1.name().unwrap();
        drop(tun1);
        assert!(!tun1_name.exists().unwrap());
    }

    #[test]
    fn nonblocking_switch() {
        let mut tun1 = Tun::new().unwrap();

        assert_eq!(tun1.nonblocking().unwrap(), false);
        tun1.set_nonblocking(true).unwrap();
        assert_eq!(tun1.nonblocking().unwrap(), true);
        tun1.set_nonblocking(false).unwrap();
        assert_eq!(tun1.nonblocking().unwrap(), false);
    }
}
