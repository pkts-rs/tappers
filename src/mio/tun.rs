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
use std::mem::ManuallyDrop;
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tun};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

/// A cross-platform asynchronous TUN interface, suitable for tunnelling network-layer packets.
pub struct AsyncTun {
    tun: Tun,
    io: ManuallyDrop<UdpSocket>,
}

impl AsyncTun {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        let mut tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        // SAFETY: `AsyncTun` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        let io = unsafe { UdpSocket::from_raw_fd(tun.as_raw_fd()) };

        Ok(Self {
            tun,
            io: ManuallyDrop::new(io),
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let mut tun = Tun::new_named(if_name)?;
        tun.set_nonblocking(true)?;

        // SAFETY: `AsyncTun` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        let io = unsafe { UdpSocket::from_raw_fd(tun.as_raw_fd()) };

        Ok(Self {
            tun,
            io: ManuallyDrop::new(io),
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tun.name()
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tun.set_state(state)
    }

    /// Sets the adapter state of the TUN device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.tun.set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.tun.set_state(DeviceState::Down)
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tun.mtu()
    }

    /// Retrieves the IP addresses assigned to the interface.
    ///
    /// # Portability
    ///
    /// In nearly all platforms, no addresses are automatically assigned to TUN interfaces. The
    /// exception to this is OpenBSD, which automatically assigns a link-layer IPv6 address (in
    /// addition to the specified IPv6 address) the first time an IPv6 address is assigned to a
    /// TUN device. As such, portable applications **should not** rely on the assumption that the
    /// only addresses returned from this method are those that were previously assigned via
    /// [`add_addr()`](Self::add_addr).
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.tun.addrs()
    }

    // TODO: this used to be the case, but now it's not??
    //    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TUN
    //    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.

    /// Assigns an IP address to the interface.
    ///
    /// # Portability
    ///
    /// MacOS, FreeBSD and DragonFlyBSD all require a destination address when assigning an IPv4
    /// address to a TUN device. The destination address is optional for other platforms.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to a newly created TAP device.
    /// No platforms assign link-local IPv6 addresses to TUN devices on creation. However, OpenBSD
    /// **will** assign a link-local IPv6 address (in addition to the specified IPv6 address) the
    /// first time an IPv6 address is assigned to a TUN device.
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tun.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tun.remove_addr(addr)
    }

    /// Sends a packet over the TUN device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf)
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.recv(buf)
    }
}

impl Source for AsyncTun {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.io.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.io.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.io.deregister(registry)
    }
}

impl Drop for AsyncTun {
    fn drop(&mut self) {
        // This ensures that `UdpSocket` is dropped properly while not double-closing the RawFd.
        // SAFETY: `self.io` won't be accessed after this thanks to ManuallyDrop
        let io = unsafe { ManuallyDrop::take(&mut self.io) };
        let _ = io.into_raw_fd();
    }
}
