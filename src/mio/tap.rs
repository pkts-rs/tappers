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
#[cfg(not(target_os = "windows"))]
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_os = "windows")]
use std::os::windows::io::{FromRawSocket, RawSocket};

#[cfg(not(target_os = "windows"))]
use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tap};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

/// A cross-platform asynchronous TAP interface, suitable for tunnelling link-layer packets.
pub struct AsyncTap {
    tap: Tap,
    io: ManuallyDrop<UdpSocket>,
}

impl AsyncTap {
    /// Creates a new, unique TAP device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        let mut tap = Tap::new()?;
        tap.set_nonblocking(true)?;

        // SAFETY: `AsyncTap` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        #[cfg(not(target_os = "windows"))]
        let io = unsafe { UdpSocket::from_raw_fd(tap.as_raw_fd()) };
        #[cfg(target_os = "windows")]
        let io = unsafe { UdpSocket::from_raw_socket(tap.read_handle() as RawSocket) };

        Ok(Self {
            tap,
            io: ManuallyDrop::new(io),
        })
    }

    /// Opens or creates a TAP device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let mut tap = Tap::new_named(if_name)?;
        tap.set_nonblocking(true)?;

        // SAFETY: `AsyncTap` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        #[cfg(not(target_os = "windows"))]
        let io = unsafe { UdpSocket::from_raw_fd(tap.as_raw_fd()) };
        #[cfg(target_os = "windows")]
        let io = unsafe { UdpSocket::from_raw_socket(tun.read_handle() as RawSocket) };

        Ok(Self {
            tap,
            io: ManuallyDrop::new(io),
        })
    }

    /// Retrieves the interface name of the TAP device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tap.name()
    }

    /// Sets the adapter state of the TAP device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tap.set_state(state)
    }

    /// Sets the adapter state of the TAP device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.tap.set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TAP device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.tap.set_state(DeviceState::Down)
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tap.mtu()
    }

    /// Retrieves the network-layer addresses assigned to the interface.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to TAP devices on creation.
    /// Developers should take this into account and avoid the incorrect assumption that `addrs()`
    /// will return only the addresses they have assigned via [`add_addr()`](Self::add_addr).
    /// [`add_addr()`](Self::add_addr).
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.tap.addrs()
    }

    // TODO: this used to be the case, but now it's not??
    //    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TAP
    //    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.

    /// Assigns a network-layer address to the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tap.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tap.remove_addr(addr)
    }

    /// Sends a packet over the TAP device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tap.send(buf)
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.recv(buf)
    }
}

impl Source for AsyncTap {
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

impl Drop for AsyncTap {
    fn drop(&mut self) {
        // This ensures that `UdpSocket` is dropped properly while not double-closing the RawFd.
        // SAFETY: `self.io` won't be accessed after this thanks to ManuallyDrop
        let io = unsafe { ManuallyDrop::take(&mut self.io) };
        io.into_raw_fd();
    }
}
