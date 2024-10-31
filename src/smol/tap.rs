// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// smol::unblock
// async_std::task::spawn_blocking

use std::io;
#[cfg(not(target_os = "windows"))]
use std::net::IpAddr;

#[cfg(not(target_os = "windows"))]
use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tap};

#[cfg(not(target_os = "windows"))]
use async_io::Async;

#[cfg(target_os = "windows")]
struct TapWrapper(Tap);

#[cfg(target_os = "windows")]
impl TapWrapper {
    #[inline]
    pub fn get_ref(&self) -> &Tap {
        &self.0
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut Tap {
        &mut self.0
    }
}

/// A cross-platform asynchronous TAP interface, suitable for tunnelling link-layer packets.
pub struct AsyncTap {
    #[cfg(not(target_os = "windows"))]
    tap: Async<Tap>,
    #[cfg(target_os = "windows")]
    tap: TapWrapper,
}

impl AsyncTap {
    /// Creates a new, unique TAP device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[cfg(not(target_os = "windows"))]
    fn new_impl() -> io::Result<Self> {
        let mut tap = Tap::new()?;
        tap.set_nonblocking(true)?;

        Ok(Self {
            tap: Async::new(tap)?,
        })
    }

    #[cfg(target_os = "windows")]
    fn new_impl() -> io::Result<Self> {
        let mut tap = Tap::new()?;

        Ok(Self {
            tap: TapWrapper(tap),
        })
    }

    /// Opens or creates a TAP device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Self::new_named_impl(if_name)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tap = Tap::new_named(if_name)?;
        tap.set_nonblocking(true)?;

        Ok(Self {
            tap: Async::new(tap)?,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tap = Tap::new_named(if_name)?;

        Ok(Self {
            tap: TapWrapper(tap),
        })
    }

    /// Retrieves the interface name of the TAP device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tap.get_ref().name()
    }

    /// Sets the adapter state of the TAP device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        unsafe { self.tap.get_mut().set_state(state) }
    }

    /// Sets the adapter state of the TAP device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        unsafe { self.tap.get_mut().set_state(DeviceState::Up) }
    }

    /// Sets the adapter state of the TAP device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        unsafe { self.tap.get_mut().set_state(DeviceState::Down) }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TAP device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tap.get_ref().mtu()
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
        self.tap.get_ref().addrs()
    }

    // TODO: this used to be the case, but now it's not??
    //    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TAP
    //    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.

    /// Assigns a network-layer address to the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tap.get_ref().add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tap.get_ref().remove_addr(addr)
    }

    /// Sends a packet over the TAP device.
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        self.tap.write_with(|inner| inner.send(buf)).await
    }

    #[cfg(target_os = "windows")]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        async_std::task::spawn_blocking(|| self.tap.get_ref().send(buf)).await
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tap.read_with(|inner| inner.recv(buf)).await
    }

    #[cfg(target_os = "windows")]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        async_std::task::spawn_blocking(|| self.tap.get_ref().recv(buf)).await
    }
}
