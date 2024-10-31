// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_os = "windows")]
use std::borrow::ToOwned;
use std::io;
#[cfg(not(target_os = "windows"))]
use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::sync::Arc;

#[cfg(not(target_os = "windows"))]
use async_io::Async;

#[cfg(not(target_os = "windows"))]
use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tun};

#[cfg(target_os = "windows")]
#[derive(Clone)]
struct TunWrapper(Arc<Tun>);

#[cfg(target_os = "windows")]
impl TunWrapper {
    #[inline]
    pub fn get_ref(&self) -> &Tun {
        self.0.as_ref()
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut Tun {
        // SAFETY: we never use this within spawn_blocking or similar async contexts
        Arc::<Tun>::get_mut(&mut self.0).unwrap()
    }
}

/// A cross-platform asynchronous TUN interface, suitable for tunnelling network-layer packets.
pub struct AsyncTun {
    #[cfg(not(target_os = "windows"))]
    tun: Async<Tun>,
    #[cfg(target_os = "windows")]
    tun: TunWrapper,
}

impl AsyncTun {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[cfg(not(target_os = "windows"))]
    fn new_impl() -> io::Result<Self> {
        let mut tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: Async::new(tun)?,
        })
    }

    #[cfg(target_os = "windows")]
    fn new_impl() -> io::Result<Self> {
        let mut tun = Tun::new()?;

        Ok(Self {
            tun: TunWrapper(Arc::new(tun)),
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Self::new_named_impl(if_name)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tun = Tun::new_named(if_name)?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: Async::new(tun)?,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tun = Tun::new_named(if_name)?;

        Ok(Self {
            tun: TunWrapper(Arc::new(tun)),
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tun.get_ref().name()
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        unsafe { self.tun.get_mut().set_state(state) }
    }

    /// Sets the adapter state of the TUN device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        unsafe { self.tun.get_mut().set_state(DeviceState::Up) }
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        unsafe { self.tun.get_mut().set_state(DeviceState::Down) }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tun.get_ref().mtu()
    }

    /// Retrieves the network-layer addresses assigned to the interface.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to TUN devices on creation.
    /// Developers should take this into account and avoid the incorrect assumption that `addrs()`
    /// will return only the addresses they have assigned via [`add_addr()`](Self::add_addr).
    /// [`add_addr()`](Self::add_addr).
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.tun.get_ref().addrs()
    }

    // TODO: this used to be the case, but now it's not??
    //    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TUN
    //    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.

    /// Assigns a network-layer address to the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tun.get_ref().add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tun.get_ref().remove_addr(addr)
    }

    /// Sends a packet over the TUN device.
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.write_with(|inner| inner.send(buf)).await
    }

    #[cfg(target_os = "windows")]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        let arc = self.tun.clone();
        let buf = buf.to_owned();
        async_std::task::spawn_blocking(move || arc.get_ref().send(buf.as_slice())).await
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.read_with(|inner| inner.recv(buf)).await
    }

    #[cfg(target_os = "windows")]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Prepare to share ownership of `Tun` with a blocking thread
        let arc = self.tun.clone();
        let buflen = buf.len();

        // Run `recv()` in a blocking thread
        let (res, data) = async_std::task::spawn_blocking(move || {
            let mut buf = vec![0; buflen];
            let res = arc.get_ref().recv(buf.as_mut_slice());
            (res, buf)
        })
        .await;

        // Copy data output from the blocking thread to `buf`
        match res {
            Ok(len) => {
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            err => err,
        }
    }
}
