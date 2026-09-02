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
use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tun};

#[cfg(not(target_os = "windows"))]
use tokio::io::unix::AsyncFd;

/// A convenience type used to make internal operations consistent between Windows and Unix.
#[cfg(target_os = "windows")]
#[derive(Clone)]
struct TunWrapper(Arc<Tun>);

#[cfg(target_os = "windows")]
impl TunWrapper {
    /// Returns a reference to the underlying `Tun` function.
    pub fn get_ref(&self) -> &Tun {
        &self.0
    }
}

/// A cross-platform asynchronous TUN interface, suitable for tunnelling network-layer packets.
pub struct AsyncTun {
    #[cfg(not(target_os = "windows"))]
    tun: AsyncFd<Tun>,
    #[cfg(target_os = "windows")]
    tun: TunWrapper,
}

impl AsyncTun {
    /// Opens an existing TUN device of the given device number.
    #[cfg(any(
        target_os = "windows",
        all(feature = "portable-racy", not(target_os = "macos"))
    ))]
    #[inline]
    pub fn open(device_num: u32) -> io::Result<Self> {
        Self::open_impl(device_num)
    }

    #[cfg(target_os = "windows")]
    pub fn open_impl(device_num: u32) -> io::Result<Self> {
        let tun = Tun::open(device_num)?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: TunWrapper(Arc::new(tun)),
        })
    }

    #[cfg(all(
        feature = "portable-racy",
        not(any(target_os = "macos", target_os = "windows"))
    ))]
    pub fn open_impl(device_num: u32) -> io::Result<Self> {
        let tun = Tun::open(device_num)?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: AsyncFd::new(tun)?,
        })
    }

    /// Creates a new, unique TUN device.
    #[cfg(any(
        feature = "portable-racy",
        not(any(target_os = "openbsd", target_os = "windows"))
    ))]
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[cfg(all(target_os = "windows", feature = "portable-racy"))]
    #[inline]
    pub fn new_impl() -> io::Result<Self> {
        let tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: TunWrapper(Arc::new(tun)),
        })
    }

    #[cfg(all(
        not(target_os = "windows"),
        any(feature = "portable-racy", not(target_os = "openbsd"))
    ))]
    #[inline]
    pub fn new_impl() -> io::Result<Self> {
        let tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: AsyncFd::new(tun)?,
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_numbered(device_num: u32) -> io::Result<Self> {
        Self::new_numbered_impl(device_num)
    }

    #[cfg(target_os = "windows")]
    #[inline]
    pub fn new_numbered_impl(device_num: u32) -> io::Result<Self> {
        let tun = Tun::new_numbered(device_num)?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: TunWrapper(Arc::new(tun)),
        })
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn new_numbered_impl(device_num: u32) -> io::Result<Self> {
        let tun = Tun::new_numbered(device_num)?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: AsyncFd::new(tun)?,
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tun.get_ref().name()
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        self.tun.get_ref().set_state(state)
    }

    /// Sets the adapter state of the TUN device to "up".
    #[inline]
    pub fn set_up(&self) -> io::Result<()> {
        self.tun.get_ref().set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&self) -> io::Result<()> {
        self.tun.get_ref().set_state(DeviceState::Down)
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
        loop {
            let mut guard = self.tun.readable().await?;

            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        let arc = self.tun.clone();
        let buf = buf.to_owned();
        tokio::task::spawn_blocking(move || arc.get_ref().send(buf.as_slice())).await?
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.tun.readable().await?;

            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Prepare to share ownership of `Tun` with a blocking thread
        let arc = self.tun.clone();
        let buflen = buf.len();

        // Run `recv()` in a blocking thread
        let (res, data) = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0; buflen];
            let res = arc.get_ref().recv(buf.as_mut_slice());
            (res, buf)
        })
        .await?;

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
