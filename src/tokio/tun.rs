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
#[cfg(target_os = "windows")]
use std::mem::ManuallyDrop;
#[cfg(not(target_os = "windows"))]
use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::os::windows::io::{FromRawSocket, RawSocket};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use crate::{AddAddress, AddressInfo};
use crate::{DeviceState, Interface, Tun};

#[cfg(not(target_os = "windows"))]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "windows")]
use tokio::io::Interest;
#[cfg(target_os = "windows")]
use tokio::net::UdpSocket;

/// A cross-platform asynchronous TUN interface, suitable for tunnelling network-layer packets.
pub struct AsyncTun {
    #[cfg(not(target_os = "windows"))]
    tun: AsyncFd<Tun>,
    #[cfg(target_os = "windows")]
    tun: Tun,
    #[cfg(target_os = "windows")]
    io: ManuallyDrop<UdpSocket>,
}

impl AsyncTun {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Self::new_impl()
    }

    #[cfg(target_os = "windows")]
    fn new_impl() -> io::Result<Self> {
        let mut tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        // SAFETY: `AsyncTun` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        let io = unsafe { UdpSocket::from_raw_socket(tun.read_handle() as RawSocket) };

        Ok(Self {
            tun,
            io: ManuallyDrop::new(io),
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn new_impl() -> io::Result<Self> {
        let mut tun = Tun::new()?;
        tun.set_nonblocking(true)?;

        Ok(Self {
            tun: AsyncFd::new(tun)?,
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
            tun: AsyncFd::new(tun)?,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tun = Tun::new_named(if_name)?;
        tun.set_nonblocking(true)?;

        // SAFETY: `AsyncTun` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        #[cfg(target_os = "windows")]
        let io = unsafe { UdpSocket::from_raw_socket(tun.read_handle() as RawSocket) };

        Ok(Self {
            tun,
            io: ManuallyDrop::new(io),
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
        self.tun.get_mut().set_state(state)
    }

    /// Sets the adapter state of the TUN device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.tun.get_mut().set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.tun.get_mut().set_state(DeviceState::Down)
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
        const SEND_MAX_BLOCKING_INTERVAL: u64 = 100;
        let mut timeout = 1; // Start with 1 millisecond timeout

        loop {
            match self.tun.send(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(timeout)).await;
                    timeout = cmp::min(timeout * 2, SEND_MAX_BLOCKING_INTERVAL);
                }
                res => return res,
            }
        }
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.tun.writable().await?;

            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.io.readable().await?;

            match guard.try_io(Interest::READABLE, |inner| self.tun.recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

impl Drop for AsyncTun {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            // This ensures that `UdpSocket` is dropped properly while not double-closing the RawFd.
            // SAFETY: `self.io` won't be accessed after this thanks to ManuallyDrop
            let io = unsafe { ManuallyDrop::take(&mut self.io) };
            io.into_raw_fd();
        }
    }
}
