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
use std::cmp;
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
use crate::{DeviceState, Interface, Tap};

#[cfg(not(target_os = "windows"))]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "windows")]
use tokio::io::Interest;
#[cfg(target_os = "windows")]
use tokio::net::UdpSocket;

/// A convenience type used to make internal operations consistent between Windows and Unix.
#[cfg(target_os = "windows")]
struct TapWrapper(Tap);

#[cfg(target_os = "windows")]
impl TapWrapper {
    /// Returns a reference to the underlying `Tap` function.
    pub fn get_ref(&self) -> &Tap {
        &self.0
    }

    /// Returns a reference to the underlying `Tap` function.
    pub fn get_mut(&mut self) -> &mut Tap {
        &mut self.0
    }
}

/// A cross-platform asynchronous TAP interface, suitable for tunnelling link-layer packets.
pub struct AsyncTap {
    #[cfg(not(target_os = "windows"))]
    tap: AsyncFd<Tap>,
    #[cfg(target_os = "windows")]
    tap: TapWrapper,
    /// SAFETY: file descriptor/handle is closed when `tap` goes out of scope, so this doesn't need to.
    #[cfg(target_os = "windows")]
    io: ManuallyDrop<UdpSocket>,
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
            tap: AsyncFd::new(tap)?,
        })
    }

    #[cfg(target_os = "windows")]
    fn new_impl() -> io::Result<Self> {
        let mut tap = Tap::new()?;
        tap.set_nonblocking(true)?;

        // SAFETY: `AsyncTap` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        let io = unsafe {
            UdpSocket::from_std(std::net::UdpSocket::from_raw_socket(
                tap.read_handle() as RawSocket
            ))?
        };

        Ok(Self {
            tap: TapWrapper(tap),
            io: ManuallyDrop::new(io),
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
            tap: AsyncFd::new(tap)?,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_named_impl(if_name: Interface) -> io::Result<Self> {
        let mut tap = Tap::new_named(if_name)?;
        tap.set_nonblocking(true)?;

        // SAFETY: `AsyncTap` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        #[cfg(target_os = "windows")]
        let io = unsafe {
            UdpSocket::from_std(std::net::UdpSocket::from_raw_socket(
                tap.read_handle() as RawSocket
            ))?
        };

        Ok(Self {
            tap: TapWrapper(tap),
            io: ManuallyDrop::new(io),
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
        self.tap.get_mut().set_state(state)
    }

    /// Sets the adapter state of the TAP device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.tap.get_mut().set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TAP device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.tap.get_mut().set_state(DeviceState::Down)
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
        loop {
            let mut guard = self.tap.readable().await?;

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
            match self.tap.get_ref().send(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(timeout)).await;
                    timeout = cmp::min(timeout * 2, SEND_MAX_BLOCKING_INTERVAL);
                }
                res => return res,
            }
        }
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.tap.writable().await?;

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

            match guard.try_io(Interest::READABLE, || self.tap.get_ref().recv(buf)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                res => return res,
            }
        }
    }
}
