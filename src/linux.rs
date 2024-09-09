// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Linux-specific TUN/TAP interfaces.

// Values that have yet to be included in libc:

mod tap;
mod tun;

pub use tap::Tap;
pub use tun::Tun;

use std::io;

use crate::{DeviceState, Interface};

pub(crate) const DEV_NET_TUN: *const i8 = b"/dev/net/tun\0".as_ptr() as *const i8;

// TODO: include Generic Receive Offset variant of Tun/Tap
//
// Related reading:
// https://tailscale.com/blog/throughput-improvements
// https://blog.cloudflare.com/virtual-networking-101-understanding-tap/

// To delete a device, Netlink RTM_DELLINK is needed
// for *BSD, look into `brctl delif`

pub(crate) struct TunImpl {
    tun: Tun,
}

impl TunImpl {
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self { tun: Tun::new()? })
    }

    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tun: Tun::new_named(if_name)?,
        })
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tun.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tun.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tun.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.tun.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.tun.nonblocking()
    }

    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf)
    }

    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }
}

pub(crate) struct TapImpl {
    tap: Tap,
}

impl TapImpl {
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self { tap: Tap::new()? })
    }

    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tap: Tap::new_named(if_name)?,
        })
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tap.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tap.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tap.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.tap.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.tap.nonblocking()
    }

    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tap.send(buf)
    }

    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tap.recv(buf)
    }
}
