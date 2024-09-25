//! TUN/TAP interface for various Unix systems (*BSD variants, Solaris, IllumOS).
//!
//!
//!
//!

pub mod tap;
pub mod tun;

pub use tap::Tap;
pub use tun::Tun;

use std::io;
use std::ptr;

use crate::libc_extra::*;
use crate::{DeviceState, Interface};

#[inline]
pub(crate) fn ifreq_empty() -> ifreq {
    ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_data: ptr::null_mut(),
        },
    }
}

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
