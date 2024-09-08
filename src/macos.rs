//! MacOS-specific TUN/TAP interfaces.
//!

mod feth;
mod utun;

use std::io;

pub use feth::FethTap;
pub use utun::Utun;

use crate::{DeviceState, Interface};

pub(crate) struct TunImpl {
    tun: Utun,
}

impl TunImpl {
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self { tun: Utun::new()? })
    }

    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tun: Utun::new_named(if_name)?,
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
    tap: FethTap,
}

impl TapImpl {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            tap: FethTap::new()?,
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tap: FethTap::new_named(Some(if_name), None)?,
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tap.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tap.set_state(state)
    }

    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.tap.set_state(DeviceState::Up)
    }

    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.tap.set_state(DeviceState::Down)
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
