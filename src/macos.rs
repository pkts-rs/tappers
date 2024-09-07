

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
        Ok(Self {
            tun: Utun::new()?,
        })
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

}
