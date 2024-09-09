use std::io;

use crate::{DeviceState, Interface};

#[cfg(target_os = "linux")]
use crate::linux::TunImpl;
#[cfg(target_os = "macos")]
use crate::macos::TunImpl;
#[cfg(target_os = "windows")]
use crate::wintun::TunImpl;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::HANDLE;

/// A cross-platform TUN interface.
pub struct Tun {
    inner: TunImpl,
}

impl Tun {
    // tun_exists(if_name) -> checks to see if the given TUN device exists

    // *BSD and MacOS all strictly name interfaces, so we can infer type from iface name.
    // Linux doesn't strictly name interfaces, but there appears to be a netlink call based on
    // `strace ip -details link show` that returns interface type information.
    // We can just call open() for Wintun and then immediately close the tunnel.

    // new() -> creates a new TUN device with a unique device identifier

    // new_named(if_name) -> opens the given TUN device, or creates one if doesn't exist

    // Note: Wintun TOCTOU? Only if other interface not created with Wintun but not `tappers`
    //

    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            inner: TunImpl::new()?,
        })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            inner: TunImpl::new_named(if_name)?,
        })
    }

    /// Retrieves the interface name of the TUN device.
    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.inner.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.inner.set_state(state)
    }

    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Up)
    }

    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Down)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.inner.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }

    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf)
    }

    #[cfg(target_os = "windows")]
    #[inline]
    pub fn read_handle(&mut self) -> HANDLE {
        self.inner.read_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn unique_names() {
        let tun1 = Tun::new().unwrap();
        let tun2 = Tun::new().unwrap();
        let tun3 = Tun::new().unwrap();

        let tun1_name = tun1.name().unwrap();
        let tun2_name = tun2.name().unwrap();
        let tun3_name = tun3.name().unwrap();

        assert!(tun1_name != tun2_name);
        assert!(tun1_name != tun3_name);
        assert!(tun2_name != tun3_name);
    }

    #[test]
    #[serial]
    fn up_down() {
        let mut tun1 = Tun::new().unwrap();

        tun1.set_up().unwrap();
        tun1.set_down().unwrap();
    }

    #[test]
    #[serial]
    fn exists() {
        let tun1 = Tun::new().unwrap();
        let tun1_name = tun1.name().unwrap();
        assert!(tun1_name.exists().unwrap());
    }

    #[test]
    #[serial]
    fn not_persistent() {
        let tun1 = Tun::new().unwrap();

        let tun1_name = tun1.name().unwrap();
        drop(tun1);
        assert!(!tun1_name.exists().unwrap());
    }
}
