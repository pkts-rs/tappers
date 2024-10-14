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
use std::net::IpAddr;

#[cfg(not(target_os = "windows"))]
use crate::AddAddress;
use crate::{DeviceState, Interface};

#[cfg(target_os = "linux")]
use crate::linux::TunImpl;
#[cfg(target_os = "macos")]
use crate::macos::TunImpl;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris"
))]
use crate::unix::TunImpl;
#[cfg(target_os = "windows")]
use crate::wintun::TunImpl;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(not(target_os = "windows"))]
use crate::AddressInfo;

/// A cross-platform TUN interface, suitable for tunnelling network-layer packets.
pub struct Tun {
    inner: TunImpl,
}

// *BSD and MacOS all strictly name interfaces, so we can infer type from iface name.
// Linux doesn't strictly name interfaces, but there appears to be a netlink call based on
// `strace ip -details link show` that returns interface type information.
// We can just call open() for Wintun and then immediately close the tunnel.

// Note: Wintun TOCTOU? Only if other interface not created with Wintun but not `tappers`

impl Tun {
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

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.inner.set_state(state)
    }

    /// Sets the adapter state of the TUN device to "up".
    #[inline]
    pub fn set_up(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Up)
    }

    /// Sets the adapter state of the TUN device to "down".
    #[inline]
    pub fn set_down(&mut self) -> io::Result<()> {
        self.inner.set_state(DeviceState::Down)
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.inner.mtu()
    }

    /// Sets the blocking mode of the TUN device for reads/writes.
    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Retrieves the blocking mode of the TUN device.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Retrieves the IP addresses assigned to the interface.
    ///
    /// # Portability
    ///
    /// In nearly all platforms, no addresses are automatically assigned to TUN interfaces. The
    /// exception to this is OpenBSD, which automatically assigns a link-layer IPv6 address (in
    /// addition to the specified IPv6 address) the first time an IPv6 address is assigned to a
    /// TUN device. As such, portable applications **should not** rely on the assumption that the
    /// only addresses returned from this method are those that were previously assigned via
    /// [`add_addr()`](Self::add_addr).
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.inner.addrs()
    }

    // TODO: this used to be the case, but now it's not??
    //    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TUN
    //    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.

    /// Assigns an IP address to the interface.
    ///
    /// # Portability
    ///
    /// MacOS, FreeBSD and DragonFlyBSD all require a destination address when assigning an IPv4
    /// address to a TUN device. The destination address is optional for other platforms.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to a newly created TAP device.
    /// No platforms assign link-local IPv6 addresses to TUN devices on creation. However, OpenBSD
    /// **will** assign a link-local IPv6 address (in addition to the specified IPv6 address) the
    /// first time an IPv6 address is assigned to a TUN device.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.inner.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.inner.remove_addr(addr)
    }

    /// Sends a packet over the TUN device.
    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }

    /// Receives a packet over the TUN device.
    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf)
    }

    /// The HANDLE
    #[cfg(target_os = "windows")]
    #[inline]
    pub fn read_handle(&mut self) -> HANDLE {
        self.inner.read_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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

    #[cfg(target_os = "macos")]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"utun24\0".as_ptr() as *const i8) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tun = Tun::new_named(iface).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name_cstr());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn given_name() {
        use std::ffi::OsStr;

        let chosen_name = OsStr::new("tun24");

        let iface = Interface::new(chosen_name).unwrap();
        let tun = Tun::new_named(iface).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name());
    }

    #[test]
    fn up_down() {
        let mut tun1 = Tun::new().unwrap();

        tun1.set_up().unwrap();
        tun1.set_down().unwrap();
    }

    #[test]
    fn exists() {
        let tun1 = Tun::new().unwrap();
        let tun1_name = tun1.name().unwrap();
        assert!(tun1_name.exists().unwrap());
    }

    #[test]
    fn not_exists() {
        use std::ffi::OsStr;
        let chosen_name = OsStr::new("tun24");
        let iface = Interface::new(chosen_name).unwrap();
        assert!(!iface.exists().unwrap());
    }

    #[test]
    fn not_persistent() {
        let tun1 = Tun::new().unwrap();

        let tun1_name = tun1.name().unwrap();
        drop(tun1);
        assert!(!tun1_name.exists().unwrap());
    }

    #[test]
    fn nonblocking_switch() {
        let mut tun1 = Tun::new().unwrap();

        assert_eq!(tun1.nonblocking().unwrap(), false);
        tun1.set_nonblocking(true).unwrap();
        assert_eq!(tun1.nonblocking().unwrap(), true);
        tun1.set_nonblocking(false).unwrap();
        assert_eq!(tun1.nonblocking().unwrap(), false);
    }
}

#[cfg(not(target_os = "windows"))]
#[cfg(test)]
mod tests_unix {
    use crate::AddAddressV4;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn add_ipv4() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ip1);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));
        tun1.add_addr(ip1_req).unwrap();
        assert!(tun1.addrs().unwrap().iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn add_ipv4_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ip1);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));
        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let mut ip2_req = AddAddressV4::new(ip2);
        ip2_req.set_destination(Ipv4Addr::new(10, 102, 0, 2));
        tun1.add_addr(ip1_req).unwrap();
        tun1.add_addr(ip2_req).unwrap();

        let addrs = tun1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn add_ipv6() {
        let tun1 = Tun::new().unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(
            0x0032, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
        ));
        tun1.add_addr(ip1).unwrap();

        let addrs = tun1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn add_ipv6_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip2 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tun1.add_addr(ip1).unwrap();
        tun1.add_addr(ip2).unwrap();

        let addrs = tun1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn add_ipv4_ipv6_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ip1);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));

        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let mut ip2_req = AddAddressV4::new(ip2);
        ip2_req.set_destination(Ipv4Addr::new(10, 102, 0, 2));

        let ip3 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip4 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);

        tun1.add_addr(ip1_req).unwrap();
        tun1.add_addr(ip2_req).unwrap();
        tun1.add_addr(ip3).unwrap();
        tun1.add_addr(ip4).unwrap();
        let addrs = tun1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
        assert!(addrs.iter().any(|a| a.address() == ip3));
        assert!(addrs.iter().any(|a| a.address() == ip4));
    }

    #[test]
    fn remove_ipv4() {
        let tun1 = Tun::new().unwrap();
        let ipv4 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ipv4);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));
        tun1.add_addr(ip1_req).unwrap();
        tun1.remove_addr(IpAddr::V4(ipv4)).unwrap();
        let addrs = tun1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ipv4));
    }

    #[test]
    fn remove_ipv4_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ip1);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));
        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let mut ip2_req = AddAddressV4::new(ip2);
        ip2_req.set_destination(Ipv4Addr::new(10, 102, 0, 2));
        tun1.add_addr(ip1_req).unwrap();
        tun1.add_addr(ip2_req).unwrap();
        tun1.remove_addr(IpAddr::V4(ip1)).unwrap();
        tun1.remove_addr(IpAddr::V4(ip2)).unwrap();
        let addrs = tun1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn remove_ipv6() {
        let tun1 = Tun::new().unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(
            0x0032, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
        ));
        tun1.add_addr(ip1).unwrap();
        tun1.remove_addr(ip1).unwrap();
        let addrs = tun1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn remove_ipv6_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip2 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tun1.add_addr(ip1).unwrap();
        tun1.add_addr(ip2).unwrap();
        tun1.remove_addr(IpAddr::V6(ip1)).unwrap();
        tun1.remove_addr(IpAddr::V6(ip2)).unwrap();
        let addrs = tun1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn remove_ipv4_ipv6_multi() {
        let tun1 = Tun::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let mut ip1_req = AddAddressV4::new(ip1);
        ip1_req.set_destination(Ipv4Addr::new(10, 101, 0, 2));

        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let mut ip2_req = AddAddressV4::new(ip2);
        ip2_req.set_destination(Ipv4Addr::new(10, 102, 0, 2));

        let ip3 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);

        let ip4 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);

        tun1.add_addr(ip1_req).unwrap();
        tun1.add_addr(ip2_req).unwrap();
        tun1.add_addr(ip3).unwrap();
        tun1.add_addr(ip4).unwrap();

        tun1.remove_addr(IpAddr::V6(ip3)).unwrap();
        tun1.remove_addr(IpAddr::V4(ip1)).unwrap();
        tun1.remove_addr(IpAddr::V6(ip4)).unwrap();
        tun1.remove_addr(IpAddr::V4(ip2)).unwrap();

        let addrs = tun1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
        assert!(!addrs.iter().any(|a| a.address() == ip3));
        assert!(!addrs.iter().any(|a| a.address() == ip4));
    }

    /*
    #[test]
    fn send_ipv4() {
        let mut tun1 = Tun::new().unwrap();
        let tun_ip = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
        let udp_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        tun1.add_addr(tun_ip).unwrap();
        tun1.set_up().unwrap();

        let udp = UdpSocket::bind((udp_ip, 5354)).unwrap();

        // IPv4 packet
        let send_pkt: [u8; 76] = [
            0x45, 0x00, 0x00, 0x4c, 0xd5, 0x06, 0x00, 0x00,
            0x40, 0x11, 0x1c, 0x35, 0x0a, 0x64, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01, 0xd5, 0x88, 0x35, 0x36,
            0x00, 0x38, 0x84, 0x62, 0x39, 0x86, 0x01, 0x20,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x31, 0x01, 0x31, 0x01, 0x31, 0x01, 0x31,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
            0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
            0x00, 0x0a, 0x00, 0x08, 0xb4, 0xb1, 0xb9, 0xaf,
            0xa7, 0xfa, 0x8a, 0x17,
        ];
        assert_eq!(tun1.send(&send_pkt).unwrap(), 76);

        let mut pkt = [0u8; 48];
        let (recv_len, addr) = udp.recv_from(&mut pkt).unwrap();
        assert_eq!(recv_len, 48);
        assert_eq!(&send_pkt[76 - 48..], pkt.as_slice());
    }

    #[test]
    fn recv_ipv4() {
        let mut tun1 = Tun::new().unwrap();
        let tun_ip = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
        let udp_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        tun1.add_addr(tun_ip).unwrap();
        tun1.set_up().unwrap();

        let udp = UdpSocket::bind((udp_ip, 5454)).unwrap();

        let dns_req: [u8; 48] = [
            0x39, 0x86, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x01, 0x31, 0x01, 0x31,
            0x01, 0x31, 0x01, 0x31, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
            0xb4, 0xb1, 0xb9, 0xaf, 0xa7, 0xfa, 0x8a, 0x17,
        ];

        let req: [u8; 2] = [0x00, 0x46];
        let mut buf = [0u8; 100];

        tun1.set_nonblocking(true).unwrap();
        while let Ok(_) = tun1.recv(&mut buf) {} // Clear TUN of traffic
        tun1.set_nonblocking(false).unwrap();

        assert_eq!(udp.send_to(&req, (tun_ip, 5354)).unwrap(), 2);

        let mut recv_len = 0;
        loop {
            recv_len = tun1.recv(&mut buf).unwrap();
            if buf[0] >> 4 == 0x06 {
                continue
            }
            break
        }
        assert_eq!(recv_len, 30);
        assert_eq!(&buf[28..30], &dns_req);
    }
    */
}
