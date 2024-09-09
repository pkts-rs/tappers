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

/*
#[allow(unused)]
const TUNSETNOCSUM: u64 = 0x400454C8; // Obsolete
const TUNSETDEBUG: u64 = 0x400454C9;
const TUNSETIFF: u64 = 0x400454CA;
const TUNSETPERSIST: u64 = 0x400454CB;
const TUNSETOWNER: u64 = 0x400454CC;
const TUNSETLINK: u64 = 0x400454CD;
const TUNSETGROUP: u64 = 0x400454CE;
#[allow(unused)]
const TUNGETFEATURES: u64 = 0x800454CF;
#[allow(unused)]
const TUNSETOFFLOAD: u64 = 0x400454D0;
#[allow(unused)]
const TUNSETTXFILTER: u64 = 0x400454D1;
const TUNGETIFF: u64 = 0x800454D2;
#[allow(unused)]
const TUNGETSNDBUF: u64 = 0x800454D3;
#[allow(unused)]
const TUNSETSNDBUF: u64 = 0x400454D4;
#[allow(unused)]
const TUNATTACHFILTER: u64 = 0x401054D5;
#[allow(unused)]
const TUNDETACHFILTER: u64 = 0x401054D6;
#[allow(unused)]
const TUNGETVNETHDRSZ: u64 = 0x800454D7;
#[allow(unused)]
const TUNSETVNETHDRSZ: u64 = 0x400454D8;
#[allow(unused)]
const TUNSETQUEUE: u64 = 0x400454D9;
#[allow(unused)]
const TUNSETIFINDEX: u64 = 0x400454DA;
#[allow(unused)]
const TUNGETFILTER: u64 = 0x800454DB;
#[allow(unused)]
const TUNSETVNETLE: u64 = 0x400454DC;
#[allow(unused)]
const TUNGETVNETLE: u64 = 0x800454DD;
#[allow(unused)]
const TUNSETVNETBE: u64 = 0x400454DE;
#[allow(unused)]
const TUNGETVNETBE: u64 = 0x800454DF;
#[allow(unused)]
const TUNSETSTEERINGBPF: u64 = 0x400454E0;
#[allow(unused)]
const TUNSETFILTERBPF: u64 = 0x400454E1;
#[allow(unused)]
const TUNSETCARRIER: u64 = 0x400454E2;
#[allow(unused)]
const TUNGETDEVNETNS: u64 = 0x800454E3;

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(unused)]
struct tun_pi {
    flags: u16,
    proto: u16,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(unused)]
struct tun_filter {
    flags: u16,
    count: u16,
    addr: *mut [u8; libc::ETH_ALEN as usize],
}

/*
bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Offloads: u32 {
        /// Offload transport-layer checksum validation.
        const L4_CHKSUM       = libc::TUN_F_CSUM;
        /// Offload segmenetation of IPv4/TCP packets.
        const TCPV4_SEGMENT   = libc::TUN_F_TSO4;
        /// Offload segmenetation of IPv6/TCP packets.
        const TCPV6_SEGMENT   = libc::TUN_F_TSO6;
        /// Offload segmenetation of TCP packets with ECN bits.
        const TCP_ECN_SEGMENT = libc::TUN_F_TSO_ECN;
        /// Offload segmenetation of UDP/IPv4 packets.
        const UDPV4_SEGMENT   = libc::TUN_F_USO4;
        /// Offload segmenetation of UDP/IPv6 packets.
        const UDPV6_SEGMENT   = libc::TUN_F_USO6;
    }
}
*/

// TODO: include Generic Receive Offset variant of Tun/Tap
//
// Related reading:
// https://tailscale.com/blog/throughput-improvements
// https://blog.cloudflare.com/virtual-networking-101-understanding-tap/
*/

// To delete a device, Netlink RTM_DELLINK is needed
// for *BSD, look into `brctl delif`
// for MacOS, `sudo ifconfig [bridge-name] down`
// `sudo ifconfig [bridge-name] destroy`

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
