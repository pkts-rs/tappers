// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{io, mem};

use crate::libc_extra::*;

#[derive(Clone, Copy, Debug)]
pub struct SysctlParseError {
    error: &'static str,
}

impl SysctlParseError {
    fn new(error: &'static str) -> Self {
        Self { error }
    }

    pub fn error(&self) -> &'static str {
        self.error
    }
}

impl From<SysctlParseError> for io::Error {
    #[inline]
    fn from(value: SysctlParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value.error())
    }
}

pub struct IfList<'a> {
    data: &'a [u8],
}

impl<'a> IfList<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for IfList<'a> {
    type Item = Result<SysctlMessage<'a>, SysctlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let Some(msg_type) = self.data.get(3) else {
            return Some(Err(SysctlParseError::new(
                "sysctl returned RT message header with truncated type/length fields",
            )));
        };

        let msg_len = u16::from_ne_bytes(self.data[..2].try_into().unwrap()) as usize;
        if msg_len > self.data.len() {
            return Some(Err(SysctlParseError::new(
                "sysctl returned RT message header with invalid length",
            )));
        }

        let (msg_data, rem) = self.data.split_at(msg_len);
        self.data = rem;
        match *msg_type as i32 {
            RTM_NEWADDR => {
                if msg_data.len() < mem::size_of::<ifa_msghdr>() {
                    return Some(Err(SysctlParseError::new(
                        "sysctl RTM_NEWADDR message had insufficient header bytes",
                    )));
                }

                let (hdr_slice, rem_data) = msg_data.split_at(mem::size_of::<ifa_msghdr>());
                let hdr_bytes: [u8; mem::size_of::<ifa_msghdr>()] = hdr_slice.try_into().unwrap();
                let msghdr: ifa_msghdr = unsafe { mem::transmute(hdr_bytes) };

                #[allow(unused_mut)]
                let mut addr_data = rem_data;

                #[cfg(target_os = "openbsd")]
                {
                    let padding_len = msghdr.ifam_hdrlen as usize - mem::size_of::<ifa_msghdr>();
                    let Some(rem_data) = addr_data.get(padding_len..) else {
                        return Some(Err(SysctlParseError::new("sysctl RTM_NEWADDR message had insufficient bytes for OpenBSD header padding")));
                    };
                    addr_data = rem_data;
                }

                Some(Ok(SysctlMessage::NewAddress(SysctlNewAddress {
                    header: msghdr,
                    addr_data,
                })))
            }
            ty => Some(Ok(SysctlMessage::Unknown(ty))),
        }
    }
}

#[non_exhaustive]
pub enum SysctlMessage<'a> {
    //    InterfaceInfo,
    NewAddress(SysctlNewAddress<'a>),
    //    Announce,
    Unknown(i32),
}

pub struct SysctlNewAddress<'a> {
    header: ifa_msghdr,
    addr_data: &'a [u8],
}

impl<'a> SysctlNewAddress<'a> {
    #[inline]
    pub fn index(&self) -> libc::c_ushort {
        self.header.ifam_index
    }

    #[inline]
    pub fn flags(&self) -> libc::c_int {
        self.header.ifam_flags
    }

    #[inline]
    pub fn metric(&self) -> libc::c_int {
        self.header.ifam_metric
    }

    #[inline]
    pub fn addrs(&self) -> SysctlAddrIter<'a> {
        SysctlAddrIter::new(self.addr_data, self.header.ifam_addrs)
    }
}

pub struct SysctlAddrIter<'a> {
    data: &'a [u8],
    flags: i32,
    flag_idx: usize,
}

impl<'a> SysctlAddrIter<'a> {
    fn new(data: &'a [u8], ifam_addrs: i32) -> Self {
        Self {
            data,
            flags: ifam_addrs,
            flag_idx: 0,
        }
    }
}

impl<'a> Iterator for SysctlAddrIter<'a> {
    type Item = Result<SysctlAddr, SysctlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.data.is_empty() {
                return None;
            }

            if self.flag_idx >= 8 * mem::size_of::<libc::c_int>() {
                return None;
            }

            let rtax = self.flag_idx;
            self.flag_idx += 1;
            if self.flags & (1 << rtax) == 0 {
                continue;
            }

            let Some(addr_family) = self.data.get(1) else {
                return Some(Err(SysctlParseError::new(
                    "sysctl RTM_NEWADDR had insufficient data for address family field",
                )));
            };

            let addrlen = self.data[0] as usize;
            let Some(addr_data) = self.data.get(..addrlen) else {
                return Some(Err(SysctlParseError::new(
                    "sysctl RTM_NEWADDR had insufficient data for sockaddr field",
                )));
            };
            #[cfg(not(target_os = "macos"))]
            {
                self.data = self.data.get(RT_ROUNDUP(addrlen)..).unwrap_or(&[]);
            }
            #[cfg(target_os = "macos")]
            {
                self.data = self.data.get(addrlen..).unwrap_or(&[]);
            }

            let addr = match *addr_family as i32 {
                libc::AF_INET if addrlen >= 8 => {
                    let addr_bytes: [u8; 4] = addr_data[4..8].try_into().unwrap();
                    IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(addr_bytes)))
                }
                libc::AF_INET6 if addrlen >= mem::size_of::<libc::sockaddr_in6>() => {
                    let addr_bytes: [u8; mem::size_of::<libc::sockaddr_in6>()] = addr_data
                        [..mem::size_of::<libc::sockaddr_in6>()]
                        .try_into()
                        .unwrap();
                    let addr: libc::sockaddr_in6 = unsafe { mem::transmute(addr_bytes) };
                    IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(addr.sin6_addr.s6_addr)))
                }
                libc::AF_UNSPEC if addrlen == mem::size_of::<libc::sockaddr_in6>() => {
                    let addr_bytes: [u8; mem::size_of::<libc::sockaddr_in6>()] =
                        addr_data.try_into().unwrap();
                    let addr: libc::sockaddr_in6 = unsafe { mem::transmute(addr_bytes) };
                    IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(addr.sin6_addr.s6_addr)))
                }
                libc::AF_INET | libc::AF_INET6 => {
                    return Some(Err(SysctlParseError::new(
                        "sysctl RTM_NEWADDR has addrlen mismatch",
                    )))
                }
                _ => continue,
            };

            return Some(Ok(match rtax as i32 {
                RTAX_DST => SysctlAddr::Destination(addr),
                RTAX_GATEWAY => SysctlAddr::Gateway(addr),
                RTAX_NETMASK => SysctlAddr::Netmask(addr),
                RTAX_IFA => SysctlAddr::Address(addr),
                RTAX_BRD => SysctlAddr::Broadcast(addr),
                _ => SysctlAddr::Other,
            }));
        }
    }
}

//     #define RTA_DST       0x1    /* destination sockaddr present */
//     #define RTA_GATEWAY   0x2    /* gateway sockaddr present */
//     #define RTA_NETMASK   0x4    /* netmask sockaddr present */
//     #define RTA_GENMASK   0x8    /* cloning mask sockaddr present */
//     #define RTA_IFP       0x10   /* interface name sockaddr present */
//     #define RTA_IFA       0x20   /* interface addr sockaddr present */
//     #define RTA_AUTHOR    0x40   /* sockaddr for author of redirect */
//     #define RTA_BRD       0x80   /* for NEWADDR, broadcast or p-p dest addr */
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SysctlAddr {
    /// RTA_DST - destination sockaddr
    Destination(IpAddr),
    /// RTA_GATEWAY - gateway sockaddr
    Gateway(IpAddr),
    /// RTA_NETMASK - netmask sockaddr
    Netmask(IpAddr),
    /// RTA_IFA - interface address sockaddr
    Address(IpAddr),
    /// RTA_BRD - for NEWADDR, broadcast or p-p dest addr
    Broadcast(IpAddr),
    /// Some other RTA_* value
    Other,
}

#[cfg(target_os = "macos")]
mod tests_macos {
    use super::*;

    #[test]
    fn single_ipv6_macos() {
        let sysctl_out = [
            132u8, 0, 5, 14, 16, 0, 0, 0, 81, 128, 0, 0, 19, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 220,
            5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 202, 77, 6, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 20, 18, 19, 0, 1, 5, 0, 0, 117, 116, 117, 110, 52, 0, 0, 0, 0, 0, 0, 0, 80, 0, 5,
            12, 164, 0, 0, 0, 0, 1, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 28, 30, 0, 0, 0, 0, 0, 0, 255,
            255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 30, 0, 0, 0,
            0, 0, 0, 254, 128, 0, 19, 0, 0, 0, 0, 104, 189, 249, 21, 195, 19, 170, 108, 0, 0, 0, 0,
            0, 0, 0, 0, 80, 0, 5, 12, 164, 0, 0, 0, 0, 1, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 28, 30, 0,
            0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 28, 30, 0, 0, 0, 0, 0, 0, 0, 50, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];

        let expected = [
            SysctlAddr::Netmask(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            SysctlAddr::Address(IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0x0013, 0, 0, 0x68bd, 0xf915, 0xc313, 0xaa6c,
            ))),
            SysctlAddr::Netmask(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            SysctlAddr::Address(IpAddr::V6(Ipv6Addr::new(50, 2, 3, 4, 5, 6, 7, 8))),
        ];
        let mut idx = 0;

        let if_list = IfList::new(sysctl_out.as_slice());
        for msg in if_list {
            match msg.unwrap() {
                SysctlMessage::NewAddress(new_addr) => {
                    for addr in new_addr.addrs() {
                        assert_eq!(addr.unwrap(), expected[idx]);
                        idx += 1;
                    }
                }
                SysctlMessage::Unknown(_) => (),
            }
        }

        assert_eq!(idx, 4);
    }
}
