// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused)]

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::{io, iter, mem, ptr};

use crate::{libc_extra::*, MacAddr};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum AddressFamily {
    V4 = 0x02,
    V6 = 0x0A,
}

pub struct RtNetlink {
    fd: RawFd,
    seq: u32,
}

impl RtNetlink {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, seq: 1 })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NlParseError {
    error: &'static str,
}

impl NlParseError {
    fn new(error: &'static str) -> Self {
        Self { error }
    }

    pub fn error(&self) -> &'static str {
        self.error
    }
}

impl From<NlParseError> for io::Error {
    #[inline]
    fn from(value: NlParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value.error())
    }
}

// =============================================================================
//                          Netlink Request Messages
// =============================================================================

#[derive(Clone, Debug)]
pub struct NetlinkRequest {
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub payload: NlmsgPayload,
}

impl NetlinkRequest {
    pub fn serialize(&self) -> Vec<u8> {
        const HDR_LEN: usize = mem::size_of::<libc::nlmsghdr>();

        // First, reserve space for the Netlink header...
        let mut v = vec![0; NLMSG_ALIGN(HDR_LEN)];

        // ...then write payload bytes...
        self.payload.serialize(&mut v);

        // ...finally, measure the total message length and write the header.
        let header = libc::nlmsghdr {
            nlmsg_len: v.len() as u32,
            nlmsg_type: match &self.payload {
                NlmsgPayload::NewAddress(_) => libc::RTM_NEWADDR,
                NlmsgPayload::GetAddress(_) => libc::RTM_GETADDR,
                NlmsgPayload::DeleteAddress(_) => libc::RTM_DELADDR,
                NlmsgPayload::NewRoute(_) => libc::RTM_NEWROUTE,
                NlmsgPayload::DeleteRoute(_) => libc::RTM_DELROUTE,
                NlmsgPayload::NewNeighbor(_) => libc::RTM_NEWNEIGH,
                NlmsgPayload::DeleteNeighbor(_) => libc::RTM_DELNEIGH,
            },
            nlmsg_flags: self.flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: self.pid,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                ptr::addr_of!(header) as *const u8,
                v.as_mut_ptr(),
                mem::size_of_val(&header),
            );
        }

        v
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NlmsgPayload {
    /// An `RTM_NEWADDR` request.
    NewAddress(NlmsgNewAddress),
    /// An `RTM_GETADDR` request.
    GetAddress(NlmsgGetAddress),
    /// An `RTM_DELADDR` request.
    DeleteAddress(NlmsgDeleteAddress),
    /// An `RTM_NEWROUTE` request.
    NewRoute(NlmsgNewRoute),
    /// An `RTM_DELROUTE` request.
    DeleteRoute(NlmsgDeleteRoute),
    /// An `RTM_NEWNEIGH` request.
    NewNeighbor(NlmsgNewNeighbor),
    /// An `RTM_DELNEIGH` request.
    DeleteNeighbor(NlmsgDeleteNeighbor),
}

impl NlmsgPayload {
    #[inline]
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            NlmsgPayload::NewAddress(nlmsg_new_address) => nlmsg_new_address.serialize(buf),
            NlmsgPayload::GetAddress(nlmsg_get_address) => nlmsg_get_address.serialize(buf),
            NlmsgPayload::DeleteAddress(nlmsg_delete_address) => {
                nlmsg_delete_address.serialize(buf)
            }
            NlmsgPayload::NewRoute(nlmsg_new_route) => nlmsg_new_route.serialize(buf),
            NlmsgPayload::DeleteRoute(nlmsg_delete_route) => nlmsg_delete_route.serialize(buf),
            NlmsgPayload::NewNeighbor(nlmsg_new_neighbor) => nlmsg_new_neighbor.serialize(buf),
            NlmsgPayload::DeleteNeighbor(nlmsg_delete_neighbor) => {
                nlmsg_delete_neighbor.serialize(buf)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgNewAddress {
    pub family: u8,
    pub prefix_length: u8,
    pub flags: u8,
    pub scope: u8,
    pub iface_idx: u32,
    pub attrs: Vec<AddressAttr>,
}

impl NlmsgNewAddress {
    fn serialize(&self, buf: &mut Vec<u8>) {
        const ADDRMSG_LEN: usize = mem::size_of::<ifaddrmsg>();
        const ADDRMSG_PADDING: usize = NLMSG_ALIGN(ADDRMSG_LEN) - ADDRMSG_LEN;

        let addrmsg = ifaddrmsg {
            ifa_family: self.family,
            ifa_prefixlen: self.prefix_length,
            ifa_flags: self.flags,
            ifa_scope: self.scope,
            ifa_index: self.iface_idx,
        };

        let addrmsg_bytes: [u8; ADDRMSG_LEN] = unsafe { mem::transmute(addrmsg) };
        buf.extend(&addrmsg_bytes);
        buf.extend(&[0u8; ADDRMSG_PADDING]);

        for attr in self.attrs.iter() {
            attr.serialize(buf);
        }
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgGetAddress {
    pub family: u8,
    pub prefix_length: u8,
    pub flags: u8,
    pub scope: u8,
    pub iface_idx: u32,
}

impl NlmsgGetAddress {
    fn serialize(&self, buf: &mut Vec<u8>) {
        const ADDRMSG_LEN: usize = mem::size_of::<ifaddrmsg>();
        const ADDRMSG_PADDING: usize = NLMSG_ALIGN(ADDRMSG_LEN) - ADDRMSG_LEN;

        let addrmsg = ifaddrmsg {
            ifa_family: self.family,
            ifa_prefixlen: self.prefix_length,
            ifa_flags: self.flags,
            ifa_scope: self.scope,
            ifa_index: self.iface_idx,
        };

        let addrmsg_bytes: [u8; ADDRMSG_LEN] = unsafe { mem::transmute(addrmsg) };
        buf.extend(&addrmsg_bytes);
        buf.extend(&[0u8; ADDRMSG_PADDING]);
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgDeleteAddress {
    pub family: u8,
    pub prefix_length: u8,
    pub flags: u8,
    pub scope: u8,
    pub iface_idx: u32,
    pub attrs: Vec<AddressAttr>,
}

impl NlmsgDeleteAddress {
    fn serialize(&self, buf: &mut Vec<u8>) {
        const ADDRMSG_LEN: usize = mem::size_of::<ifaddrmsg>();
        const ADDRMSG_PADDING: usize = NLMSG_ALIGN(ADDRMSG_LEN) - ADDRMSG_LEN;

        let addrmsg = ifaddrmsg {
            ifa_family: self.family,
            ifa_prefixlen: self.prefix_length,
            ifa_flags: self.flags,
            ifa_scope: self.scope,
            ifa_index: self.iface_idx,
        };

        let addrmsg_bytes: [u8; ADDRMSG_LEN] = unsafe { mem::transmute(addrmsg) };
        buf.extend(&addrmsg_bytes);
        buf.extend(&[0u8; ADDRMSG_PADDING]);

        for attr in self.attrs.iter() {
            attr.serialize(buf);
        }
    }
}

#[derive(Clone, Debug)]
pub enum AddressAttr {
    /// IFA_ADDRESS - a peer-to-peer destination address
    Address(IpAddr),
    /// IFA_LOCAL - the address of the interface
    Local(IpAddr),
    /// IFA_LOCAL - the interface name
    Label(CString),
    /// IFA_BROADCAST - the broadcast address of the interface
    Broadcast(IpAddr),
    /// IFA_ANYCAST - the anycast address of the interface
    Anycast(IpAddr),
    CacheInfo(AddrCacheInfo),
    /// IFA_UNSPEC - an unspecified RT attribute
    Unspecified(Vec<u8>),
    /// Some other unknown RT attribute
    Unknown(u16, Vec<u8>),
}

impl AddressAttr {
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            AddressAttr::Address(ip_addr) => {
                let rta_type = libc::IFA_ADDRESS;
                match *ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let rta_len = 8u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u32::from(ipv4_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let rta_len = 20u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u128::from(ipv6_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                }
            }
            AddressAttr::Local(ip_addr) => {
                let rta_type = libc::IFA_LOCAL;
                match *ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let rta_len = 8u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u32::from(ipv4_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let rta_len = 20u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u128::from(ipv6_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                }
            }
            AddressAttr::Label(cstring) => {
                let rta_type = libc::IFA_LABEL;
                let rta_len = cstring.as_bytes_with_nul().len() + 4;
                buf.extend((rta_len as u16).to_ne_bytes());
                buf.extend(rta_type.to_ne_bytes());
                buf.extend(cstring.as_bytes_with_nul());
                let padded_len = NLMSG_ALIGN(rta_len) - rta_len;
                buf.extend(iter::repeat(0).take(padded_len));
            }
            AddressAttr::Broadcast(ip_addr) => {
                let rta_type = libc::IFA_BROADCAST;
                match *ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let rta_len = 8u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u32::from(ipv4_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let rta_len = 20u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u128::from(ipv6_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                }
            }
            AddressAttr::Anycast(ip_addr) => {
                let rta_type = libc::IFA_ANYCAST;
                match *ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let rta_len = 8u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u32::from(ipv4_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let rta_len = 20u16;
                        buf.extend(rta_len.to_ne_bytes());
                        buf.extend(rta_type.to_ne_bytes());
                        buf.extend(u128::from(ipv6_addr).to_be_bytes());
                        let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                        buf.extend(iter::repeat(0).take(padded_len));
                    }
                }
            }
            AddressAttr::CacheInfo(cache_info) => {
                let rta_type = libc::IFA_CACHEINFO;
                let rta_len = 4u16 + mem::size_of_val(cache_info) as u16;
                buf.extend(rta_len.to_ne_bytes());
                buf.extend(rta_type.to_ne_bytes());
                let cache_info_bytes: [u8; mem::size_of::<AddrCacheInfo>()] =
                    unsafe { mem::transmute_copy(cache_info) };
                buf.extend(&cache_info_bytes);
                let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                buf.extend(iter::repeat(0).take(padded_len));
            }
            AddressAttr::Unspecified(unspec) => {
                let rta_type = libc::IFA_UNSPEC;
                let rta_len = 4u16 + unspec.len() as u16;
                buf.extend(rta_len.to_ne_bytes());
                buf.extend(rta_type.to_ne_bytes());
                buf.extend(unspec);
                let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                buf.extend(iter::repeat(0).take(padded_len));
            }
            AddressAttr::Unknown(ty, unknown) => {
                let rta_type = *ty;
                let rta_len = 4u16 + unknown.len() as u16;
                buf.extend(rta_len.to_ne_bytes());
                buf.extend(rta_type.to_ne_bytes());
                buf.extend(unknown);
                let padded_len = NLMSG_ALIGN(rta_len as usize) - rta_len as usize;
                buf.extend(iter::repeat(0).take(padded_len));
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgNewRoute {
    pub iface_idx: i32,
    pub state: u16,
    pub flags: u8,
    pub arp_type: u8,
    pub attrs: Vec<RouteAttr>,
}

impl NlmsgNewRoute {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgDeleteRoute {
    pub iface_idx: i32,
    pub state: u16,
    pub flags: u8,
    pub arp_type: u8,
    pub attrs: Vec<RouteAttr>,
}

impl NlmsgDeleteRoute {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub enum RouteAttr {
    /// RTA_UNSPEC - ignored
    Unspec(Vec<u8>),
    /// RTA_DST - Route destination address
    Destination(IpAddr),
    /// RTA_SRC - Route source address
    Source(IpAddr),
    /// RTA_IIF - Input interface index
    InputInterface(i32),
    /// RTA_OIF - Output interface index
    OutputInterface(i32),
    /// RTA_GATEWAY - The gateway of the route
    Gateway(IpAddr),
    /// RTA_PRIORITY - The priority of the route
    Priority(i32),
    /// RTA_PREFSRC - The preferred source address
    PreferredSource(IpAddr),
    /// RTA_METRICS - Route metric
    Metric(i32),
    /// RTA_Flow - Route realm
    Flow(i32),
    /// RTA_CACHEINFO - Route cache info
    CacheInfo(RouteCacheInfo),
    /// RTA_TABLE - Routing table ID; if set, rtm_table is ignored
    TableId(i32),
    /// RTA_MARK
    Mark(i32),
    /// RTA_MFC_STATS
    MfcStats(RouteMfcStats),
    /// RTA_VIA - Gateway in different address family
    Via(Vec<u8>),
    /// RTA_NEWDST - Change packet destination address
    NewDestination(IpAddr),
    /// RTA_PREF - RFC4191 IPv6 router preference
    Ipv6Preference(i8),
    /// RTA_EXPIRES - Expire time for IPv6 routes (in seconds)
    Expires(i32),
    /// Some other unknown RT attribute
    Unknown(u16, Vec<u8>),
}

impl RouteAttr {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgNewNeighbor {
    pub iface_idx: i32,
    pub state: u16,
    pub flags: u8,
    pub arp_type: u8,
    pub attrs: Vec<NeighborAttr>,
}

impl NlmsgNewNeighbor {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct NlmsgDeleteNeighbor {
    pub iface_idx: i32,
    pub state: u16,
    pub flags: u8,
    pub arp_type: u8,
    pub attrs: Vec<NeighborAttr>,
}

impl NlmsgDeleteNeighbor {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub enum NeighborAttr {
    /// NTA_DST - a neighbor cache network layer destination address
    DestinationAddress(IpAddr),
    /// NTA_LLADDR - a neighbor cache link layer address
    LinkAddress(MacAddr),
    /// NTA_CACHEINFO - cache statistics
    CacheInfo(NeighborCacheInfo),
    /// Some other unknown RT attribute
    Unknown(u16, Vec<u8>),
}

impl NeighborAttr {
    fn serialize(&self, buf: &mut Vec<u8>) {
        todo!()
    }
}

// =============================================================================
//                          Netlink Response Messages
// =============================================================================

pub struct NetlinkResponseRef<'a> {
    data: &'a [u8],
}

impl<'a> NetlinkResponseRef<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    #[inline]
    pub fn messages(&self) -> NlmsgIter<'a> {
        NlmsgIter::new(self.data)
    }
}

pub struct NlmsgIter<'a> {
    data: &'a [u8],
}

impl<'a> NlmsgIter<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for NlmsgIter<'a> {
    type Item = Result<NlmsgRef<'a>, NlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        const HDR_LEN: usize = mem::size_of::<libc::nlmsghdr>();

        let Some(hdr_slice) = self.data.get(..HDR_LEN) else {
            return Some(Err(NlParseError::new(
                "netlink response had truncated nlmsg header",
            )));
        };

        let hdr_bytes: [u8; HDR_LEN] = hdr_slice.try_into().unwrap();
        let header: libc::nlmsghdr = unsafe { mem::transmute(hdr_bytes) };

        let Some(nlmsg) = self.data.get(..header.nlmsg_len as usize) else {
            return Some(Err(NlParseError::new(
                "netlink response had truncated nlmsg payload",
            )));
        };

        let padded_len = NLMSG_ALIGN(header.nlmsg_len as usize);
        // Truncated padding is fine
        self.data = self.data.get(padded_len..).unwrap_or(&[]);

        Some(NlmsgRef::parse(nlmsg))
    }
}

pub struct NlmsgRef<'a> {
    flags: u16,
    seq: u32,
    pid: u32,
    payload: NlmsgPayloadRef<'a>,
}

impl<'a> NlmsgRef<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, NlParseError> {
        const HDR_LEN: usize = mem::size_of::<libc::nlmsghdr>();

        let Some(hdr_slice) = data.get(..HDR_LEN) else {
            return Err(NlParseError::new(
                "netlink response had truncated nlmsg header",
            ));
        };

        let hdr_bytes: [u8; HDR_LEN] = hdr_slice.try_into().unwrap();
        let header: libc::nlmsghdr = unsafe { mem::transmute(hdr_bytes) };

        const PAYLOAD_START: usize = NLMSG_ALIGN(HDR_LEN);

        const NLMSG_NOOP: u16 = libc::NLMSG_NOOP as u16;
        const NLMSG_OVERRUN: u16 = libc::NLMSG_OVERRUN as u16;
        const NLMSG_DONE: u16 = libc::NLMSG_DONE as u16;
        const NLMSG_ERROR: u16 = libc::NLMSG_ERROR as u16;
        Ok(NlmsgRef {
            flags: header.nlmsg_flags,
            seq: header.nlmsg_seq,
            pid: header.nlmsg_pid,
            payload: match header.nlmsg_type {
                NLMSG_NOOP => NlmsgPayloadRef::Noop,
                NLMSG_OVERRUN => NlmsgPayloadRef::Overrun,
                NLMSG_DONE => NlmsgPayloadRef::Done,
                NLMSG_ERROR => {
                    let Some(error_payload) = data.get(PAYLOAD_START..) else {
                        return Err(NlParseError::new(
                            "netlink response had truncated Error payload",
                        ));
                    };

                    NlmsgPayloadRef::Error(NlmsgError::parse(error_payload)?)
                }
                libc::RTM_NEWADDR => {
                    let Some(addr_payload) = data.get(PAYLOAD_START..) else {
                        return Err(NlParseError::new(
                            "netlink response had truncated RTM_GETADDR payload",
                        ));
                    };

                    NlmsgPayloadRef::GetAddress(NlmsgGetAddressRef::parse(addr_payload)?)
                }
                // libc::RTM_GETLINK => ,
                libc::RTM_NEWROUTE => {
                    let Some(route_payload) = data.get(PAYLOAD_START..) else {
                        return Err(NlParseError::new(
                            "netlink response had truncated RTM_GETROUTE payload",
                        ));
                    };

                    NlmsgPayloadRef::GetRoute(NlmsgGetRoute::parse(route_payload)?)
                }
                libc::RTM_NEWNEIGH => {
                    let Some(neighbor_payload) = data.get(PAYLOAD_START..) else {
                        return Err(NlParseError::new(
                            "netlink response had truncated RTM_GETNEIGH payload",
                        ));
                    };

                    NlmsgPayloadRef::GetNeighbor(NlmsgGetNeighbor::parse(neighbor_payload)?)
                }
                _ => NlmsgPayloadRef::Unknown,
            },
        })
    }

    #[inline]
    pub fn flags_raw(&self) -> u16 {
        self.flags
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    #[inline]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[inline]
    pub fn payload(&self) -> NlmsgPayloadRef<'a> {
        self.payload
    }
}

#[derive(Clone, Copy)]
pub enum NlmsgPayloadRef<'a> {
    /// Indicates the message should be ignored; not often used in practice.
    Noop,
    /// Marks the end of a dump request.
    Done,
    /// Indicates that the socket buffer has overflown (not used to date).
    Overrun,
    /// Indicates the request failed with the designated error code.
    Error(NlmsgError), // TODO: could include original request header, payload...
    /// Informational response from an `RTM_GETADDR` request.
    GetAddress(NlmsgGetAddressRef<'a>),
    /// Informational response from an `RTM_GETROUTE` request.
    GetRoute(NlmsgGetRoute<'a>),
    /// Informational response from an `RTM_GETNEIGHBOR` request.
    GetNeighbor(NlmsgGetNeighbor<'a>),
    /// Some other RTNetlink message
    Unknown,
    /*
    // /// Informational response from an `RTM_GETLINK` request.
    // GetLink(),
    /// Informational response from an `RTM_GETRULE` request.
    GetRule(),
    /// Informational response from an `RTM_GETQDISC` request.
    GetQdisc(),
    /// Informational response from an `RTM_GETTCLASS` request.
    GetTrafficClass(),
    /// Informational response from an `RTM_GETTFILTER` request.
    GetTrafficFilter(),
    */
}

#[derive(Clone, Copy)]
pub struct NlmsgError {
    errno: i32,
}

impl NlmsgError {
    fn parse(data: &[u8]) -> Result<Self, NlParseError> {
        let Some(errno_bytes) = data.get(..4) else {
            return Err(NlParseError::new(
                "netlink Error response had truncated errno value",
            ));
        };

        Ok(Self {
            // This is meant to be negated--errno values from netlink come as negative.
            errno: -i32::from_ne_bytes(errno_bytes.try_into().unwrap()),
        })
    }

    pub fn errno(&self) -> i32 {
        self.errno
    }
}

#[derive(Clone, Copy)]
pub struct NlmsgGetAddressRef<'a> {
    family: u8,
    prefix_length: u8,
    flags: u8,
    scope: u8,
    iface_idx: u32,
    attr_data: &'a [u8],
}

impl<'a> NlmsgGetAddressRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, NlParseError> {
        const ADDRMSG_LEN: usize = mem::size_of::<ifaddrmsg>();

        let Some(addrmsg_bytes) = data.get(..ADDRMSG_LEN) else {
            return Err(NlParseError::new(
                "netlink RTM_GETADDR message was truncated",
            ));
        };
        let addrmsg_arr: [u8; ADDRMSG_LEN] = addrmsg_bytes.try_into().unwrap();
        let addrmsg: ifaddrmsg = unsafe { mem::transmute(addrmsg_arr) };

        let rem = data.get(NLMSG_ALIGN(ADDRMSG_LEN)..).unwrap_or(&[]);

        Ok(Self {
            family: addrmsg.ifa_family,
            prefix_length: addrmsg.ifa_prefixlen,
            flags: addrmsg.ifa_flags,
            scope: addrmsg.ifa_scope,
            iface_idx: addrmsg.ifa_index,
            attr_data: rem,
        })
    }

    // TODO: add specific type?
    #[inline]
    pub fn family(&self) -> u8 {
        self.family
    }

    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_length
    }

    // TODO: add specific type
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    // TODO: add specific type
    #[inline]
    pub fn scope(&self) -> u8 {
        self.scope
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.iface_idx
    }

    #[inline]
    pub fn attrs(&self) -> AddressAttrIter {
        AddressAttrIter::new(self.attr_data)
    }
}

pub struct AddressAttrIter<'a> {
    data: &'a [u8],
}

impl<'a> AddressAttrIter<'a> {
    #[inline]
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for AddressAttrIter<'a> {
    type Item = Result<AddressAttrRef<'a>, NlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let Some(attr_len_bytes) = self.data.get(..2) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETADDR attribute had truncated length filed",
            )));
        };

        let Some(attr_type_bytes) = self.data.get(2..4) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETADDR attribute had truncated type field",
            )));
        };

        let attr_len = u16::from_ne_bytes(attr_len_bytes.try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(attr_type_bytes.try_into().unwrap());

        let Some(attr_data) = self.data.get(4..attr_len) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETADDR attribute had truncated data field",
            )));
        };

        let padded_len = NLMSG_ALIGN(attr_len);
        // Truncated padding is fine
        self.data = self.data.get(padded_len..).unwrap_or(&[]);

        Some(Ok(match attr_type {
            libc::IFA_ADDRESS => match attr_data.len() {
                4 => AddressAttrRef::Address(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => AddressAttrRef::Address(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_ADDRESS attribute with invalid size",
                    )))
                }
            },
            libc::IFA_LOCAL => match attr_data.len() {
                4 => AddressAttrRef::Local(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => AddressAttrRef::Local(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_LOCAL attribute with invalid size",
                    )))
                }
            },
            libc::IFA_BROADCAST => match attr_data.len() {
                4 => AddressAttrRef::Broadcast(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => AddressAttrRef::Broadcast(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_BROADCAST attribute with invalid size",
                    )))
                }
            },
            libc::IFA_ANYCAST => match attr_data.len() {
                4 => AddressAttrRef::Anycast(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => AddressAttrRef::Anycast(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_ANYCAST attribute with invalid size",
                    )))
                }
            },
            libc::IFA_CACHEINFO => {
                if attr_data.len() == mem::size_of::<AddrCacheInfo>() {
                    let cache_info_bytes: [u8; mem::size_of::<AddrCacheInfo>()] =
                        attr_data.try_into().unwrap();
                    let cache_info: AddrCacheInfo = unsafe { mem::transmute(cache_info_bytes) };
                    AddressAttrRef::CacheInfo(cache_info)
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_CACHEINFO attribute with invalid size",
                    )));
                }
            }
            libc::IFA_LABEL => {
                let Ok(cstr) = CStr::from_bytes_with_nul(attr_data) else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETADDR had IFA_LABEL attribute with invalid data",
                    )));
                };

                AddressAttrRef::Label(cstr)
            }
            libc::IFA_UNSPEC => AddressAttrRef::Unspecified(attr_data),
            _ => AddressAttrRef::Unknown(attr_type, attr_data),
        }))
    }
}

pub enum AddressAttrRef<'a> {
    /// IFA_ADDRESS - interface address
    Address(IpAddr),
    /// IFA_LOCAL - local address
    Local(IpAddr),
    /// IFA_LABEL - name of the interface
    Label(&'a CStr),
    /// IFA_BROADCAST - broadcast address
    Broadcast(IpAddr),
    /// IFA_ANYCAST - anycast address
    Anycast(IpAddr),
    /// IFA_CACHEINFO - cache info
    CacheInfo(AddrCacheInfo),
    /// IFA_UNSPEC - an unspecified RT attribute
    Unspecified(&'a [u8]),
    /// Some other unknown RT attribute
    Unknown(u16, &'a [u8]),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AddrCacheInfo {
    prefered: u32,
    valid: u32,
    cstamp: u32,
    tstamp: u32,
}

#[derive(Clone, Copy)]
pub struct NlmsgGetNeighbor<'a> {
    iface_idx: i32,
    state: u16,
    flags: u8,
    arp_type: u8,
    attr_data: &'a [u8],
}

impl<'a> NlmsgGetNeighbor<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, NlParseError> {
        const NDMSG_LEN: usize = mem::size_of::<ndmsg>();

        let Some(msg_bytes) = data.get(..NDMSG_LEN) else {
            return Err(NlParseError::new(
                "netlink RTM_GETNEIGH message was truncated",
            ));
        };
        let msg_arr: [u8; NDMSG_LEN] = msg_bytes.try_into().unwrap();
        let msg: ndmsg = unsafe { mem::transmute(msg_arr) };

        let rem = data.get(NLMSG_ALIGN(NDMSG_LEN)..).unwrap_or(&[]);

        Ok(Self {
            iface_idx: msg.ndm_index,
            state: msg.ndm_state,
            flags: msg.ndm_flags,
            arp_type: msg.ndm_type,
            attr_data: rem,
        })
    }

    pub fn index(&self) -> i32 {
        self.iface_idx
    }

    pub fn state(&self) -> u16 {
        self.state
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn arp_type(&self) -> u8 {
        self.arp_type
    }

    pub fn attrs(&self) -> NeighborAttrIter<'a> {
        NeighborAttrIter::new(self.attr_data)
    }
}

pub struct NeighborAttrIter<'a> {
    data: &'a [u8],
}

impl<'a> NeighborAttrIter<'a> {
    #[inline]
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for NeighborAttrIter<'a> {
    type Item = Result<NeighborAttrRef<'a>, NlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let Some(attr_len_bytes) = self.data.get(..2) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETNEIGH attribute had truncated length filed",
            )));
        };

        let Some(attr_type_bytes) = self.data.get(2..4) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETNEIGH attribute had truncated type field",
            )));
        };

        let attr_len = u16::from_ne_bytes(attr_len_bytes.try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(attr_type_bytes.try_into().unwrap());

        let Some(attr_data) = self.data.get(4..attr_len) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETNEIGH attribute had truncated data field",
            )));
        };

        let padded_len = NLMSG_ALIGN(attr_len);
        // Truncated padding is fine
        self.data = self.data.get(padded_len..).unwrap_or(&[]);

        Some(Ok(match attr_type {
            libc::NDA_DST => match attr_data.len() {
                4 => NeighborAttrRef::DestinationAddress(IpAddr::V4(Ipv4Addr::from(
                    u32::from_be_bytes(attr_data.try_into().unwrap()),
                ))),
                16 => NeighborAttrRef::DestinationAddress(IpAddr::V6(Ipv6Addr::from(
                    u128::from_be_bytes(attr_data.try_into().unwrap()),
                ))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETNEIGH had NDA_DST attribute with invalid size",
                    )))
                }
            },
            libc::NDA_LLADDR => {
                if attr_data.len() == 6 {
                    let cache_info_bytes: [u8; 6] = attr_data.try_into().unwrap();
                    NeighborAttrRef::LinkAddress(MacAddr::from(cache_info_bytes))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETNEIGH had IFA_LLADDR attribute with invalid size",
                    )));
                }
            }
            libc::NDA_CACHEINFO => {
                if attr_data.len() == mem::size_of::<NeighborCacheInfo>() {
                    let cache_info_bytes: [u8; mem::size_of::<NeighborCacheInfo>()] =
                        attr_data.try_into().unwrap();
                    let cache_info: NeighborCacheInfo = unsafe { mem::transmute(cache_info_bytes) };
                    NeighborAttrRef::CacheInfo(cache_info)
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETNEIGH had NDA_CACHEINFO attribute with invalid size",
                    )));
                }
            }
            _ => NeighborAttrRef::Unknown(attr_type, attr_data),
        }))
    }
}

pub enum NeighborAttrRef<'a> {
    /// NTA_DST - a neighbor cache network layer destination address
    DestinationAddress(IpAddr),
    /// NTA_LLADDR - a neighbor cache link layer address
    LinkAddress(MacAddr),
    /// NTA_CACHEINFO - cache statistics
    CacheInfo(NeighborCacheInfo),
    /// Some other unknown RT attribute
    Unknown(u16, &'a [u8]),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NeighborCacheInfo {
    pub confirmed: u32,
    pub used: u32,
    pub updated: u32,
    pub refcnt: u32,
}

#[derive(Clone, Copy)]
pub struct NlmsgGetRoute<'a> {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table_id: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    flags: u32,
    attr_data: &'a [u8],
}

impl<'a> NlmsgGetRoute<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, NlParseError> {
        const NDMSG_LEN: usize = mem::size_of::<rtmsg>();

        let Some(msg_bytes) = data.get(..NDMSG_LEN) else {
            return Err(NlParseError::new(
                "netlink RTM_GETROUTE message was truncated",
            ));
        };
        let msg_arr: [u8; NDMSG_LEN] = msg_bytes.try_into().unwrap();
        let msg: rtmsg = unsafe { mem::transmute(msg_arr) };

        let rem = data.get(NLMSG_ALIGN(NDMSG_LEN)..).unwrap_or(&[]);

        Ok(Self {
            family: msg.rtm_family,
            dst_len: msg.rtm_dst_len,
            src_len: msg.rtm_src_len,
            tos: msg.rtm_tos,
            table_id: msg.rtm_table,
            protocol: msg.rtm_protocol,
            scope: msg.rtm_scope,
            route_type: msg.rtm_type,
            flags: msg.rtm_flags,
            attr_data: rem,
        })
    }

    pub fn family(&self) -> u8 {
        self.family
    }

    pub fn tos(&self) -> u8 {
        self.tos
    }

    pub fn table_id(&self) -> u8 {
        self.table_id
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn scope(&self) -> u8 {
        self.scope
    }

    pub fn route_type(&self) -> u8 {
        self.route_type
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn attrs(&self) -> RouteAttrIter<'a> {
        RouteAttrIter::new(self.attr_data)
    }
}

pub struct RouteAttrIter<'a> {
    data: &'a [u8],
}

impl<'a> RouteAttrIter<'a> {
    #[inline]
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for RouteAttrIter<'a> {
    type Item = Result<RouteAttrRef<'a>, NlParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let Some(attr_len_bytes) = self.data.get(..2) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETROUTE attribute had truncated length filed",
            )));
        };

        let Some(attr_type_bytes) = self.data.get(2..4) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETROUTE attribute had truncated type field",
            )));
        };

        let attr_len = u16::from_ne_bytes(attr_len_bytes.try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(attr_type_bytes.try_into().unwrap());

        let Some(attr_data) = self.data.get(4..attr_len) else {
            return Some(Err(NlParseError::new(
                "netlink RTM_GETROUTE attribute had truncated data field",
            )));
        };

        let padded_len = NLMSG_ALIGN(attr_len);
        // Truncated padding is fine
        self.data = self.data.get(padded_len..).unwrap_or(&[]);

        Some(Ok(match attr_type {
            libc::RTA_DST => match attr_data.len() {
                4 => RouteAttrRef::Destination(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => RouteAttrRef::Destination(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_DST attribute with invalid size",
                    )))
                }
            },
            libc::RTA_SRC => match attr_data.len() {
                4 => RouteAttrRef::Source(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => RouteAttrRef::Source(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_SRC attribute with invalid size",
                    )))
                }
            },
            libc::RTA_IIF => {
                if attr_data.len() == 4 {
                    RouteAttrRef::InputInterface(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_IIF attribute with invalid size",
                    )));
                }
            }
            libc::RTA_OIF => {
                if attr_data.len() == 4 {
                    RouteAttrRef::OutputInterface(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_OIF attribute with invalid size",
                    )));
                }
            }
            libc::RTA_GATEWAY => match attr_data.len() {
                4 => RouteAttrRef::Gateway(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => RouteAttrRef::Gateway(IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_GATEWAY attribute with invalid size",
                    )))
                }
            },
            libc::RTA_PRIORITY => {
                if attr_data.len() == 4 {
                    RouteAttrRef::Priority(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_PRIORITY attribute with invalid size",
                    )));
                }
            }
            libc::RTA_PREFSRC => match attr_data.len() {
                4 => RouteAttrRef::PreferredSource(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => RouteAttrRef::PreferredSource(IpAddr::V6(Ipv6Addr::from(
                    u128::from_be_bytes(attr_data.try_into().unwrap()),
                ))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_PREFSRC attribute with invalid size",
                    )))
                }
            },
            libc::RTA_METRICS => {
                if attr_data.len() == 4 {
                    RouteAttrRef::Metric(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_METRIC attribute with invalid size",
                    )));
                }
            }
            libc::RTA_FLOW => {
                if attr_data.len() == 4 {
                    RouteAttrRef::Flow(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_FLOW attribute with invalid size",
                    )));
                }
            }
            libc::RTA_CACHEINFO => {
                if attr_data.len() == mem::size_of::<RouteCacheInfo>() {
                    let cache_info_bytes: [u8; mem::size_of::<RouteCacheInfo>()] =
                        attr_data.try_into().unwrap();
                    let cache_info: RouteCacheInfo = unsafe { mem::transmute(cache_info_bytes) };
                    RouteAttrRef::CacheInfo(cache_info)
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETNEIGH had NDA_CACHEINFO attribute with invalid size",
                    )));
                }
            }
            libc::RTA_TABLE => {
                if attr_data.len() == 4 {
                    RouteAttrRef::TableId(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_TABLE attribute with invalid size",
                    )));
                }
            }
            libc::RTA_MFC_STATS => {
                if attr_data.len() == mem::size_of::<RouteMfcStats>() {
                    let mfc_stat_bytes: [u8; mem::size_of::<RouteMfcStats>()] =
                        attr_data.try_into().unwrap();
                    let mfc_stats: RouteMfcStats = unsafe { mem::transmute(mfc_stat_bytes) };
                    RouteAttrRef::MfcStats(mfc_stats)
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_MFC_STATS attribute with invalid size",
                    )));
                }
            }
            libc::RTA_NEWDST => match attr_data.len() {
                4 => RouteAttrRef::NewDestination(IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(
                    attr_data.try_into().unwrap(),
                )))),
                16 => RouteAttrRef::NewDestination(IpAddr::V6(Ipv6Addr::from(
                    u128::from_be_bytes(attr_data.try_into().unwrap()),
                ))),
                _ => {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_NEWDST attribute with invalid size",
                    )))
                }
            },
            libc::RTA_PREF => {
                if attr_data.len() == 1 {
                    RouteAttrRef::Ipv6Preference(attr_data[0] as i8)
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_PREF attribute with invalid size",
                    )));
                }
            }
            libc::RTA_EXPIRES => {
                if attr_data.len() == 4 {
                    RouteAttrRef::Expires(i32::from_ne_bytes(attr_data.try_into().unwrap()))
                } else {
                    return Some(Err(NlParseError::new(
                        "netlink RTM_GETROUTE had RTA_EXPIRES attribute with invalid size",
                    )));
                }
            }
            libc::RTA_UNSPEC => RouteAttrRef::Unspec(attr_data),
            _ => RouteAttrRef::Unknown(attr_type, attr_data),
        }))
    }
}

pub enum RouteAttrRef<'a> {
    /// RTA_UNSPEC - ignored
    Unspec(&'a [u8]),
    /// RTA_DST - Route destination address
    Destination(IpAddr),
    /// RTA_SRC - Route source address
    Source(IpAddr),
    /// RTA_IIF - Input interface index
    InputInterface(i32),
    /// RTA_OIF - Output interface index
    OutputInterface(i32),
    /// RTA_GATEWAY - The gateway of the route
    Gateway(IpAddr),
    /// RTA_PRIORITY - The priority of the route
    Priority(i32),
    /// RTA_PREFSRC - The preferred source address
    PreferredSource(IpAddr),
    /// RTA_METRICS - Route metric
    Metric(i32),
    /// RTA_Flow - Route realm
    Flow(i32),
    /// RTA_CACHEINFO - Route cache info
    CacheInfo(RouteCacheInfo),
    /// RTA_TABLE - Routing table ID; if set, rtm_table is ignored
    TableId(i32),
    /// RTA_MARK
    Mark(i32),
    /// RTA_MFC_STATS
    MfcStats(RouteMfcStats),
    /// RTA_VIA - Gateway in different address family
    Via(&'a [u8]),
    /// RTA_NEWDST - Change packet destination address
    NewDestination(IpAddr),
    /// RTA_PREF - RFC4191 IPv6 router preference
    Ipv6Preference(i8),
    /// RTA_EXPIRES - Expire time for IPv6 routes (in seconds)
    Expires(i32),
    /// Some other unknown RT attribute
    Unknown(u16, &'a [u8]),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RouteCacheInfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: i32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RouteMfcStats {
    pub mfcs_packets: u64,
    pub mfcs_bytes: u64,
    pub mfcs_wrong_if: u64,
}
