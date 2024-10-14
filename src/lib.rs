// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tappers is a networking library that provides cross-platform support for TUN, TAP and virtual
//! Ethernet (vETH) interfaces in Rust.
//!
//! The [`Tun`] and [`Tap`] structs found in the root of this crate are designed to work across
//! all supported platforms (Linux/MacOS/Windows/*BSD). Additional OS-specific functionality
//! is provided via the [`linux`], [`macos`], [`unix`] and [`wintun`] modules.
//!
//! ## Examples
//!
//! To create a TUN device and begin synchronously receiving packets from it:
//!
//! ```no_run
//! # use std::io;
//! # #[cfg(not(target_os = "windows"))]
//! # fn create_tun() -> io::Result<()> {
//! use std::net::Ipv4Addr;
//! use tappers::Tun;
//!
//! // Create a new TUN device with a unique identifier
//! let mut tun = Tun::new()?;
//! // Assign an IP address to the TUN device
//! tun.add_addr(Ipv4Addr::new(10, 100, 0, 1))?;
//! // Enable the TUN device to begin receiving packets
//! tun.set_up()?;
//!
//! let mut recv_buf = [0; 65536];
//!
//! loop {
//!     // Receive a single network-layer packet from the TUN device
//!     let amount = tun.recv(&mut recv_buf)?;
//!     println!("Received packet: {:?}", &recv_buf[0..amount]);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Likewise, to create a TAP device and begin receiving packets from it:
//!
//! ```no_run
//! # use std::io;
//! # #[cfg(not(target_os = "windows"))]
//! # fn create_tap() -> io::Result<()> {
//! use std::net::Ipv6Addr;
//! use tappers::Tap;
//!
//! // Create a new TAP device with a unique identifier
//! let mut tap = Tap::new()?;
//! // Assign an IP address to the TAP device
//! tap.add_addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff))?;
//! // Enable the TAP device to begin receiving packets
//! tap.set_up()?;
//!
//! let mut recv_buf = [0; 65536];
//!
//! loop {
//!     // Receive a single link-layer packet from the TAP device
//!     let amount = tap.recv(&mut recv_buf)?;
//!     println!("Received packet: {:?}", &recv_buf[0..amount]);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Tappers additionally allows for more complex configuration of interfaces:
//!
//! ```no_run
//! # use std::io;
//! # #[cfg(not(target_os = "windows"))]
//! # fn create_tap() -> io::Result<()> {
//! use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
//! use tappers::{AddAddressV4, AddAddressV6, AddressInfo, DeviceState, Interface, Tap};
//!
//! // Select an existing (or new) TAP interface name to open
//! let tap_name = Interface::new("tap10")?;
//!
//! // Open the TAP device of the name "tap10" (or create it if it doesn't exist)
//! let mut tap = Tap::new_named(tap_name)?;
//!
//! // Add a new address with associated info to the TAP device
//! let new_addr = Ipv4Addr::new(10, 100, 0, 1);
//! let mut addr_req = AddAddressV4::new(new_addr);
//! addr_req.set_netmask(24);
//! addr_req.set_broadcast(Ipv4Addr::new(10, 100, 0, 255));
//!
//! tap.add_addr(addr_req)?;
//!
//! // Retrieve information on the IPv4/IPv6 addresses bound to the TAP device
//! let addrs = tap.addrs()?;
//! for addr_info in addrs {
//!     println!("IP address: {}", addr_info.address());
//!     if let Some(netmask) = addr_info.netmask() {
//!         println!("Netmask: {}", netmask);
//!     }
//!     if let Some(broadcast) = addr_info.broadcast() {
//!         println!("Broadcast: {}", broadcast);
//!     }
//! }
//!
//! // Remove an address from the TAP device
//! tap.remove_addr(IpAddr::V4(new_addr))?;
//!
//! // Configure whether the TAP device performs non-blocking reads/writes
//! tap.set_nonblocking(true)?;
//!
//! // Bring the device up to enable packet exchange
//! tap.set_state(DeviceState::Up);
//!
//! let mut buf = [0; 65536];
//!
//! // Receive packets from the interface
//! let amount = tap.recv(&mut buf)?;
//!
//! // Send packets over the interface
//! let amount = tap.send(&buf[..amount])?;
//!
//! // Bring the device down to disable packet exchange
//! tap.set_state(DeviceState::Down);
//!
//! // The TUN device represented by `tun` is automatically be removed from the system when dropped.
//! # Ok(())
//! # }
//! ```

// TODO: handle EINTR where applicable
// TODO: add CLOEXEC to all sockets

// Show required OS/features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(doc, target_os = "linux"))]
pub mod linux;
#[cfg(any(doc, target_os = "macos"))]
pub mod macos;
#[cfg(any(
    doc,
    target_os = "dragonfly",
    target_os = "freebsd",
//    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
//    target_os = "solaris"
))]
pub mod unix;
#[cfg(any(doc, all(target_os = "windows", feature = "wintun")))]
pub mod wintun;

#[cfg(any(doc, not(target_os = "windows")))]
mod libc_extra;
#[cfg(target_os = "linux")]
mod rtnetlink;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod sysctl;
#[cfg(not(target_os = "windows"))]
mod tap;
#[cfg(any(not(target_os = "windows"), feature = "wintun"))]
mod tun;

#[cfg(not(target_os = "windows"))]
pub use tap::Tap;
#[cfg(any(not(target_os = "windows"), feature = "wintun"))]
pub use tun::Tun;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use std::cmp;
#[cfg(any(doc, not(target_os = "windows")))]
use std::ffi::CStr;
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Display};
#[cfg(not(target_os = "windows"))]
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(not(target_os = "windows"))]
use std::os::fd::RawFd;
#[cfg(all(doc, target_os = "windows"))]
pub type RawFd = i32;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::str::FromStr;
use std::{array, io, ptr};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{ERROR_DEV_NOT_EXIST, ERROR_NO_DATA};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdapterIndex, MAX_ADAPTER_NAME};

#[cfg(not(target_os = "windows"))]
use crate::libc_extra::*;

#[cfg(target_os = "linux")]
use rtnetlink::{
    AddressAttr, AddressAttrRef, NetlinkRequest, NetlinkResponseRef, NlmsgDeleteAddress,
    NlmsgGetAddress, NlmsgNewAddress, NlmsgPayload, NlmsgPayloadRef,
};
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
use sysctl::*;

const NETLINK_MAX_RECV: usize = 65536;

pub type Netmask = u8;

/// Information associated with an interface IP address.
#[derive(Clone, Debug)]
pub enum AddressInfo {
    V4(AddressInfoV4),
    V6(AddressInfoV6),
}

impl AddressInfo {
    /// The IP address associated with the interface.
    pub fn address(&self) -> IpAddr {
        match self {
            Self::V4(a) => IpAddr::V4(a.address()),
            Self::V6(a) => IpAddr::V6(a.address()),
        }
    }

    /// The broadcast address associated with the interface.
    pub fn broadcast(&self) -> Option<IpAddr> {
        Some(match self {
            Self::V4(a) => IpAddr::V4(a.broadcast()?),
            Self::V6(a) => IpAddr::V6(a.broadcast()?),
        })
    }

    /// The point-to-point destination address associated with the interface.
    pub fn destination(&self) -> Option<IpAddr> {
        Some(match self {
            Self::V4(a) => IpAddr::V4(a.destination()?),
            Self::V6(a) => IpAddr::V6(a.destination()?),
        })
    }

    /// The netmask associated with the interface.
    pub fn netmask(&self) -> Option<Netmask> {
        match self {
            Self::V4(a) => a.netmask(),
            Self::V6(a) => a.netmask(),
        }
    }
}

/// Information associated with an interface IPv4 address.
#[derive(Clone, Debug)]
pub struct AddressInfoV4 {
    addr: Ipv4Addr,
    broadcast: Option<Ipv4Addr>,
    destination: Option<Ipv4Addr>,
    netmask: Option<Netmask>, // defaults to 32 for IPv4, 64 for IPv6 (per ifconfig behavior)
}

impl AddressInfoV4 {
    /// The IPv4 address associated with the interface.
    pub fn address(&self) -> Ipv4Addr {
        self.addr
    }

    /// The broadcast address associated with the interface.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        self.broadcast
    }

    /// The point-to-point destination address associated with the interface.
    pub fn destination(&self) -> Option<Ipv4Addr> {
        self.destination
    }

    /// The netmask associated with the interface.
    pub fn netmask(&self) -> Option<Netmask> {
        self.netmask
    }
}

/// Information associated with an interface IPv6 address.
#[derive(Clone, Debug)]
pub struct AddressInfoV6 {
    addr: Ipv6Addr,
    broadcast: Option<Ipv6Addr>,
    destination: Option<Ipv6Addr>,
    netmask: Option<Netmask>,
}

impl AddressInfoV6 {
    /// The IPv6 address associated with the interface.
    pub fn address(&self) -> Ipv6Addr {
        self.addr
    }

    /// The broadcast address associated with the interface.
    pub fn broadcast(&self) -> Option<Ipv6Addr> {
        self.broadcast
    }

    /// The point-to-point destination address associated with the interface.
    pub fn destination(&self) -> Option<Ipv6Addr> {
        self.destination
    }

    /// The netmask associated with the interface.
    pub fn netmask(&self) -> Option<Netmask> {
        self.netmask
    }
}

/// An information type used to add an address and its associated information (desination address,
/// netmask, etc.) to an interface.
#[derive(Clone, Debug)]
pub enum AddAddress {
    V4(AddAddressV4),
    V6(AddAddressV6),
}

impl AddAddress {
    #[inline]
    fn addr(&self) -> IpAddr {
        match self {
            Self::V4(a) => a.addr.into(),
            Self::V6(a) => a.addr.into(),
        }
    }

    #[inline]
    fn brd(&self) -> Option<IpAddr> {
        match self {
            Self::V4(a) => Some(a.brd?.into()),
            Self::V6(a) => Some(a.brd?.into()),
        }
    }

    #[inline]
    fn dst(&self) -> Option<IpAddr> {
        match self {
            Self::V4(a) => Some(a.dst?.into()),
            Self::V6(a) => Some(a.dst?.into()),
        }
    }

    #[inline]
    fn netmask(&self) -> Option<Netmask> {
        match self {
            Self::V4(a) => a.netmask,
            Self::V6(a) => a.netmask,
        }
    }
}

impl From<IpAddr> for AddAddress {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(a) => a.into(),
            IpAddr::V6(a) => a.into(),
        }
    }
}

impl From<Ipv4Addr> for AddAddress {
    fn from(value: Ipv4Addr) -> Self {
        AddAddressV4::new(value).into()
    }
}

impl From<Ipv6Addr> for AddAddress {
    fn from(value: Ipv6Addr) -> Self {
        AddAddressV6::new(value).into()
    }
}

/// An information type used to add an IPv4 address and its associated information (desination
/// address, netmask, etc.) to an interface.
#[derive(Clone, Debug)]
pub struct AddAddressV4 {
    addr: Ipv4Addr,
    brd: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    netmask: Option<Netmask>,
}

impl AddAddressV4 {
    /// Constructs a new `AddAddress` request for the given IPv4 address.
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            brd: None,
            dst: None,
            netmask: None,
        }
    }

    /// Adds an associated broadcast address to the request.
    ///
    /// Note that only one of broadcast and destination addresses may be set for a request; if both
    /// are set, then any invocation of `add_addr()` the request is used for will fail with an error
    /// of kind [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_broadcast(&mut self, addr: Ipv4Addr) {
        self.brd = Some(addr);
    }

    /// Adds an associated destination address to the request.
    ///
    /// Note that only one of broadcast and destination addresses may be set for a request; if both
    /// are set, then any invocation of `add_addr()` the request is used for will fail with an error
    /// of kind [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_destination(&mut self, addr: Ipv4Addr) {
        self.dst = Some(addr);
    }

    /// Adds an associated netmask for the given request.
    ///
    /// The netmask must between 0 and 32 inclusive; if a value outside of this range is used, then
    /// any invocation of `add_addr()` the request is used for will fail with an error of kind
    /// [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_netmask(&mut self, netmask: Netmask) {
        self.netmask = Some(netmask);
    }
}

impl From<AddAddressV4> for AddAddress {
    #[inline]
    fn from(value: AddAddressV4) -> Self {
        AddAddress::V4(value)
    }
}

/// An information type used to add an IPv6 address and its associated information (desination
/// address, netmask, etc.) to an interface.
#[derive(Clone, Debug)]
pub struct AddAddressV6 {
    addr: Ipv6Addr,
    brd: Option<Ipv6Addr>,
    dst: Option<Ipv6Addr>,
    netmask: Option<Netmask>,
}

impl AddAddressV6 {
    /// Constructs a new `AddAddress` request for the given IPv6 address.
    pub fn new(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            brd: None,
            dst: None,
            netmask: None,
        }
    }

    /// Adds an associated broadcast address to the request.
    ///
    /// Note that only one of broadcast and destination addresses may be set for a request; if both
    /// are set, then any invocation of `add_addr()` the request is used for will fail with an error
    /// of kind [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_broadcast(&mut self, addr: Ipv6Addr) {
        self.brd = Some(addr);
    }

    /// Adds an associated destination address to the request.
    ///
    /// Note that only one of broadcast and destination addresses may be set for a request; if both
    /// are set, then any invocation of `add_addr()` the request is used for will fail with an error
    /// of kind [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_destination(&mut self, addr: Ipv6Addr) {
        self.dst = Some(addr);
    }

    /// Adds an associated netmask for the given request.
    ///
    /// The netmask must between 0 and 128 inclusive; if a value outside of this range is used, then
    /// any invocation of `add_addr()` the request is used for will fail with an error of kind
    /// [`io::ErrorKind::InvalidInput`].
    #[inline]
    pub fn set_netmask(&mut self, netmask: Netmask) {
        self.netmask = Some(netmask);
    }
}

impl From<AddAddressV6> for AddAddress {
    #[inline]
    fn from(value: AddAddressV6) -> Self {
        AddAddress::V6(value)
    }
}

/// The device state of an [`Interface`].
///
/// Intefaces can generally be configured to be either up (active) or down (inactive). [`Tun`] and
/// [`Tap`] both allow this state to be set via the [`set_state()`](Tun::set_state) method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    /// An activated device state.
    Up,
    /// A deactivated device state.
    Down,
}

#[cfg(not(target_os = "windows"))]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = libc::IF_NAMESIZE - 1;
#[cfg(target_os = "windows")]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = MAX_ADAPTER_NAME as usize - 1;

/// An identifier associated with a particular network device.
///
/// Network interfaces are not guaranteed to be static; network devices can be added and removed,
/// and in certain circumstances an interface that once pointed to one device may end up pointing
/// to another during the course of a program's lifetime.  Likewise, [`index()`](Interface::index)
/// isn't guaranteed to always return the same index for a given interface as the network device
/// associated to that interface could change between consecutive calls to `name()`/`name_raw()`.
/// Conversely, [`from_index()`](Interface::from_index) may not always return the same interface.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    /// The stored name of the interface.
    #[cfg(not(target_os = "windows"))]
    name: [u8; Self::MAX_INTERFACE_NAME_LEN + 1],
    #[cfg(target_os = "windows")]
    name: [u16; Self::MAX_INTERFACE_NAME_LEN + 1],
    is_catchall: bool,
}

impl Interface {
    // TODO: scope these better

    /// The maximum length (in bytes) that an interface name can be.
    ///
    /// Note that this value is platform-dependent. It determines the size of the buffer used for
    /// storing the interface name in an `Interface` instance, so the size of an `Interface` is
    /// likewise platform-dependent.
    pub const MAX_INTERFACE_NAME_LEN: usize = INTERNAL_MAX_INTERFACE_NAME_LEN;

    /// A special catch-all interface identifier that specifies all operational interfaces.
    ///
    /// Note that this interface is not valid for most contexts--its main purpose is enabling raw
    /// sockets or similar sniffing devices to listen in on traffic from all interfaces at once.
    #[cfg(not(target_os = "windows"))]
    pub fn any() -> io::Result<Self> {
        let name = [0; Self::MAX_INTERFACE_NAME_LEN + 1];

        // Leave the interface name blank since this is the catch-all identifier
        Ok(Self {
            name,
            is_catchall: true,
        })
    }

    /// Constructs an `Interface` from the given interface name.
    ///
    /// `if_name` must not consist of more than
    /// [`MAX_INTERFACE_NAME_LEN`](Self::MAX_INTERFACE_NAME_LEN) bytes of UTF-8 (for *nix
    /// platforms) or, and must not contain any null characters.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if `if_name` is longer than the maximum
    /// number of bytes or contains a null character.
    #[inline]
    pub fn new(if_name: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::new_inner(if_name)
    }

    /// Constructs an `Interface` from the given C string.
    ///
    /// `if_name` must not consist of more than
    /// [`MAX_INTERFACE_NAME_LEN`](Self::MAX_INTERFACE_NAME_LEN) bytes.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if `if_name` is longer than the maximum
    /// number of bytes.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn from_cstr(if_name: &CStr) -> io::Result<Self> {
        Self::new_raw(if_name.to_bytes())
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(unused)]
    pub(crate) unsafe fn from_raw(arr: [u8; Self::MAX_INTERFACE_NAME_LEN + 1]) -> Self {
        Self {
            name: arr,
            is_catchall: false,
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn new_inner(if_name: impl AsRef<OsStr>) -> io::Result<Self> {
        let mut utf16 = if_name.as_ref().encode_wide();
        let name = array::from_fn(|_| utf16.next().unwrap_or(0));

        let interface = Interface {
            name,
            is_catchall: false,
        };

        Ok(interface)
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn new_inner(if_name: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::new_raw(if_name.as_ref().as_bytes())
    }

    // TODO: this should be `from_slice`
    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn new_raw(if_name: &[u8]) -> io::Result<Self> {
        if if_name.len() > Self::MAX_INTERFACE_NAME_LEN || if_name.contains(&0x00) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed interface name",
            ));
        }

        let mut name_iter = if_name.iter();
        let name = array::from_fn(|_| name_iter.next().cloned().unwrap_or(0));

        Ok(Interface {
            name,
            is_catchall: false,
        })
    }

    /*
    /// Find all available interfaces on the given machine.
    pub fn find_all() -> io::Result<Vec<Self>> {

    }
    */

    /// Returns the `Interface` corresponding to the given interface index.
    ///
    /// # Errors
    ///
    /// Any returned error indicates that `if_index` does not correspond to a valid interface.
    #[inline]
    #[cfg(not(target_os = "windows"))]
    pub fn from_index(if_index: u32) -> io::Result<Self> {
        // TODO: do Unix systems other than Linux actually consider '0' to be a catch-all?
        if if_index == 0 {
            return Self::any();
        }

        let mut name = [0u8; Self::MAX_INTERFACE_NAME_LEN + 1];
        match unsafe { libc::if_indextoname(if_index, name.as_mut_ptr() as *mut i8) } {
            ptr if ptr.is_null() => Err(io::Error::last_os_error()),
            _ => Ok(Self {
                name,
                is_catchall: false,
            }),
        }
    }

    /// Indicates whether the interface can currently be found on the system.
    #[inline]
    pub fn exists(&self) -> io::Result<bool> {
        match self.index() {
            Ok(_) => Ok(true),
            Err(e) => {
                let not_found = e.kind() == io::ErrorKind::NotFound;

                #[cfg(target_os = "linux")]
                let not_found_sys = e.raw_os_error() == Some(libc::ENODEV);
                #[cfg(target_os = "windows")]
                let not_found_sys = false;
                #[cfg(target_os = "macos")]
                let not_found_sys = e.raw_os_error() == Some(libc::ENXIO);
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                let not_found_sys = e.raw_os_error() == Some(libc::ENXIO);

                if not_found || not_found_sys {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Retrieves the associated interface index of the network interface.
    #[inline]
    pub fn index(&self) -> io::Result<u32> {
        self.index_impl()
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn index_impl(&self) -> io::Result<u32> {
        match unsafe { libc::if_nametoindex(self.name.as_ptr() as *const i8) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(i),
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn index_impl(&self) -> io::Result<u32> {
        let mut index = 0u32;
        match unsafe { GetAdapterIndex(self.name.as_ptr(), ptr::addr_of_mut!(index)) } {
            0 => Ok(index),
            ERROR_DEV_NOT_EXIST | ERROR_NO_DATA => Err(io::ErrorKind::NotFound.into()),
            e => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("GetAdapterIndex returned error {}", e),
            )),
        }
    }

    // TODO: If the above doesn't work, use ConvertInterfaceNameToLuidA (or else get the LUID
    // directly) and `ConvertInterfaceLuidToIndex`

    /// Retrieves the name of the interface.
    pub fn name(&self) -> OsString {
        self.name_impl()
    }

    #[cfg(not(target_os = "windows"))]
    fn name_impl(&self) -> OsString {
        let length = self.name.iter().position(|c| *c == 0).unwrap();
        OsStr::from_bytes(&self.name[..length]).to_owned()
    }

    #[cfg(target_os = "windows")]
    fn name_impl(&self) -> OsString {
        let length = self.name.iter().position(|c| *c == 0).unwrap();
        OsString::from_wide(&self.name[..length])
    }

    /// Returns the interface name as an array of bytes (i.e. unsigned 8-bit integers).
    #[cfg(not(target_os = "windows"))]
    pub fn name_raw(&self) -> [u8; Self::MAX_INTERFACE_NAME_LEN + 1] {
        self.name
    }

    /// Returns the interface name as an array of `char` bytes (i.e. signed 8-bit integers).
    #[cfg(any(doc, not(target_os = "windows")))]
    pub fn name_raw_i8(&self) -> [i8; Self::MAX_INTERFACE_NAME_LEN + 1] {
        array::from_fn(|i| self.name[i] as i8)
    }

    /// Returns the name associated with the given interface in C-string format.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if the name assigned to the interface is
    /// not valid UTF-8.
    ///
    /// Otherwise, a returned error indicates that [`Interface`] does not correspond to a valid
    /// interface.
    #[cfg(any(doc, not(target_os = "windows")))]
    #[inline]
    pub fn name_cstr(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.name.as_ptr() as *const i8) }
    }

    // An interface may have multiple assigned IP addresses. This is referred to as multihoming (see
    // https://en.wikipedia.org/wiki/Multihoming).

    #[cfg(any(doc, not(target_os = "windows")))]
    #[inline]
    pub(crate) fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.addrs_impl() // GetAdaptersAddresses for Windows
    }

    #[cfg(target_os = "linux")]
    fn addrs_impl(&self) -> io::Result<Vec<AddressInfo>> {
        let index = self.index()?;
        let mut addrs = Vec::new();

        // TODO: in the future we could make this more efficient by reusing the same NL socket.
        // However, it looks like doing so is non-trivial; simply pulling out the socket creation
        // from this loop causes an unexpected bug in message parsing.
        for ifa_family in [libc::AF_INET, libc::AF_INET6] {
            let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let req = NetlinkRequest {
                flags: (libc::NLM_F_REQUEST | libc::NLM_F_ROOT) as u16,
                seq: 1,
                pid: 0,
                payload: rtnetlink::NlmsgPayload::GetAddress(NlmsgGetAddress {
                    family: ifa_family as u8,
                    prefix_length: 0u8,
                    flags: 0u8,
                    scope: 0u8,
                    iface_idx: index,
                }),
            };

            let req_bytes = req.serialize();

            let ret = unsafe {
                libc::send(
                    fd,
                    req_bytes.as_ptr() as *const libc::c_void,
                    req_bytes.len(),
                    0,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                Self::close_fd(fd);
                return Err(err);
            }

            let mut buf = Vec::<u8>::new();
            buf.reserve_exact(NETLINK_MAX_RECV);

            let len = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    NETLINK_MAX_RECV,
                    0,
                )
            };
            if len < 0 {
                let err = io::Error::last_os_error();
                Self::close_fd(fd);
                return Err(err);
            }

            unsafe {
                buf.set_len(len as usize);
            }

            Self::close_fd(fd);

            let resp = NetlinkResponseRef::new(&buf);

            for msg in resp.messages() {
                match msg?.payload() {
                    NlmsgPayloadRef::Error(e) => {
                        return Err(io::Error::from_raw_os_error(e.errno()))
                    }
                    NlmsgPayloadRef::GetAddress(a) => {
                        if a.family() as i32 != ifa_family {
                            continue;
                        }

                        if a.index() != index {
                            continue;
                        }

                        let mut dst = None;
                        let netmask = Some(a.prefix_len());
                        let mut addr = None;
                        let mut brd = None;

                        for attr in a.attrs() {
                            match attr? {
                                AddressAttrRef::Address(a) => {
                                    if ifa_family == libc::AF_INET && !a.is_ipv4() {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "netlink RTM_GETADDR returned incorrect address family",
                                        ));
                                    }
                                    dst = Some(a);
                                }
                                AddressAttrRef::Local(a) => {
                                    if ifa_family == libc::AF_INET && !a.is_ipv4() {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "netlink RTM_GETADDR returned incorrect address family",
                                        ));
                                    }
                                    addr = Some(a);
                                }
                                AddressAttrRef::Label(_) => (),
                                AddressAttrRef::Broadcast(b) => {
                                    if ifa_family == libc::AF_INET && !b.is_ipv4() {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "netlink RTM_GETADDR returned incorrect address family",
                                        ));
                                    }
                                    brd = Some(b);
                                }
                                AddressAttrRef::Anycast(_) => (),
                                AddressAttrRef::CacheInfo(_) => (),
                                AddressAttrRef::Unspecified(_) => (),
                                AddressAttrRef::Unknown(_, _) => (),
                            }
                        }

                        if dst.is_some() && addr.is_none() {
                            // TODO: see https://stackoverflow.com/questions/39640716/filter-ipv6-local-address-using-netlink
                            addr = dst;
                        }

                        if let Some(ip_addr) = addr {
                            match ip_addr {
                                IpAddr::V4(addr) => {
                                    let broadcast = match brd {
                                        Some(IpAddr::V4(a)) => Some(a),
                                        _ => None,
                                    };

                                    let destination = match dst {
                                        Some(IpAddr::V4(a)) => Some(a),
                                        _ => None,
                                    };

                                    addrs.push(AddressInfo::V4(AddressInfoV4 {
                                        addr,
                                        broadcast,
                                        destination,
                                        netmask,
                                    }));
                                }
                                IpAddr::V6(addr) => {
                                    let broadcast = match brd {
                                        Some(IpAddr::V6(a)) => Some(a),
                                        _ => None,
                                    };

                                    let destination = match dst {
                                        Some(IpAddr::V6(a)) => Some(a),
                                        _ => None,
                                    };

                                    addrs.push(AddressInfo::V6(AddressInfoV6 {
                                        addr,
                                        broadcast,
                                        destination,
                                        netmask,
                                    }));
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }

        Ok(addrs)
    }

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn addrs_impl(&self) -> io::Result<Vec<AddressInfo>> {
        const MEMORY_MIN: usize = 2048;
        const MEMORY_MAX: usize = 16777216;

        // First, get the index of the interface
        let if_index = self.index()?;
        let mut addrs = Vec::new();

        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_UNSPEC, // address family
            libc::NET_RT_IFLIST,
            if_index as i32,
        ];

        let mut needed: libc::size_t = 0;

        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                ptr::null_mut(),
                ptr::addr_of_mut!(needed),
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut needed = needed as usize;
        needed = cmp::max(needed, MEMORY_MIN);
        needed = cmp::min(needed + (needed >> 1), MEMORY_MAX);
        // 50% more than what the kernel suggested should be plenty

        let mut buf: Vec<u8> = Vec::with_capacity(needed);
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let mut buflen: libc::size_t = needed;

        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf_ptr,
                ptr::addr_of_mut!(buflen),
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            buf.set_len(buflen as usize);
        }

        let if_list = IfList::new(buf.as_slice());
        for message in if_list {
            match message? {
                SysctlMessage::NewAddress(new_addr) => {
                    let mut dst = None;
                    let mut mask = None;
                    let mut addr = None;
                    let mut brd = None;

                    for ip_addr in new_addr.addrs() {
                        match ip_addr? {
                            SysctlAddr::Destination(a) => dst = Some(a),
                            SysctlAddr::Gateway(_) => (),
                            SysctlAddr::Netmask(a) => mask = Some(a),
                            SysctlAddr::Address(a) => addr = Some(a),
                            SysctlAddr::Broadcast(a) => brd = Some(a),
                            SysctlAddr::Other => (),
                        }
                    }

                    if let Some(ip_addr) = addr {
                        match ip_addr {
                            IpAddr::V4(addr) => {
                                let broadcast = match brd {
                                    Some(IpAddr::V4(a)) => Some(a),
                                    _ => None,
                                };

                                let destination = match dst {
                                    Some(IpAddr::V4(a)) => Some(a),
                                    _ => None,
                                };

                                let netmask = match mask {
                                    Some(IpAddr::V4(a)) => {
                                        Some(32u8 - u32::from(a).trailing_zeros() as u8)
                                    }
                                    _ => None,
                                };

                                addrs.push(AddressInfo::V4(AddressInfoV4 {
                                    addr,
                                    broadcast,
                                    destination,
                                    netmask,
                                }));
                            }
                            IpAddr::V6(addr) => {
                                let broadcast = match brd {
                                    Some(IpAddr::V6(a)) => Some(a),
                                    _ => None,
                                };

                                let destination = match dst {
                                    Some(IpAddr::V6(a)) => Some(a),
                                    _ => None,
                                };

                                let netmask = match mask {
                                    Some(IpAddr::V6(a)) => {
                                        Some(128u8 - u128::from(a).trailing_zeros() as u8)
                                    }
                                    _ => None,
                                };

                                addrs.push(AddressInfo::V6(AddressInfoV6 {
                                    addr,
                                    broadcast,
                                    destination,
                                    netmask,
                                }));
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        Ok(addrs)
    }

    /// Assigns an IP address to the given interface.
    ///
    /// # Portability
    ///
    /// MacOS, FreeBSD and DragonFlyBSD all require a destination address when assigning an IPv4
    /// address to a TUN device.
    ///
    /// MacOS additionally requires a destination address when assigning an IPv6 address to a TUN
    /// device. Neither FreeBSD nor DragonFlyBSD include this restriction.
    ///
    /// Most platforms automatically assign a link-local IPv6 address to a newly created TAP device.
    /// No platforms assign link-local IPv6 addresses to TUN devices on creation. However, OpenBSD
    /// will assign a link-local IPv6 address the moment you try to assign some other IPv6 address.
    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub(crate) fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.add_addr_impl(req.into())
    }

    // See the following for Netlink examples:
    // https://olegkutkov.me/2018/02/14/monitoring-linux-networking-state-using-netlink/

    #[cfg(target_os = "linux")]
    fn add_addr_impl(&self, req: AddAddress) -> io::Result<()> {
        let index = self.index()?;
        // BUG: netmask unused

        let (family, default_prefixlen) = match req {
            AddAddress::V4(_) => (libc::AF_INET, 32),
            AddAddress::V6(_) => (libc::AF_INET6, 64),
        };
        let prefixlen = req.netmask().unwrap_or(default_prefixlen);

        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let local = sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let local_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        if unsafe { libc::bind(fd, ptr::addr_of!(local) as *const libc::sockaddr, local_len) } < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        let mut attrs = vec![AddressAttr::Local(req.addr())];
        if let Some(brd) = req.brd() {
            attrs.push(AddressAttr::Broadcast(brd));
        }

        if let Some(dst) = req.dst() {
            attrs.push(AddressAttr::Address(dst));
        }

        let nlreq = NetlinkRequest {
            flags: (libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_REQUEST | libc::NLM_F_ACK)
                as u16,
            seq: 1,
            pid: 0,
            payload: NlmsgPayload::NewAddress(NlmsgNewAddress {
                family: family as u8,
                prefix_length: prefixlen,
                flags: 0u8,
                scope: 0u8,
                iface_idx: index,
                attrs,
            }),
        };

        let mut req_bytes = nlreq.serialize();

        let mut iov = libc::iovec {
            iov_base: req_bytes.as_mut_ptr() as *mut libc::c_void,
            iov_len: req_bytes.len(),
        };

        let mut dst_addr = sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        let msg = libc::msghdr {
            msg_name: ptr::addr_of_mut!(dst_addr) as *mut libc::c_void,
            msg_namelen: mem::size_of::<libc::sockaddr_nl>() as u32,
            msg_iov: ptr::addr_of_mut!(iov),
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let res = unsafe { libc::sendmsg(fd, ptr::addr_of!(msg), 0) };
        if res < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        let mut buf = Vec::<u8>::new();
        buf.reserve_exact(NETLINK_MAX_RECV);

        let len = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                NETLINK_MAX_RECV,
                0,
            )
        };
        if len < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        unsafe {
            buf.set_len(len as usize);
        }

        Self::close_fd(fd);

        let resp = NetlinkResponseRef::new(buf.as_slice());
        let msg = resp.messages().next().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink ADD_ADDR request returned no response",
        ))??;
        match msg.payload() {
            NlmsgPayloadRef::Error(e) => {
                if e.errno() == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(e.errno()))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "netlink ADD_ADDR request returned unexpected response type",
            )),
        }
    }

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn add_addr_impl(&self, req: AddAddress) -> io::Result<()> {
        match req {
            AddAddress::V4(v4_req) => {
                let netmask = match 32u8.checked_sub(v4_req.netmask.unwrap_or(32)) {
                    Some(32) => 0,
                    Some(mask) => (u32::MAX >> mask) << mask,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "netmask must be between 0 and 32 for IPv4 addresses",
                        ))
                    }
                };

                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u8,
                    sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(v4_req.addr).to_be(),
                    },
                    sin_zero: [0; 8],
                };

                let ifra_broadaddr =
                    match (v4_req.brd, v4_req.dst) {
                        (Some(_), Some(_)) => return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "AddAddress request cannot contain both broadcast and destination addr",
                        )),
                        (None, Some(addr)) | (Some(addr), None) => libc::sockaddr_in {
                            sin_family: libc::AF_INET as u8,
                            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                            sin_port: 0,
                            sin_addr: libc::in_addr {
                                s_addr: u32::from(addr).to_be(),
                            },
                            sin_zero: [0; 8],
                        },
                        (None, None) => libc::sockaddr_in {
                            sin_family: 0,
                            sin_len: 0,
                            sin_port: 0,
                            sin_addr: libc::in_addr { s_addr: 0 },
                            sin_zero: [0; 8],
                        },
                    };

                let mut req = ifaliasreq {
                    ifra_name: self.name_raw_i8(),
                    #[cfg(not(target_os = "openbsd"))]
                    ifra_addr: addr,
                    #[cfg(target_os = "openbsd")]
                    ifra_ifrau: __c_anonymous_ifra_ifrau { ifrau_addr: addr },
                    ifra_broadaddr,
                    ifra_mask: libc::sockaddr_in {
                        sin_family: libc::AF_INET as u8,
                        sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                        sin_port: 0,
                        sin_addr: libc::in_addr {
                            s_addr: netmask.to_be(),
                        },
                        sin_zero: [0; 8],
                    },
                    #[cfg(target_os = "freebsd")]
                    ifra_vhid: 0,
                };

                let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if inet_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                unsafe {
                    match libc::ioctl(inet_fd, SIOCAIFADDR, ptr::addr_of_mut!(req)) {
                        0 => {
                            libc::close(inet_fd);
                            Ok(())
                        }
                        _ => {
                            let err = io::Error::last_os_error();
                            libc::close(inet_fd);
                            Err(err)
                        }
                    }
                }
            }
            AddAddress::V6(v6_req) => {
                let netmask = match 128u8.checked_sub(v6_req.netmask.unwrap_or(64)) {
                    Some(128) => 0u128.to_be_bytes(),
                    Some(mask) => ((u128::MAX >> mask) << mask).to_be_bytes(),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "netmask must be between 0 and 32 for IPv4 addresses",
                        ))
                    }
                };

                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u8,
                    sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: u128::from(v6_req.addr).to_be_bytes(),
                    },
                    sin6_scope_id: 0,
                };

                let ifra_broadaddr =
                    match (v6_req.brd, v6_req.dst) {
                        (Some(_), Some(_)) => return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "AddAddress request cannot contain both broadcast and destination addr",
                        )),
                        (None, Some(addr)) | (Some(addr), None) => libc::sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as u8,
                            sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                            sin6_port: 0,
                            sin6_flowinfo: 0,
                            sin6_addr: libc::in6_addr {
                                s6_addr: u128::from(addr).to_be_bytes(),
                            },
                            sin6_scope_id: 0,
                        },
                        (None, None) => libc::sockaddr_in6 {
                            sin6_family: 0,
                            sin6_len: 0,
                            sin6_port: 0,
                            sin6_flowinfo: 0,
                            sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
                            sin6_scope_id: 0,
                        },
                    };

                let mut req = in6_aliasreq {
                    ifra_name: self.name_raw_i8(),
                    #[cfg(not(target_os = "openbsd"))]
                    ifra_addr: addr,
                    #[cfg(target_os = "openbsd")]
                    ifra_ifrau: __c_anonymous_in6_ifra_ifrau { ifrau_addr: addr },
                    ifra_broadaddr,
                    ifra_prefixmask: libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as u8,
                        sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr { s6_addr: netmask },
                        sin6_scope_id: 0,
                    },
                    ifra_flags: 0,
                    ifra_lifetime: in6_addrlifetime {
                        ia6t_expire: 0,
                        ia6t_preferred: 0,
                        ia6t_vltime: ND6_INFINITE_LIFETIME,
                        ia6t_pltime: ND6_INFINITE_LIFETIME,
                    },
                    #[cfg(target_os = "freebsd")]
                    ifra_vhid: 0,
                };

                let inet6_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
                if inet6_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                unsafe {
                    match libc::ioctl(inet6_fd, SIOCAIFADDR_IN6, ptr::addr_of_mut!(req)) {
                        0 => {
                            libc::close(inet6_fd);
                            Ok(())
                        }
                        _ => {
                            let err = io::Error::last_os_error();
                            libc::close(inet6_fd);
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub(crate) fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.remove_addr_impl(addr)
    }

    #[cfg(target_os = "linux")]
    fn remove_addr_impl(&self, addr: IpAddr) -> io::Result<()> {
        let index = self.index()?;
        // BUG: netmask unused

        let (family, prefixlen) = match addr {
            IpAddr::V4(_) => (libc::AF_INET, 32),
            IpAddr::V6(_) => (libc::AF_INET6, 64),
        };

        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let local = sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let local_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        if unsafe { libc::bind(fd, ptr::addr_of!(local) as *const libc::sockaddr, local_len) } < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        let req = NetlinkRequest {
            flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            seq: 1,
            pid: 0,
            payload: NlmsgPayload::DeleteAddress(NlmsgDeleteAddress {
                family: family as u8,
                prefix_length: prefixlen,
                flags: 0u8,
                scope: 0u8,
                iface_idx: index,
                attrs: vec![AddressAttr::Local(addr)],
            }),
        };

        let mut req_bytes = req.serialize();

        let mut iov = libc::iovec {
            iov_base: req_bytes.as_mut_ptr() as *mut libc::c_void,
            iov_len: req_bytes.len(),
        };

        let mut dst_addr = sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        let msg = libc::msghdr {
            msg_name: ptr::addr_of_mut!(dst_addr) as *mut libc::c_void,
            msg_namelen: mem::size_of::<libc::sockaddr_nl>() as u32,
            msg_iov: ptr::addr_of_mut!(iov),
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let res = unsafe { libc::sendmsg(fd, ptr::addr_of!(msg), 0) };
        if res < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        let mut buf = Vec::<u8>::new();
        buf.reserve_exact(NETLINK_MAX_RECV);

        let len = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                NETLINK_MAX_RECV,
                0,
            )
        };
        if len < 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(fd);
            return Err(err);
        }

        unsafe {
            buf.set_len(len as usize);
        }

        Self::close_fd(fd);

        let resp = NetlinkResponseRef::new(buf.as_slice());
        let msg = resp.messages().next().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink DEL_ADDR request returned no response",
        ))??;
        match msg.payload() {
            NlmsgPayloadRef::Error(e) => {
                if e.errno() == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(e.errno()))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "netlink DEL_ADDR request returned unexpected response type",
            )),
        }
    }

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn remove_addr_impl(&self, addr: IpAddr) -> io::Result<()> {
        match addr {
            IpAddr::V4(v4_addr) => {
                let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if inet_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u8,
                    sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(v4_addr).to_be(),
                    },
                    sin_zero: [0; 8],
                };

                let addr: libc::sockaddr = unsafe { mem::transmute(addr) };

                let mut req = ifreq {
                    ifr_name: self.name_raw_i8(),
                    ifr_ifru: __c_anonymous_ifr_ifru { ifru_addr: addr },
                };

                unsafe {
                    match libc::ioctl(inet_fd, SIOCDIFADDR, ptr::addr_of_mut!(req)) {
                        0 => {
                            libc::close(inet_fd);
                            Ok(())
                        }
                        _ => {
                            let err = io::Error::last_os_error();
                            libc::close(inet_fd);
                            Err(err)
                        }
                    }
                }
            }
            IpAddr::V6(v6_addr) => {
                let inet6_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
                if inet6_fd < 0 {
                    return Err(io::Error::last_os_error());
                }

                let s6_addr: [u8; 16] = u128::from(v6_addr).to_be_bytes();

                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u8,
                    sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr },
                    sin6_scope_id: 0,
                };

                let mut req = in6_ifreq {
                    ifr_name: self.name_raw_i8(),
                    ifr_ifru: __c_anonymous_in6_ifr_ifru { ifru_addr: addr },
                };

                unsafe {
                    match libc::ioctl(inet6_fd, SIOCDIFADDR_IN6, ptr::addr_of_mut!(req)) {
                        0 => {
                            libc::close(inet6_fd);
                            Ok(())
                        }
                        _ => {
                            let err = io::Error::last_os_error();
                            libc::close(inet6_fd);
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

/// A MAC (Media Access Control) address.
#[derive(Clone)]
pub struct MacAddr {
    addr: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(value: [u8; 6]) -> Self {
        Self { addr: value }
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(value: MacAddr) -> Self {
        value.addr
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacAddress")
            .field(
                "addr",
                &format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    self.addr[0],
                    self.addr[1],
                    self.addr[2],
                    self.addr[3],
                    self.addr[4],
                    self.addr[5]
                ),
            )
            .finish()
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = AddrConversionError; // TODO: change to MacAddrParseError?

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        let mut addr_idx = 0;

        if let Some(delim @ (b':' | b'-')) = s.as_bytes().get(2) {
            // Hexadecimal separated by colons (XX:XX:XX:XX:XX:XX) or dashes (XX-XX-XX-XX-XX-XX)

            if s.bytes().len() != 17 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod3_idx = idx % 3;
                if (mod3_idx) == 2 {
                    if b != *delim {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected colon/dash",
                        ));
                    }
                    addr_idx += 1;
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod3_idx == 0 {
                        b <<= 4;
                    }

                    addr[addr_idx] |= b;
                }
            }
        } else if let Some(b'.') = s.as_bytes().get(4) {
            // Hexadecimal separated by dots (XXXX.XXXX.XXXX)

            if s.bytes().len() != 14 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod5_idx = idx % 5;
                if (mod5_idx) == 4 {
                    if b != b'.' {
                        return Err(AddrConversionError::new("invalid character in MAC address: expected '.' after four hexadecimal values"));
                    }
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod5_idx & 0b1 == 0 {
                        // Evens, i.e. every first hex value in a byte
                        addr[addr_idx] = b << 4;
                    } else {
                        // Odds, i.e. every 2nd hex value
                        addr[addr_idx] |= b;
                        addr_idx += 1;
                    }
                }
            }
        } else {
            // Unseparated hexadecimal (XXXXXXXXXXXX)

            if s.bytes().len() != 12 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                b = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => 10 + (b - b'a'),
                    b'A'..=b'F' => 10 + (b - b'A'),
                    _ => {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected hexadecimal value",
                        ))
                    }
                };

                let even_bit = (idx & 0b1) == 0;

                if even_bit {
                    // Evens, i.e. every first hex value in a byte
                    addr[addr_idx] = b << 4;
                } else {
                    // Odds, i.e. every 2nd hex value
                    addr[addr_idx] |= b;
                    addr_idx += 1;
                }
            }
        }

        Ok(Self { addr })
    }
}

/// An error in converting data into a MAC address.
///
/// This type encompasses errors in parsing either a `sockaddr_*` type or a string into an address.
#[derive(Debug)]
pub struct AddrConversionError {
    reason: &'static str,
}

impl AddrConversionError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a string describing the nature of the conversion error.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.reason
    }
}
