// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::{array, cmp, io, mem, ptr};

use crate::libc_extra::*;
use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface, MacAddr};

const BPF_BUFFER_LEN: i32 = 131072;

/// Fake Ethernet ("feth") TAP device interface that includes MacOS-specific functionality.
///
/// Apple does not support conventional TAP APIs, so this implementation instead uses the somewhat
/// undocumented `IF_FAKE` or "feth" interface to act as a link-layer virtual network.
pub struct FethTap {
    bpf: File,
}

impl FethTap {
    /// Creates a new TAP device.
    ///
    /// The interface name associated with this TAP device will be "feth" with a device number
    /// appended (e.g. "feth0", "feth1"), and can be retrieved via the [`name()`](Self::name)
    /// method.
    pub fn create() -> io::Result<()> {
        Self::create_named(None, None)
    }

    // BIOCSETLIF to lock bpf to specific feth sink

    /// Creates a new TAP device using the specified interface numbers for the `feth` devices.
    ///
    /// MacOS requires that a pair of `feth` devices be created in order to mimic TAP behavior.
    /// These devices are paired to one another; one device is used as a virtual interface, while
    /// the other is used to actually read and write packets. A call to [`new()`](Self::new)
    /// normally assigns the two lowest available interface numbers to these devices; this method
    /// may instead be used to manually assign interface numbers. If one or both of the interface
    /// numbers is already being used (or is otherwise unavailable), this method will return an
    /// error.
    pub fn create_numbered(
        adapter_if_number: Option<u32>,
        sink_if_number: Option<u32>,
    ) -> io::Result<()> {
        let iface = match adapter_if_number {
            Some(n) => Some(Interface::new_raw(format!("feth{}", n).as_bytes())?),
            None => None,
        };

        let peer_iface = match sink_if_number {
            Some(n) => Some(Interface::new_raw(format!("feth{}", n).as_bytes())?),
            None => None,
        };

        Self::create_named(iface, peer_iface)
    }

    /// Creates a new TAP device using the specified interface names for the `feth` devices.
    ///
    /// MacOS requires that a pair of `feth` devices be created in order to mimic TAP behavior.
    /// These devices are paired to one another; one device is used as an adapter interface, while
    /// the other is used as a sink to actually read and write packets. A call to [`new()`](Self::new)
    /// normally assigns the two lowest available interface numbers to these devices; this method
    /// may instead be used to manually assign interface numbers. If one or both of the interface
    /// numbers is already being used (or is otherwise unavailable), this method will return an
    /// error.
    pub fn create_named(
        adapter_if_name: Option<Interface>,
        sink_if_name: Option<Interface>,
    ) -> io::Result<()> {
        let mut adapter_if_name = adapter_if_name.unwrap_or(Interface::new_raw(b"feth")?);
        let mut sink_if_name = sink_if_name.unwrap_or(Interface::new_raw(b"feth")?);

        /*
        if &adapter_if_name.name_raw()[..4] != b"feth" || !adapter_if_name.name_raw()[4].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied iface was not a `feth` interface",
            ));
        }

        if &sink_if_name.name_raw()[..4] != b"feth" || !adapter_if_name.name_raw()[4].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied peer_iface was not a `feth` interface",
            ));
        }
        */

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        // TODO: set O_CLOEXEC on this and all other sockets

        let mut req = libc::ifreq {
            ifr_name: adapter_if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        // SIOCIFCREATE2 is of no effect for `feth` sockets, so we don't use it?
        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFCREATE, &raw mut req) } < 0 {
            let e = io::Error::last_os_error();
            return Err(e);
        }

        adapter_if_name = unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) };

        // Create the peer `feth` device
        req.ifr_name = sink_if_name.name_raw_char();

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFCREATE, &raw mut req) } < 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(sockfd.as_raw_fd(), adapter_if_name);
            return Err(err);
        }

        sink_if_name = unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) };

        // Peer the two devices together

        let mut fake_req = if_fake_request {
            iffr_reserved: [0u64; 4],
            iffr_u: __c_anonymous_iffr_u {
                iffru_peer_name: sink_if_name.name_raw_char(),
            },
        };

        let mut spec = ifdrv {
            ifd_name: adapter_if_name.name_raw_char(),
            ifd_cmd: IF_FAKE_S_CMD_SET_PEER,
            ifd_len: mem::size_of_val(&fake_req),
            ifd_data: (&raw mut fake_req).cast(),
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSDRVSPEC, &raw mut spec) } != 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(sockfd.as_raw_fd(), adapter_if_name);
            Self::destroy_iface(sockfd.as_raw_fd(), sink_if_name);
            return Err(err);
        }

        Ok(())
    }

    pub(crate) fn new_compat(device_num: u32) -> io::Result<Self> {
        match Self::create_numbered(Some(device_num), None) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        Self::open(device_num)
    }

    pub fn exists(if_name: Interface) -> io::Result<bool> {
        if &if_name.name_raw()[..4] != b"feth" || !if_name.name_raw()[4].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-TUN interface name provided",
            ));
        }

        let mut req = ifreq {
            ifr_name: if_name.name_raw_char(),
            ifr_ifru: __c_anonymous_ifr_ifru {
                ifru_data: ptr::null_mut(),
            },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } == 0 {
            return Ok(true);
        }

        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENXIO)) {
            Ok(false)
        } else {
            Err(err)
        }
    }

    pub fn exists_numbered(device_num: u32) -> io::Result<bool> {
        Self::exists(Interface::new_raw(
            format!("feth{}", device_num).as_bytes(),
        )?)
    }

    pub fn open(device_num: u32) -> io::Result<Self> {
        let if_name = Interface::new(format!("feth{}", device_num)).unwrap();
        Self::open_named(if_name)
    }

    pub fn open_named(if_name: Interface) -> io::Result<Self> {
        if &if_name.name_raw()[..4] != b"feth" || !if_name.name_raw()[4].is_ascii_digit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied if_name was not a feth interface",
            ));
        }

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut ifreq = if_fake_request {
            iffr_reserved: [0u64; 4],
            iffr_u: __c_anonymous_iffr_u {
                iffru_peer_name: [0i8; libc::IFNAMSIZ],
            },
        };

        let mut ifd = ifdrv {
            ifd_name: if_name.name_raw_char(),
            ifd_cmd: IF_FAKE_G_CMD_GET_PEER,
            ifd_len: mem::size_of_val(&ifreq),
            ifd_data: (&raw mut ifreq).cast(),
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), libc::SIOCGDRVSPEC, &raw mut ifd) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let sink_if_name =
            unsafe { Interface::from_raw(ifreq.iffr_u.iffru_peer_name.map(|i| i as u8)) };

        if sink_if_name.name_cstr() == c"" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied feth interface has no peer",
            ));
        }

        let mut sink_req = libc::ifreq {
            ifr_name: sink_if_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut bpf_idx = 0;
        let bpf = loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/dev/bpf{}", bpf_idx))
            {
                Ok(file) => break file,
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                    bpf_idx += 1;
                    if bpf_idx >= 1024 {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        };

        let mut enable = 1i32;
        let mut disable = 0i32;
        let mut buffer_len = BPF_BUFFER_LEN; // TODO: make configurable?

        // Sets the length of the buffer that will be used for subsequent `read()`s
        if unsafe {
            libc::ioctl(
                bpf.as_raw_fd(),
                libc::BIOCSBLEN,
                ptr::addr_of_mut!(buffer_len),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        // Have reads return immediately when packets are received
        // TODO: make configurable?
        if unsafe {
            libc::ioctl(
                bpf.as_raw_fd(),
                libc::BIOCIMMEDIATE,
                ptr::addr_of_mut!(enable),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        // Don't sniff packets that were sent out on the interface
        if unsafe {
            libc::ioctl(
                bpf.as_raw_fd(),
                libc::BIOCGSEESENT,
                ptr::addr_of_mut!(disable),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        // Set BPF socket to be listening on to the peer `feth` interface
        if unsafe { libc::ioctl(bpf.as_raw_fd(), libc::BIOCSETIF, &raw mut sink_req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Disable network-layer header rewriting on the interface output routine
        if unsafe { libc::ioctl(bpf.as_raw_fd(), libc::BIOCSHDRCMPLT, &raw mut enable) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Do receive packets even if they're not addressed specifically to the interface's
        // associated address
        if unsafe { libc::ioctl(bpf.as_raw_fd(), libc::BIOCPROMISC as u64, &raw mut enable) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { bpf })
    }

    /// Determines whether Link Receive Offload (LRO) is enabled for all TAP (feth) devices.
    pub fn lro() -> io::Result<bool> {
        let mut lro = 0u32;
        let mut lro_len = mem::size_of_val(&lro);

        unsafe {
            match libc::sysctlbyname(
                c"net.link.fake.lro".as_ptr(),
                (&raw mut lro).cast(),
                &raw mut lro_len,
                ptr::null_mut(),
                0,
            ) {
                0 => Ok(lro > 0),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Enables or disables Link Receive Offload for all TAP (feth) devices.
    pub fn set_lro(lro_enabled: bool) -> io::Result<()> {
        let mut lro = match lro_enabled {
            true => 1i32,
            false => 0i32,
        };

        unsafe {
            match libc::sysctlbyname(
                c"net.link.fake.lro".as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                (&raw mut lro).cast(),
                mem::size_of_val(&lro),
            ) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the primary `feth` interface name associated with the TAP device.
    pub fn name(&self) -> io::Result<Interface> {
        let sink_name = self.sink_name()?;

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut ifreq = if_fake_request {
            iffr_reserved: [0u64; 4],
            iffr_u: __c_anonymous_iffr_u {
                iffru_peer_name: [0i8; libc::IFNAMSIZ],
            },
        };

        let mut ifd = ifdrv {
            ifd_name: sink_name.name_raw_char(),
            ifd_cmd: IF_FAKE_G_CMD_GET_PEER,
            ifd_len: mem::size_of_val(&ifreq),
            ifd_data: (&raw mut ifreq).cast(),
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGDRVSPEC, &raw mut ifd) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { Interface::from_raw(ifreq.iffr_u.iffru_peer_name.map(|c| c as u8)) })
    }

    /// Returns the sink `feth` interface name associated with the TAP device.
    pub fn sink_name(&self) -> io::Result<Interface> {
        let mut req = libc::ifreq {
            ifr_name: [0i8; libc::IFNAMSIZ],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.bpf.as_raw_fd(), libc::BIOCGETIF, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { Interface::from_raw(req.ifr_name.map(|c| c as u8)) })
    }

    /// Returns the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCGIFDEVMTU, &raw mut req) {
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_current as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the minimum permissible Maximum Transmission Unit (MTU) that the TAP device can be
    /// set to.
    pub fn min_mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCGIFDEVMTU, &raw mut req) {
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_min as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the maximum permissible Maximum Transmission Unit (MTU) that the TAP device can be
    /// set to.
    pub fn max_mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCGIFDEVMTU, &raw mut req) {
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_max as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        let mtu: i32 = mtu.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mtu too large--must be less than 2147483648 (2^31)",
            )
        })?;

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: mtu },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFMTU, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        req = libc::ifreq {
            ifr_name: self.sink_name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: mtu },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFMTU, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Retrieves the current state of the TAP device (i.e. "UP" or "DOWN").
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_UP as i16 > 0 } {
            Ok(DeviceState::Up)
        } else {
            Ok(DeviceState::Down)
        }
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                    // peer_req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                }
                DeviceState::Up => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                    // peer_req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                }
            }
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Now do for sink

        let mut req = libc::ifreq {
            ifr_name: self.sink_name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                    // peer_req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                }
                DeviceState::Up => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                    // peer_req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                }
            }
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Indicates whether Address Resolution Protocol (ARP) is enabled on the Tap device.
    pub fn arp(&self) -> io::Result<bool> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_NOARP as i16 > 0 } {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Enables or disables Address Resolution Protocol (ARP) on the Tap device.
    pub fn set_arp(&self, do_arp: bool) -> io::Result<()> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut sink_req = libc::ifreq {
            ifr_name: self.sink_name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCGIFFLAGS, &raw mut sink_req) } < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match do_arp {
                true => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_NOARP as i16);
                    sink_req.ifr_ifru.ifru_flags &= !(libc::IFF_NOARP as i16);
                }
                false => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_NOARP as i16;
                    sink_req.ifr_ifru.ifru_flags |= libc::IFF_NOARP as i16;
                }
            }
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFFLAGS, &raw mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSIFFLAGS, &raw mut sink_req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /*
    pub fn debug(&self) -> io::Result<bool> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_DEBUG as i16 > 0 } {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_debug(&self, do_debug: bool) -> io::Result<()> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match do_debug {
                false => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_DEBUG as i16);
                    peer_req.ifr_ifru.ifru_flags &= !(libc::IFF_DEBUG as i16);
                }
                true => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_DEBUG as i16;
                    peer_req.ifr_ifru.ifru_flags |= libc::IFF_DEBUG as i16;
                }
            }
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
    */

    /*
    pub fn promiscuous(&self) -> io::Result<bool> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { req.ifr_ifru.ifru_flags & libc::IFF_PROMISC as i16 > 0 } {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_promiscuous(&self, do_promiscuous: bool) -> io::Result<()> {
        // We don't set/clear promiscuous mode on the peer device--it's already enabled by the
        // attached BPF.

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match do_promiscuous {
                false => req.ifr_ifru.ifru_flags &= !(libc::IFF_PROMISC as i16),
                true => req.ifr_ifru.ifru_flags |= libc::IFF_PROMISC as i16,
            }
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
    */

    // TODO: which of these impls is correct?
    /*
    pub fn lro(&self) -> io::Result<bool> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: 0,
            },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFCAP, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        if unsafe { req.ifr_ifru.ifru_flags & IFCAP_LRO as i16 > 0 } {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_lro(&self, do_lro: bool) -> io::Result<()> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: 0,
            },
        };

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: 0,
            },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFCAP, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFCAP, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        unsafe {
            match do_lro {
                false => {
                    req.ifr_ifru.ifru_flags &= !(IFCAP_LRO as i16);
                    peer_req.ifr_ifru.ifru_flags &= !(IFCAP_LRO as i16);
                }
                true => {
                    req.ifr_ifru.ifru_flags |= IFCAP_LRO as i16;
                    peer_req.ifr_ifru.ifru_flags |= IFCAP_LRO as i16;
                }
            }
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFCAP, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFCAP, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        Ok(())
    }
    */

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TUN device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.bpf.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.bpf.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = match nonblocking {
            true => flags | libc::O_NONBLOCK,
            false => flags & !libc::O_NONBLOCK,
        };

        if unsafe { libc::fcntl(self.bpf.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    // Need to define SIOCGIFLLADDR first
    /*
    pub fn ll_addr(&self) -> io::Result<MacAddr> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_data: [0; 14],
                }
            },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFLLADDR, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error())
        }

        debug_assert_eq!(unsafe { req.ifr_ifru.ifru_addr.sa_data[4] }, 6);

        let addr_bytes = unsafe { &req.ifr_ifru.ifru_addr.sa_data[6..12] };
        let addr_arr = array::from_fn(|i| addr_bytes[i] as u8);

        Ok(MacAddr::from(addr_arr))
    }
    */

    /// Sets the link-layer address of the interface.
    pub fn set_ll_addr(&self, addr: MacAddr) -> io::Result<()> {
        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let addr = libc::sockaddr_dl {
            sdl_len: mem::size_of::<libc::sockaddr_dl>() as u8,
            sdl_family: AF_LINK as u8,
            sdl_index: 0,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 6, // This is what the XNU kernel wants, based on source inspection
            sdl_slen: 0,
            sdl_data: array::from_fn(|i| {
                if i < 6 {
                    addr.addr[i] as libc::c_char
                } else {
                    0
                }
            }),
        };

        let mut req = libc::ifreq {
            ifr_name: self.name()?.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sa_data: [0; 14],
                },
            },
        };

        // TODO: this feels very, very wrong. `sockaddr_dl` technically fits within the ifr_ifru
        // union, and it's the type of address required for this ioctl, but it just feels... wrong.
        unsafe {
            let ll_addr_ptr = (&raw const addr).cast::<u8>();
            let ifreq_addr_ptr = (&raw mut req.ifr_ifru.ifru_addr).cast();
            let copy_len = cmp::min(
                mem::size_of_val(&addr),
                mem::size_of::<libc::__c_anonymous_ifr_ifru>(),
            );
            ptr::copy_nonoverlapping(ll_addr_ptr, ifreq_addr_ptr, copy_len);
        }

        unsafe {
            match libc::ioctl(sockfd.as_raw_fd(), SIOCSIFLLADDR, &raw mut req) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /*
    pub fn add_multicast(&self, multicast_addr: MacAddr) -> io::Result<()> {
        let addr = libc::sockaddr_dl {
            sdl_len: mem::size_of::<libc::sockaddr_dl>() as u8,
            sdl_family: AF_LINK as u8,
            sdl_index: 0,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 6, // This is what the XNU kernel wants, based on source inspection
            sdl_slen: 0,
            sdl_data: array::from_fn(|i| {
                if i < 6 {
                    multicast_addr.addr[i] as libc::c_char
                } else {
                    0
                }
            }),
        };

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sa_data: [0; 14],
                },
            },
        };

        // TODO: this feels very, very wrong. `sockaddr_dl` technically fits within the ifr_ifru
        // union, and it's the type of address required for this ioctl, but it just feels... wrong.
        unsafe {
            let ll_addr_ptr = ptr::addr_of!(addr) as *const u8;
            let ifreq_addr_ptr = ptr::addr_of_mut!(req.ifr_ifru.ifru_addr) as *mut u8;
            let copy_len = cmp::min(
                mem::size_of_val(&addr),
                mem::size_of::<libc::__c_anonymous_ifr_ifru>(),
            );
            ptr::copy_nonoverlapping(ll_addr_ptr, ifreq_addr_ptr, copy_len);
        }

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCADDMULTI, ptr::addr_of_mut!(req)) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
    */

    /// Retrieves the network-layer addresses assigned to the interface.
    ///
    /// This method makes no guarantee on the order of addresses returned. IPv4 and IPv6 addresses
    /// may be mixed in any random order within the `Vec`, even between consecutive calls to this
    /// method.
    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.name()?.addrs()
    }

    /// Adds the specified network-layer address to the interface.
    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.name()?.add_addr(req)
    }

    /// Removes the specified network-layer address from the interface.
    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.name()?.remove_addr(addr)
    }

    /// Sends a single packet out over the TAP interface.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        (&self.bpf).write(buf)
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.bpf).read(buf)
    }

    /// Deletes the feth interface(s) from the operating system.
    ///
    /// This method will remove the TAP even if it is set to a persistent mode of operation.
    pub fn destroy(self) -> io::Result<()> {
        let mut err = None;

        let adapter_name = self.name()?;
        let sink_name = self.sink_name()?;

        let sockfd = unsafe {
            OwnedFd::from_raw_fd(match libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
                ..=-1 => return Err(io::Error::last_os_error()),
                fd => fd,
            })
        };

        let mut req = libc::ifreq {
            ifr_name: adapter_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut sink_req = libc::ifreq {
            ifr_name: sink_name.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if let Err(e) = self.set_state(DeviceState::Down) {
            err = Some(e);
        }

        drop(self);

        let mut unpeer_req = if_fake_request {
            iffr_reserved: [0u64; 4],
            iffr_u: __c_anonymous_iffr_u {
                iffru_peer_name: [0i8; libc::IFNAMSIZ],
            },
        };

        let mut spec = ifdrv {
            ifd_name: adapter_name.name_raw_char(),
            ifd_cmd: IF_FAKE_S_CMD_SET_PEER,
            ifd_len: mem::size_of_val(&unpeer_req),
            ifd_data: (&raw mut unpeer_req).cast(),
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCSDRVSPEC, &raw mut spec) } < 0 {
            err = Some(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFDESTROY, &raw mut req) } < 0 {
            err = Some(io::Error::last_os_error());
        };

        if unsafe { libc::ioctl(sockfd.as_raw_fd(), SIOCIFDESTROY, &raw mut sink_req) } < 0 {
            err = Some(io::Error::last_os_error());
        };

        err.map_or(Ok(()), Err)
    }

    fn destroy_iface(sockfd: RawFd, iface: Interface) {
        let mut req = libc::ifreq {
            ifr_name: iface.name_raw_char(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            debug_assert_eq!(libc::ioctl(sockfd, SIOCIFDESTROY, &raw mut req), 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for FethTap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.bpf.as_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for FethTap {
    fn as_raw_fd(&self) -> RawFd {
        self.bpf.as_raw_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl FromRawFd for FethTap {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            bpf: File::from_raw_fd(fd),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl IntoRawFd for FethTap {
    fn into_raw_fd(self) -> RawFd {
        self.bpf.into_raw_fd()
    }
}
