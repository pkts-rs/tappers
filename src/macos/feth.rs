// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::{array, cmp, io, mem, ptr};

use crate::libc_extra::*;
use crate::RawFd;
use crate::{AddAddress, AddressInfo, DeviceState, Interface, MacAddr};

const DEV_BPF: *const i8 = b"/dev/bpf\0".as_ptr() as *const i8;
const FETH_PREFIX: &[u8] = b"feth";
const NET_LINK_FAKE_LRO: *const i8 = b"net.link.fake.lro\0".as_ptr() as *const i8;

const BPF_CREATE_ATTEMPTS: u32 = 1024;
const BPF_BUFFER_LEN: i32 = 131072;

/// Fake Ethernet ("feth") TAP device interface that includes MacOS-specific functionality.
///
/// Apple does not support conventional TAP APIs, so this implementation instead uses the somewhat
/// undocumented `IF_FAKE` or "feth" interface to act as a link-layer virtual network.
pub struct FethTap {
    iface: Interface,
    peer_iface: Interface,
    /// NDRV file descriptor for sending packets on the interface.
    ndrv_fd: RawFd,
    /// BPF file descriptor for receiving packets from the interface.
    bpf_fd: RawFd,
}

impl FethTap {
    /// Creates a new TAP device.
    ///
    /// The interface name associated with this TAP device will be "feth" with a device number
    /// appended (e.g. "feth0", "feth1"), and can be retrieved via the [`name()`](Self::name)
    /// method.
    pub fn new() -> io::Result<Self> {
        Self::new_named(None, None)
    }

    /// Creates a new TAP device using the specified interface numbers for the `feth` devices.
    ///
    /// MacOS requires that a pair of `feth` devices be created in order to mimic TAP behavior.
    /// These devices are paired to one another; one device is used as a virtual interface, while
    /// the other is used to actually read and write packets. A call to [`new()`](Self::new)
    /// normally assigns the two lowest available interface numbers to these devices; this method
    /// may instead be used to manually assign interface numbers. If one or both of the interface
    /// numbers is already being used (or is otherwise unavailable), this method will return an
    /// error.
    pub fn new_numbered(if_number: Option<u32>, peer_if_number: Option<u32>) -> io::Result<Self> {
        let iface = match if_number {
            Some(n) => Some(Interface::new_raw(format!("feth{}", n).as_bytes())?),
            None => None,
        };

        let peer_iface = match peer_if_number {
            Some(n) => Some(Interface::new_raw(format!("feth{}", n).as_bytes())?),
            None => None,
        };

        Self::new_named(iface, peer_iface)
    }

    /// Creates a new TAP device using the specified interface names for the `feth` devices.
    ///
    /// MacOS requires that a pair of `feth` devices be created in order to mimic TAP behavior.
    /// These devices are paired to one another; one device is used as a virtual interface, while
    /// the other is used to actually read and write packets. A call to [`new()`](Self::new)
    /// normally assigns the two lowest available interface numbers to these devices; this method
    /// may instead be used to manually assign interface numbers. If one or both of the interface
    /// numbers is already being used (or is otherwise unavailable), this method will return an
    /// error.
    pub fn new_named(iface: Option<Interface>, peer_iface: Option<Interface>) -> io::Result<Self> {
        let mut iface = iface.unwrap_or(Interface::new_raw(FETH_PREFIX)?);
        let mut peer_iface = peer_iface.unwrap_or(Interface::new_raw(FETH_PREFIX)?);

        if &iface.name[..4] != FETH_PREFIX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied iface was not a `feth` interface",
            ));
        }

        if &peer_iface.name[..4] != FETH_PREFIX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supplied peer_iface was not a `feth` interface",
            ));
        }

        let ndrv_fd = unsafe { libc::socket(AF_NDRV, libc::SOCK_RAW, 0) };
        if ndrv_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // TODO: set O_CLOEXEC on this and all other sockets

        // Create the primary `feth` device

        let mut req = libc::ifreq {
            ifr_name: iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        // SIOCIFCREATE2 is of no effect for `feth` sockets, so we don't use it?
        if unsafe { libc::ioctl(ndrv_fd, SIOCIFCREATE, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        iface = Interface::from_cstr(unsafe { CStr::from_ptr(req.ifr_name.as_ptr()) }).unwrap();

        // Create the peer `feth` device

        let mut peer_req = libc::ifreq {
            ifr_name: peer_iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(ndrv_fd, SIOCIFCREATE, ptr::addr_of_mut!(peer_req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        peer_iface =
            Interface::from_cstr(unsafe { CStr::from_ptr(peer_req.ifr_name.as_ptr()) }).unwrap();

        // Peer the two devices together

        let mut fake_req = if_fake_request {
            iffr_reserved: [0u64; 4],
            iffr_u: __c_anonymous_iffr_u {
                iffru_peer_name: peer_iface.name_raw_i8(),
            },
        };

        let mut spec = ifdrv {
            ifd_name: req.ifr_name,
            ifd_cmd: IF_FAKE_S_CMD_SET_PEER,
            ifd_len: mem::size_of_val(&fake_req),
            ifd_data: ptr::addr_of_mut!(fake_req) as *mut libc::c_void,
        };

        if unsafe { libc::ioctl(ndrv_fd, SIOCSDRVSPEC, ptr::addr_of_mut!(spec)) } != 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Bind/connect the NDRV file descriptor to the peer `feth` device

        let ndrv_addrlen = mem::size_of::<sockaddr_ndrv>();
        let mut ndrv_addr = sockaddr_ndrv {
            snd_len: ndrv_addrlen as u8,
            snd_family: AF_NDRV as u8,
            snd_name: [0u8; libc::IF_NAMESIZE],
        };

        for (dst, src) in ndrv_addr.snd_name.iter_mut().zip(peer_req.ifr_name) {
            *dst = src as u8;
        }

        let ndrv_addr_ptr = ptr::addr_of!(ndrv_addr) as *const libc::sockaddr;
        if unsafe { libc::bind(ndrv_fd, ndrv_addr_ptr, ndrv_addrlen as u32) } != 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        if unsafe { libc::connect(ndrv_fd, ndrv_addr_ptr, ndrv_addrlen as u32) } != 0 {
            let err = io::Error::last_os_error();
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Open BPF device

        let mut bpf_fd = unsafe { libc::open(DEV_BPF, libc::O_RDWR | libc::O_CLOEXEC) };
        if bpf_fd < 0 {
            let errno = unsafe { *libc::__error() };
            if errno != libc::ENOENT {
                // `/dev/bpf` device existed, but some other error occurred
                let err = io::Error::last_os_error();
                Self::destroy_iface(ndrv_fd, peer_iface);
                Self::destroy_iface(ndrv_fd, iface);
                Self::close_fd(ndrv_fd);
                return Err(err);
            }

            // `/dev/bpf` isn't available--try `/dev/bpfXXX`
            // Some net utilities hardcode /dev/bpf0 for use, so we politely avoid it
            for dev_idx in 1..=BPF_CREATE_ATTEMPTS {
                let device = CString::new(format!("/dev/bpf{}", dev_idx).into_bytes()).unwrap();
                bpf_fd = unsafe { libc::open(device.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
                if bpf_fd >= 0 {
                    break;
                }

                let errno = unsafe { *libc::__error() };
                if errno != libc::EBUSY {
                    // Device wasn't in use, but some other error occurred
                    let err = io::Error::last_os_error();
                    Self::destroy_iface(ndrv_fd, peer_iface);
                    Self::destroy_iface(ndrv_fd, iface);
                    Self::close_fd(ndrv_fd);
                    return Err(err);
                }
            }

            if bpf_fd < 0 {
                // None of the BPF creation attempts succeeded
                let err = io::Error::last_os_error();
                Self::destroy_iface(ndrv_fd, peer_iface);
                Self::destroy_iface(ndrv_fd, iface);
                Self::close_fd(ndrv_fd);
                return Err(err);
            }
        }

        // Configure BPF device

        let mut enable = 1i32;
        let mut disable = 0i32;
        let mut buffer_len = BPF_BUFFER_LEN; // TODO: make configurable?

        // Sets the length of the buffer that will be used for subsequent `read()`s
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCSBLEN, ptr::addr_of_mut!(buffer_len)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Have reads return immediately when packets are received
        // TODO: make configurable?
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCIMMEDIATE, ptr::addr_of_mut!(enable)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Don't sniff packets that were sent out on the interface
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCGSEESENT, ptr::addr_of_mut!(disable)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Set BPF socket to be listening on to the peer `feth` interface
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCSETIF, ptr::addr_of_mut!(peer_req)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Disable network-layer header rewriting on the interface output routine
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCSHDRCMPLT, ptr::addr_of_mut!(enable)) } != 0 {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // Do receive packets even if they're not addressed specifically to the interface's
        // associated address
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCPROMISC as u64, ptr::addr_of_mut!(enable)) } != 0
        {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        Ok(Self {
            iface,
            peer_iface,
            ndrv_fd,
            bpf_fd,
        })
    }

    /// Determines whether Link Receive Offload (LRO) is enabled for all TAP (feth) devices.
    pub fn lro() -> io::Result<bool> {
        let mut lro = 0u32;
        let mut lro_len = mem::size_of_val(&lro);

        unsafe {
            match libc::sysctlbyname(
                NET_LINK_FAKE_LRO,
                ptr::addr_of_mut!(lro) as *mut libc::c_void,
                ptr::addr_of_mut!(lro_len),
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
                NET_LINK_FAKE_LRO,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::addr_of_mut!(lro) as *mut libc::c_void,
                mem::size_of_val(&lro),
            ) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the primary `feth` interface name associated with the TAP device.
    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.iface)
    }

    /// Returns the peer `feth` interface name associated with the TAP device.
    pub fn peer_name(&self) -> io::Result<Interface> {
        Ok(self.peer_iface)
    }

    /// Returns the Maximum Transmission Unit (MTU) of the TAP device.
    pub fn mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCGIFDEVMTU, ptr::addr_of_mut!(req)) {
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_current as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the minimum permissible Maximum Transmission Unit (MTU) that the TAP device can be
    /// set to.
    pub fn min_mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCGIFDEVMTU, ptr::addr_of_mut!(req)) {
                0 => Ok(req.ifr_ifru.ifru_devmtu.ifdm_min as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Returns the maximum permissible Maximum Transmission Unit (MTU) that the TAP device can be
    /// set to.
    pub fn max_mtu(&self) -> io::Result<usize> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_devmtu: libc::ifdevmtu {
                    ifdm_current: 0,
                    ifdm_min: 0,
                    ifdm_max: 0,
                },
            },
        };

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCGIFDEVMTU, ptr::addr_of_mut!(req)) {
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

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: mtu },
        };

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCSIFMTU, ptr::addr_of_mut!(req)) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the current state of the TAP device (i.e. "up" or "down").
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
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
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        /*
        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };
        */

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        /*
        if unsafe { libc::ioctl(self.bpf_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }
        */

        // TODO: This ^ was failing with EINVAL. Is it correct to not call it?

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

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        /*
        if unsafe { libc::ioctl(self.bpf_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }
        */

        Ok(())
    }

    /// Indicates whether Address Resolution Protocol (ARP) is enabled on the Tap device.
    pub fn arp(&self) -> io::Result<bool> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
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
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match do_arp {
                true => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_NOARP as i16);
                    peer_req.ifr_ifru.ifru_flags &= !(libc::IFF_NOARP as i16);
                }
                false => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_NOARP as i16;
                    peer_req.ifr_ifru.ifru_flags |= libc::IFF_NOARP as i16;
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

    /*
    pub fn debug(&self) -> io::Result<bool> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
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
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_i8(),
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
            ifr_name: self.iface.name_raw_i8(),
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
            ifr_name: self.iface.name_raw_i8(),
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
            ifr_name: self.iface.name_raw_i8(),
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
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: 0,
            },
        };

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_i8(),
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
        let flags = unsafe { libc::fcntl(self.bpf_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.bpf_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = match nonblocking {
            true => flags | libc::O_NONBLOCK,
            false => flags & !libc::O_NONBLOCK,
        };

        if unsafe { libc::fcntl(self.bpf_fd, libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        } else {
            Ok(())
        }

        // TODO: NDRV socket didn't allow setting nonblocking... is that okay?
        // I'm assuming it's guaranteed not to block since it runs system commands.
    }

    // Need to define SIOCGIFLLADDR first
    /*
    pub fn ll_addr(&self) -> io::Result<MacAddr> {
        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_data: [0i8; 14],
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
        let addr = libc::sockaddr_dl {
            sdl_len: mem::size_of::<libc::sockaddr_dl>() as u8,
            sdl_family: AF_LINK as u8,
            sdl_index: 0,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 6, // This is what the XNU kernel wants, based on source inspection
            sdl_slen: 0,
            sdl_data: array::from_fn(|i| if i < 6 { addr.addr[i] as i8 } else { 0i8 }),
        };

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sa_data: [0i8; 14],
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
            match libc::ioctl(self.ndrv_fd, SIOCSIFLLADDR, ptr::addr_of_mut!(req)) {
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
                    multicast_addr.addr[i] as i8
                } else {
                    0i8
                }
            }),
        };

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: mem::size_of::<libc::sockaddr_in>() as u8,
                    sa_data: [0i8; 14],
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
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.ndrv_fd, buf.as_ptr() as *mut libc::c_void, buf.len()) {
                s @ 0.. => Ok(s as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Receives a packet over the TAP device.
    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(
                self.ndrv_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            ) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Deletes the feth interface(s) from the operating system.
    ///
    /// This method will remove the TAP even if it is set to a persistent mode of operation.
    pub fn destroy(self) -> io::Result<()> {
        let mut err = None;

        Self::close_fd(self.bpf_fd);

        let mut peer_req = libc::ifreq {
            ifr_name: self.peer_iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        match unsafe { libc::ioctl(self.ndrv_fd, SIOCIFDESTROY, ptr::addr_of_mut!(peer_req)) } {
            0 => (),
            _ => err = Some(io::Error::last_os_error()),
        };

        let mut req = libc::ifreq {
            ifr_name: self.iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        match unsafe { libc::ioctl(self.ndrv_fd, SIOCIFDESTROY, ptr::addr_of_mut!(req)) } {
            0 => (),
            _ => {
                err.replace(io::Error::last_os_error());
            }
        };

        Self::close_fd(self.ndrv_fd);

        match err {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    fn destroy_iface(sockfd: RawFd, iface: Interface) {
        let mut req = libc::ifreq {
            ifr_name: iface.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            debug_assert_eq!(
                libc::ioctl(sockfd, SIOCIFDESTROY, ptr::addr_of_mut!(req)),
                0
            );
        }
    }

    #[inline]
    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }
}

impl Drop for FethTap {
    fn drop(&mut self) {
        Self::close_fd(self.bpf_fd);
        Self::destroy_iface(self.ndrv_fd, self.peer_iface);
        Self::destroy_iface(self.ndrv_fd, self.iface);
        Self::close_fd(self.ndrv_fd);
    }
}

// Lists all cloneable interfaces: SIOCIFGCLONERS
