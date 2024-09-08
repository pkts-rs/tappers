use std::ffi::CStr;
use std::os::fd::RawFd;
use std::{io, ptr};

use crate::{DeviceState, Interface};

use super::DEV_NET_TUN;

// Need to add to libc
const TUNGETIFF: u64 = 0x800454D2;

const TUNSETDEBUG: u64 = 0x400454C9;
const TUNSETGROUP: u64 = 0x400454CE;
const TUNSETLINK: u64 = 0x400454CD;
const TUNSETIFF: u64 = 0x400454CA;
const TUNSETOWNER: u64 = 0x400454CC;
const TUNSETPERSIST: u64 = 0x400454CB;

pub struct Tun {
    fd: RawFd,
}

impl Tun {
    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        let flags = libc::IFF_TUN_EXCL | libc::IFF_TUN | libc::IFF_NO_PI;

        let mut req = libc::ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        // TODO: unify `ErrorKind`s returned
        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TUN | libc::IFF_NO_PI;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Creates a new TUN device, failing if a device of the given name already exists.
    pub fn create_named(if_name: Interface) -> io::Result<Self> {
        let flags = libc::IFF_TUN_EXCL | libc::IFF_TUN | libc::IFF_NO_PI;

        let mut req = libc::ifreq {
            ifr_name: if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_flags: flags as i16,
            },
        };

        let fd = unsafe { libc::open(DEV_NET_TUN, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, TUNSETIFF, ptr::addr_of_mut!(req)) } != 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Sets the persistence of the TUN interface.
    ///
    /// If set to `false`, the TUN device will be destroyed once all file descriptor handles to it
    /// have been closed. If set to `true`, the TUN device will persist until it is explicitly
    /// closed or the system reboots. By default, persistence is set to `true` unless
    /// [`create_ephemeral()`](Self::create_ephemeral) is used.
    pub fn set_persistent(&self, persistent: bool) -> io::Result<()> {
        let persist = match persistent {
            true => 1,
            false => 0,
        };

        unsafe {
            match libc::ioctl(self.fd, TUNSETPERSIST, persist) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Retrieves the interface name associated with the TUN device.
    pub fn name(&self) -> io::Result<Interface> {
        let mut req = libc::ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            match libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) {
                0.. => Interface::from_cstr(CStr::from_ptr(req.ifr_name.as_ptr())),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Changes the interface name associated with the TUN device to `if_name`.
    pub fn set_name(&self, if_name: Interface) -> io::Result<()> {
        let old_if_name = self.name()?;

        let mut req = libc::ifreq {
            ifr_name: old_if_name.name_raw_i8(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_newname: if_name.name_raw_i8(),
            },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match libc::ioctl(ctrl_fd, libc::SIOCSIFNAME, ptr::addr_of_mut!(req)) {
                0.. => {
                    libc::close(ctrl_fd);
                    Ok(())
                }
                _ => {
                    let err = io::Error::last_os_error();
                    libc::close(ctrl_fd);
                    Err(err)
                }
            }
        }
    }

    /// Retrieves the current state of the TUN device (i.e. "up" or "down").
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut req = libc::ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        unsafe {
            match libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) {
                0.. => {
                    if (req.ifr_ifru.ifru_flags & libc::IFF_UP as i16) == 0 {
                        Ok(DeviceState::Down)
                    } else {
                        Ok(DeviceState::Up)
                    }
                }
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets the state of the TUN device (i.e. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let mut req = libc::ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
        };

        if unsafe { libc::ioctl(self.fd, TUNGETIFF, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16),
                DeviceState::Up => req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16,
            }
        }

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match libc::ioctl(ctrl_fd, libc::SIOCSIFFLAGS, ptr::addr_of_mut!(req)) {
                0.. => {
                    libc::close(ctrl_fd);
                    Ok(())
                }
                _ => {
                    let err = io::Error::last_os_error();
                    libc::close(ctrl_fd);
                    Err(err)
                }
            }
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the TUN device.
    pub fn mtu(&self) -> io::Result<usize> {
        let ifr_name = self.name()?.name_raw_i8();

        let mut req = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match libc::ioctl(ctrl_fd, libc::SIOCGIFMTU, ptr::addr_of_mut!(req)) {
                0.. => {
                    libc::close(ctrl_fd);

                    if req.ifr_ifru.ifru_mtu < 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected negative MTU",
                        ));
                    }

                    Ok(req.ifr_ifru.ifru_mtu as usize)
                }
                _ => {
                    let err = io::Error::last_os_error();
                    libc::close(ctrl_fd);
                    Err(err)
                }
            }
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the TUN device.
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        if mtu > i32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU too large"));
        }

        let ifr_name = self.name()?.name_raw_i8();

        let mut req = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_mtu: mtu as i32,
            },
        };

        let ctrl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match libc::ioctl(ctrl_fd, libc::SIOCSIFMTU, ptr::addr_of_mut!(req)) {
                0.. => {
                    libc::close(ctrl_fd);
                    Ok(())
                }
                _ => {
                    let err = io::Error::last_os_error();
                    libc::close(ctrl_fd);
                    Err(err)
                }
            }
        }
    }

    /// Reads a single packet from the TUN device.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Writes a single packet to the TUN device.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) {
                r @ 0.. => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TUN device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = match nonblocking {
            true => flags | libc::O_NONBLOCK,
            false => flags & !libc::O_NONBLOCK,
        };

        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        } else {
            Ok(())
        }
    }

    /// Sets the Ethernet link type for the TUN device (see libc ARPHRD_* constants).
    ///
    /// The device must be down (see [`set_state`](Self::set_state)) for this method to succeed.
    /// TUN devices have a default Ethernet link type of `ARPHRD_ETHER`.
    pub fn set_linktype(&self, linktype: u32) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETLINK, linktype) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Sets debug mode for the TUN device.
    pub fn set_debug(&self, debug: bool) -> io::Result<()> {
        let debug = match debug {
            true => 1,
            false => 0,
        };

        unsafe {
            match libc::ioctl(self.fd, TUNSETDEBUG, debug) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TUN device to the given user ID, thereby enabling the user to perform operations
    /// on the device.
    pub fn set_owner(&self, owner: libc::uid_t) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETOWNER, owner) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// Assigns the TUN device to the given group ID, thereby enabling users in that group to
    /// perform operations on the device.
    pub fn set_group(&self, group: libc::gid_t) -> io::Result<()> {
        unsafe {
            match libc::ioctl(self.fd, TUNSETGROUP, group) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    // SIOCGIFHWADDR, SIOCSIFHWADDR
}

impl Drop for Tun {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
