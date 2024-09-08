use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::{array, cmp, io, iter, mem, ptr};

use crate::{DeviceState, Interface, MacAddr};

const DEV_BPF: *const i8 = b"/dev/bpf\0".as_ptr() as *const i8;
const FETH_PREFIX: &[u8] = b"feth";
const NET_LINK_FAKE_LRO: *const i8 = b"net.link.fake.lro\0".as_ptr() as *const i8;

const BPF_CREATE_ATTEMPTS: u32 = 1024;
const BPF_BUFFER_LEN: i32 = 131072;

#[allow(non_camel_case_types)]
type u_quad_t = u64;

// struct/const values to be removed once libc supports
const SIOCAIFADDR: libc::c_ulong = 0x8040691a;
const SIOCGIFCAP: libc::c_ulong = 0xc020695b;
const SIOCGIFDEVMTU: libc::c_ulong = 0xc0206944;
const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
const SIOCIFCREATE: libc::c_ulong = 0xc0206978;
const SIOCIFCREATE2: libc::c_ulong = 0xc020697a;
const SIOCSDRVSPEC: libc::c_ulong = 0x8028697b;
const SIOCSIFCAP: libc::c_ulong = 0x8020695a;
const SIOCSIFLLADDR: libc::c_ulong = 0x8020693c;
const SIOCSIFMTU: libc::c_ulong = 0x80206934;
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080691a;
const SIOCDIFADDR_IN6: libc::c_ulong = 0x81206919;
const SIOCGIFBRDADDR: libc::c_ulong = 0xc0206923;
const SIOCGIFDSTADDR: libc::c_ulong = 0xc0206922;
const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
const SIOCGIFNETMASK: libc::c_ulong = 0xc0206925;
const SIOCIFDESTROY: libc::c_ulong = 0x80206979;
const SIOCSIFADDR: libc::c_ulong = 0x8020690c;
const SIOCSIFBRDADDR: libc::c_ulong = 0x80206913;
const SIOCSIFDSTADDR: libc::c_ulong = 0x8020690e;
const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;
const SIOCSIFNETMASK: libc::c_ulong = 0x80206916;
const SIOCADDMULTI: libc::c_ulong = 0x80206931;
const SIOCDELMULTI: libc::c_ulong = 0x80206932;
const SIOCDIFADDR: libc::c_ulong = 0x80206919;

// <net/route.h>

// Bitmask values for rtm_addrs.
pub const RTA_DST: libc::c_int = 0x1;
pub const RTA_GATEWAY: libc::c_int = 0x2;
pub const RTA_NETMASK: libc::c_int = 0x4;
pub const RTA_GENMASK: libc::c_int = 0x8;
pub const RTA_IFP: libc::c_int = 0x10;
pub const RTA_IFA: libc::c_int = 0x20;
pub const RTA_AUTHOR: libc::c_int = 0x40;
pub const RTA_BRD: libc::c_int = 0x80;

// Index offsets for sockaddr array for alternate internal encoding.
pub const RTAX_DST: libc::c_int = 0;
pub const RTAX_GATEWAY: libc::c_int = 1;
pub const RTAX_NETMASK: libc::c_int = 2;
pub const RTAX_GENMASK: libc::c_int = 3;
pub const RTAX_IFP: libc::c_int = 4;
pub const RTAX_IFA: libc::c_int = 5;
pub const RTAX_AUTHOR: libc::c_int = 6;
pub const RTAX_BRD: libc::c_int = 7;

// <net/if_fake_var.h>
const IF_FAKE_S_CMD_NONE: u64 = 0;
const IF_FAKE_S_CMD_SET_PEER: u64 = 1;
const IF_FAKE_S_CMD_SET_MEDIA: u64 = 2;
const IF_FAKE_S_CMD_SET_DEQUEUE_STALL: u64 = 3;

const IF_FAKE_G_CMD_NONE: u64 = 0;
const IF_FAKE_G_CMD_GET_PEER: u64 = 1;

// <sys/sys_domain.h>

const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: libc::c_int = 2;

// <sys/socket.h>
const AF_LINK: libc::c_int = 18;
const AF_NDRV: libc::c_int = 27;

const SCOPE6_ID_MAX: libc::size_t = 16;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ifdrv {
    /// if name, e.g. "en0"
    pub ifd_name: [libc::c_char; libc::IFNAMSIZ as usize],
    pub ifd_cmd: libc::c_ulong,
    pub ifd_len: libc::size_t,
    pub ifd_data: *mut libc::c_void,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct sockaddr_ndrv {
    pub snd_len: libc::c_uchar,
    pub snd_family: libc::c_uchar,
    pub snd_name: [libc::c_uchar; libc::IFNAMSIZ as usize],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct in6_ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ as usize],
    pub ifr_ifru: __c_anonymous_ifr_ifru6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
union __c_anonymous_ifr_ifru6 {
    pub ifru_addr: libc::sockaddr_in6,
    pub ifru_dstaddr: libc::sockaddr_in6,
    pub ifru_flags: libc::c_int,
    pub ifru_flags6: libc::c_int,
    pub ifru_metrics: libc::c_int,
    pub ifru_intval: libc::c_int,
    pub ifru_data: *mut libc::c_char,
    pub ifru_lifetime: in6_addrlifetime,
    pub ifru_stat: in6_ifstat,
    pub ifru_icmp6stat: icmp6_ifstat,
    pub ifru_scope_id: [u32; SCOPE6_ID_MAX],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct in6_addrlifetime {
    pub ia6t_expire: libc::time_t,
    pub ia6t_preferred: libc::time_t,
    pub ia6t_vltime: u32,
    pub ia6t_pltime: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct icmp6_ifstat {
    pub ifs6_in_msg: u_quad_t,
    pub ifs6_in_error: u_quad_t,
    pub ifs6_in_dstunreach: u_quad_t,
    pub ifs6_in_adminprohib: u_quad_t,
    pub ifs6_in_timeexceed: u_quad_t,
    pub ifs6_in_paramprob: u_quad_t,
    pub ifs6_in_pkttoobig: u_quad_t,
    pub ifs6_in_echo: u_quad_t,
    pub ifs6_in_echoreply: u_quad_t,
    pub ifs6_in_routersolicit: u_quad_t,
    pub ifs6_in_routeradvert: u_quad_t,
    pub ifs6_in_neighborsolicit: u_quad_t,
    pub ifs6_in_neighboradvert: u_quad_t,
    pub ifs6_in_redirect: u_quad_t,
    pub ifs6_in_mldquery: u_quad_t,
    pub ifs6_in_mldreport: u_quad_t,
    pub ifs6_in_mlddone: u_quad_t,
    pub ifs6_out_msg: u_quad_t,
    pub ifs6_out_error: u_quad_t,
    pub ifs6_out_dstunreach: u_quad_t,
    pub ifs6_out_adminprohib: u_quad_t,
    pub ifs6_out_timeexceed: u_quad_t,
    pub ifs6_out_paramprob: u_quad_t,
    pub ifs6_out_pkttoobig: u_quad_t,
    pub ifs6_out_echo: u_quad_t,
    pub ifs6_out_echoreply: u_quad_t,
    pub ifs6_out_routersolicit: u_quad_t,
    pub ifs6_out_routeradvert: u_quad_t,
    pub ifs6_out_neighborsolicit: u_quad_t,
    pub ifs6_out_neighboradvert: u_quad_t,
    pub ifs6_out_redirect: u_quad_t,
    pub ifs6_out_mldquery: u_quad_t,
    pub ifs6_out_mldreport: u_quad_t,
    pub ifs6_out_mlddone: u_quad_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct in6_ifstat {
    pub ifs6_in_receive: u_quad_t,
    pub ifs6_in_hdrerr: u_quad_t,
    pub ifs6_in_toobig: u_quad_t,
    pub ifs6_in_noroute: u_quad_t,
    pub ifs6_in_addrerr: u_quad_t,
    pub ifs6_in_protounknown: u_quad_t,
    pub ifs6_in_truncated: u_quad_t,
    pub ifs6_in_discard: u_quad_t,
    pub ifs6_in_deliver: u_quad_t,
    pub ifs6_out_forward: u_quad_t,
    pub ifs6_out_request: u_quad_t,
    pub ifs6_out_discard: u_quad_t,
    pub ifs6_out_fragok: u_quad_t,
    pub ifs6_out_fragfail: u_quad_t,
    pub ifs6_out_fragcreat: u_quad_t,
    pub ifs6_reass_reqd: u_quad_t,
    pub ifs6_reass_ok: u_quad_t,
    pub ifs6_atmfrag_rcvd: u_quad_t,
    pub ifs6_reass_fail: u_quad_t,
    pub ifs6_in_mcast: u_quad_t,
    pub ifs6_out_mcast: u_quad_t,
    pub ifs6_cantfoward_icmp6: u_quad_t,
    pub ifs6_addr_expiry_cnt: u_quad_t,
    pub ifs6_pfx_expiry_cnt: u_quad_t,
    pub ifs6_defrtr_expiry_cnt: u_quad_t,
}

/// Fake Ethernet ("feth") TAP device interface.
///
/// Apple does not support conventional TAP APIs, so this implementation instead uses the somewhat
/// undocumented `IF_FAKE` or `feth` interface to act as a link-layer virtual network.
pub struct FethTap {
    iface: Interface,
    peer_iface: Interface,
    /// NDRV file descriptor for sending packets on the interface.
    ndrv_fd: RawFd,
    /// BPF file descriptor for receiving packets from the interface.
    bpf_fd: RawFd,
}

impl FethTap {
    /*
    /// Creates a new TAP device.
    ///
    /// The interface name associated with this TAP device will be "feth" with a device number
    /// appended (e.g. "feth0", "feth1"), and can be retrieved via the [`name()`](Self::name)
    /// method.
    pub fn new() -> io::Result<Self> {
        for i in 0..FETH_CREATE_ATTEMPTS {
            let if_number = i * 2;
            let peer_if_number = if_number + 1;

            match Self::new_numbered(if_number, peer_if_number) {
                Ok(t) => return Ok(t),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists || e.raw_os_error() == Some(libc::EBUSY) => (), // TODO: replace with ResourceBusy once stable
                Err(e) => return Err(e),
            }

            // One of the interface numbers was either taken or in the process of being torn down
        }

        Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not find any `feth` interface pair that was not already in use"))
    }
    */

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

        let mut spec = ifdrv {
            ifd_name: req.ifr_name,
            ifd_cmd: IF_FAKE_S_CMD_SET_PEER,
            ifd_len: mem::size_of_val(&peer_req.ifr_name),
            ifd_data: ptr::addr_of_mut!(peer_req.ifr_name) as *mut libc::c_void,
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
        let mut buffer_len = BPF_BUFFER_LEN;

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

        // Do sniff packets even if they're not addressed specifically to us
        if unsafe { libc::ioctl(bpf_fd, libc::BIOCPROMISC as u64, ptr::addr_of_mut!(enable)) } != 0
        {
            let err = io::Error::last_os_error();
            Self::close_fd(bpf_fd);
            Self::destroy_iface(ndrv_fd, peer_iface);
            Self::destroy_iface(ndrv_fd, iface);
            Self::close_fd(ndrv_fd);
            return Err(err);
        }

        // TODO: do any of these need to come before we bind/connect our NDRV and BPF sockets?
        // If so, we'll bind/connect when the device is brought up

        // ipconfig feth{if1} lladdr <mac-addr>
        // ipconfig feth{if2} peer feth{if1}
        // ipconfig feth{if2} mtu <mtu>
        // ipconfig feth{if2} up
        // ipconfig feth{if1} mtu <mtu>
        // ipconfig feth{if1} metric <metric>
        // ipconfig feth{if1} up

        // configure IPv6 params

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

    fn close_fd(fd: RawFd) {
        unsafe {
            debug_assert_eq!(libc::close(fd), 0);
        }
    }

    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.iface)
    }

    pub fn peer_name(&self) -> io::Result<Interface> {
        Ok(self.peer_iface)
    }

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

    /// Sets the state of the TAP device (i.e. "up" or "down").
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
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

        if unsafe { libc::ioctl(self.bpf_fd, SIOCGIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match state {
                DeviceState::Down => {
                    req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                    peer_req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
                }
                DeviceState::Up => {
                    req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                    peer_req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                }
            }
        }

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(self.bpf_fd, SIOCSIFFLAGS, ptr::addr_of_mut!(peer_req)) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

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

    /// Indicates whether nonblocking is enabled for `read` and `write` operations on the TAP device.
    pub fn nonblocking(&self) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(self.ndrv_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    /// Sets nonblocking mode for `read` and `write` operations on the TUN device.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let nonblocking = match nonblocking {
            true => 1,
            false => 0,
        };

        if unsafe { libc::ioctl(self.ndrv_fd, libc::FIONBIO, nonblocking) } != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            match libc::ioctl(self.bpf_fd, libc::FIONBIO, nonblocking) {
                0.. => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
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

    pub fn del_multicast(&self, multicast_addr: MacAddr) -> io::Result<()> {
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
            match libc::ioctl(self.ndrv_fd, SIOCDELMULTI, ptr::addr_of_mut!(req)) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    pub fn add_addr(&self, addr: IpAddr) -> io::Result<()> {
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
                        s_addr: v4_addr.into(),
                    },
                    sin_zero: [0; 8],
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

                assert_eq!(
                    mem::size_of::<libc::sockaddr>(),
                    mem::size_of::<libc::sockaddr_in>()
                );

                unsafe {
                    let in_addr_ptr = ptr::addr_of!(addr) as *const u8;
                    let sockaddr_ptr = ptr::addr_of_mut!(req.ifr_ifru.ifru_addr) as *mut u8;
                    ptr::copy_nonoverlapping(
                        in_addr_ptr,
                        sockaddr_ptr,
                        mem::size_of::<libc::sockaddr>(),
                    );
                }

                unsafe {
                    match libc::ioctl(self.ndrv_fd, SIOCAIFADDR, ptr::addr_of_mut!(req)) {
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

                // TODO: do flowinfo or scope_id have any significance?
                let mut req = in6_ifreq {
                    ifr_name: self.iface.name_raw_i8(),
                    ifr_ifru: __c_anonymous_ifr_ifru6 {
                        ifru_addr: libc::sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as u8,
                            sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                            sin6_port: 0,
                            sin6_flowinfo: 0,
                            sin6_addr: libc::in6_addr {
                                s6_addr: v6_addr.octets(),
                            },
                            sin6_scope_id: 0,
                        },
                    },
                };

                unsafe {
                    match libc::ioctl(self.ndrv_fd, SIOCAIFADDR_IN6, ptr::addr_of_mut!(req)) {
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

    pub fn del_addr(&self, addr: IpAddr) -> io::Result<()> {
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
                        s_addr: v4_addr.into(),
                    },
                    sin_zero: [0; 8],
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

                assert_eq!(
                    mem::size_of::<libc::sockaddr>(),
                    mem::size_of::<libc::sockaddr_in>()
                );

                unsafe {
                    let in_addr_ptr = ptr::addr_of!(addr) as *const u8;
                    let sockaddr_ptr = ptr::addr_of_mut!(req.ifr_ifru.ifru_addr) as *mut u8;
                    ptr::copy_nonoverlapping(
                        in_addr_ptr,
                        sockaddr_ptr,
                        mem::size_of::<libc::sockaddr>(),
                    );
                }

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

                // TODO: do flowinfo or scope_id have any significance?
                let mut req = in6_ifreq {
                    ifr_name: self.iface.name_raw_i8(),
                    ifr_ifru: __c_anonymous_ifr_ifru6 {
                        ifru_addr: libc::sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as u8,
                            sin6_len: mem::size_of::<libc::sockaddr_in>() as u8,
                            sin6_port: 0,
                            sin6_flowinfo: 0,
                            sin6_addr: libc::in6_addr {
                                s6_addr: v6_addr.octets(),
                            },
                            sin6_scope_id: 0,
                        },
                    },
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

    pub fn v4_netmask(&self) -> io::Result<Ipv4Addr> {
        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

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

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFNETMASK, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(inet_fd) };
            return Err(err);
        }

        assert_eq!(
            mem::size_of::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>()
        );

        let mut addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u8,
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };

        unsafe {
            let in_addr_ptr = ptr::addr_of_mut!(addr) as *mut u8;
            let sockaddr_ptr = ptr::addr_of!(req.ifr_ifru.ifru_addr) as *const u8;
            ptr::copy_nonoverlapping(sockaddr_ptr, in_addr_ptr, mem::size_of::<libc::sockaddr>());
        }

        unsafe {
            libc::close(inet_fd);
        }

        Ok(Ipv4Addr::from(addr.sin_addr.s_addr.to_be_bytes())) // TODO: verify correct endianness
    }

    pub fn set_v4_netmask(&self, addr: Ipv4Addr) -> io::Result<()> {
        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u8,
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: addr.into(),
            },
            sin_zero: [0; 8],
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

        assert_eq!(
            mem::size_of::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>()
        );

        unsafe {
            let in_addr_ptr = ptr::addr_of!(addr) as *const u8;
            let sockaddr_ptr = ptr::addr_of_mut!(req.ifr_ifru.ifru_addr) as *mut u8;
            ptr::copy_nonoverlapping(in_addr_ptr, sockaddr_ptr, mem::size_of::<libc::sockaddr>());
        }

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCSIFNETMASK, ptr::addr_of_mut!(req)) {
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

    pub fn dst_addr(&self) -> io::Result<Ipv4Addr> {
        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

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

        if unsafe { libc::ioctl(self.ndrv_fd, SIOCGIFDSTADDR, ptr::addr_of_mut!(req)) } != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(inet_fd) };
            return Err(err);
        }

        assert_eq!(
            mem::size_of::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>()
        );

        let mut addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u8,
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };

        unsafe {
            let in_addr_ptr = ptr::addr_of_mut!(addr) as *mut u8;
            let sockaddr_ptr = ptr::addr_of!(req.ifr_ifru.ifru_addr) as *const u8;
            ptr::copy_nonoverlapping(sockaddr_ptr, in_addr_ptr, mem::size_of::<libc::sockaddr>());
        }

        unsafe {
            libc::close(inet_fd);
        }

        Ok(Ipv4Addr::from(addr.sin_addr.s_addr.to_be_bytes())) // TODO: verify correct endianness
    }

    pub fn set_dst_addr(&self, addr: Ipv4Addr) -> io::Result<()> {
        let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if inet_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u8,
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: addr.into(),
            },
            sin_zero: [0; 8],
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

        assert_eq!(
            mem::size_of::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>()
        );

        unsafe {
            let in_addr_ptr = ptr::addr_of!(addr) as *const u8;
            let sockaddr_ptr = ptr::addr_of_mut!(req.ifr_ifru.ifru_addr) as *mut u8;
            ptr::copy_nonoverlapping(in_addr_ptr, sockaddr_ptr, mem::size_of::<libc::sockaddr>());
        }

        unsafe {
            match libc::ioctl(self.ndrv_fd, SIOCSIFDSTADDR, ptr::addr_of_mut!(req)) {
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

    const MEMORY_MIN: usize = 2048;
    const MEMORY_MAX: usize = 16777216;
    const RTM_VERSION: u8 = 5;

    /// Retrieves the IPv4/IPv6 addresses assigned to the interface.
    ///
    /// This method makes no guarantee on the order of addresses returned IPv4 and IPv6 addresses
    /// may be mixed randomly within the `Vec`.
    pub fn addrs(&self) -> io::Result<Vec<IpAddr>> {
        // First, get the index of the interface
        let if_index = self.iface.index()?;

        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            0,
            libc::NET_RT_IFLIST,
            if_index as i32,
        ];

        let mut needed = 0;

        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                ptr::null_mut(),
                ptr::addr_of_mut!(needed),
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        needed = cmp::max(needed, Self::MEMORY_MIN);
        needed = cmp::min(needed + (needed >> 1), Self::MEMORY_MAX);
        // 50% more than what the kernel suggested should be plenty

        // TODO: performance?
        let mut buf: Vec<u8> = Vec::with_capacity(needed);
        buf.extend(iter::repeat(0).take(needed));

        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let mut buflen = 0;

        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                buf_ptr,
                ptr::addr_of_mut!(buflen),
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut data = &buf[..buflen];
        let mut addrs = Vec::new();

        while !data.is_empty() {
            let (hdr_slice, rem_data) = data.split_at(mem::size_of::<libc::ifa_msghdr>());

            let (_, hdr_slice, _) = unsafe { hdr_slice.align_to::<libc::ifa_msghdr>() };
            let msghdr = hdr_slice.first().unwrap(); // TODO: handle alignment errors gracefully?

            let addr_end = msghdr.ifam_msglen as usize - mem::size_of::<libc::rt_msghdr>();
            if addr_end > rem_data.len() {
                break;
            }
            let (mut addr_data, rem_data) = rem_data.split_at(addr_end);
            data = rem_data;

            if msghdr.ifam_version != Self::RTM_VERSION
                || msghdr.ifam_type != libc::RTM_NEWADDR as u8
            {
                continue;
            }

            if msghdr.ifam_addrs & RTA_IFA == 0 {
                continue;
            }

            for i in 0..RTAX_IFA {
                // RTA_IFA is the 6th bitflag in the set, so we handle addresses preceding it
                let addr_bit = 1 << i;
                if msghdr.ifam_addrs & addr_bit == 0 {
                    continue;
                }

                // Skip the address
                let addrlen = addr_data[0] as usize;
                addr_data = &addr_data[addrlen..];
            }

            // The next address corresponds with RTA_IFA, or the interface's address

            let _addrlen = addr_data[0] as usize;
            let addr_family = addr_data[1] as i32;

            match addr_family {
                libc::AF_INET => {
                    // TODO: alignment *seems* like it would work out here...
                    let in_addr_bytes: [u8; mem::size_of::<libc::sockaddr_in>()] = addr_data
                        [2..2 + mem::size_of::<libc::sockaddr_in>()]
                        .try_into()
                        .unwrap();
                    unsafe {
                        let in_addr: libc::sockaddr_in = mem::transmute(in_addr_bytes);
                        addrs.push(IpAddr::V4(Ipv4Addr::from(in_addr.sin_addr.s_addr)));
                    }
                }
                libc::AF_INET6 => {
                    let in6_addr_bytes: [u8; mem::size_of::<libc::sockaddr_in6>()] = addr_data
                        [2..2 + mem::size_of::<libc::sockaddr_in6>()]
                        .try_into()
                        .unwrap();
                    unsafe {
                        let in6_addr: libc::sockaddr_in6 =
                            unsafe { mem::transmute(in6_addr_bytes) };
                        addrs.push(IpAddr::V6(Ipv6Addr::from(in6_addr.sin6_addr.s6_addr)));
                    }
                }
                _ => (), // We ignore link-layer (and other) addresses here
            }
        }

        Ok(addrs)
    }

    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match libc::write(self.ndrv_fd, buf.as_ptr() as *mut libc::c_void, buf.len()) {
                s @ 0.. => Ok(s as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

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
