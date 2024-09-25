use std::mem;

#[cfg(target_os = "freebsd")]
extern "C" {
    pub fn fdevname_r(
        fd: libc::c_int,
        buf: *mut libc::c_char,
        len: libc::c_int,
    ) -> *const libc::c_char;
}

/*
#[cfg(target_os = "dragonfly")]
extern "C" {
    pub fn fdevname_r(fd: libc::c_int, buf: *mut libc::c_char, len: libc::c_int) -> libc::c_int;
}
*/

pub const IOCPARM_MASK: u64 = 0x1fff; // parameter length, at most 13 bits
pub const IOCPARM_SHIFT: usize = 16;
pub const IOCGROUP_SHIFT: usize = 8;

#[allow(non_snake_case)]
pub const fn IOCPARM_LEN(x: u64) -> u64 {
    (x >> IOCPARM_SHIFT) & IOCPARM_MASK
}

#[allow(non_snake_case)]
pub const fn IOCBASECMD(x: u64) -> u64 {
    x & !(IOCPARM_MASK << IOCPARM_SHIFT)
}

#[allow(non_snake_case)]
pub const fn IOCGROUP(x: u64) -> u64 {
    ((x) >> IOCGROUP_SHIFT) & 0xff
}

pub const IOC_VOID: u64 = 0x20000000; // no parameters
pub const IOC_OUT: u64 = 0x40000000; // copy parameters out
pub const IOC_IN: u64 = 0x80000000; // copy parameters in
pub const IOC_INOUT: u64 = IOC_IN | IOC_OUT; // copy parameters in and out
pub const IOC_DIRMASK: u64 = 0xe0000000; // mask for IN | OUT | VOID

#[allow(non_snake_case)]
pub const fn _IOC(inout: u64, group: u64, num: u64, len: usize) -> u64 {
    inout
        | (((len & (IOCPARM_MASK as usize)) as u64) << IOCPARM_SHIFT)
        | (group << IOCGROUP_SHIFT)
        | num
}

#[allow(non_snake_case)]
pub const fn _IO(g: u8, n: u64) -> u64 {
    _IOC(IOC_VOID, g as u64, n, 0)
}

#[allow(non_snake_case)]
pub const fn _IOR<T: Sized>(g: u8, n: u64) -> u64 {
    _IOC(IOC_OUT, g as u64, n, mem::size_of::<T>())
}

#[allow(non_snake_case)]
pub const fn _IOW<T: Sized>(g: u8, n: u64) -> u64 {
    _IOC(IOC_IN, g as u64, n, mem::size_of::<T>())
}

#[allow(non_snake_case)]
pub const fn _IOWR<T: Sized>(g: u8, n: u64) -> u64 {
    _IOC(IOC_INOUT, g as u64, n, mem::size_of::<T>())
}

#[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
#[allow(non_camel_case_types)]
pub type caddr_t = *mut libc::c_char;

#[cfg(target_os = "openbsd")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[cfg(target_os = "openbsd")]
#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_vnetid: i64,
    pub ifru_media: u64,
    pub ifru_data: caddr_t, // MTU in `struct if_data`
    pub ifru_index: libc::c_uint,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_buffer: ifreq_buffer,
    pub ifru_flags: [libc::c_short; 2],
    pub ifru_index: libc::c_short,
    pub ifru_jid: libc::c_int,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_phys: libc::c_int,
    pub ifru_media: libc::c_int,
    pub ifru_data: caddr_t,
    pub ifru_cap: [libc::c_int; 2],
    pub ifru_fib: libc::c_uint,
    pub ifru_vlan_pcp: libc::c_uchar,
    pub ifru_nv: ifreq_nv_req,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ifreq_nv_req {
    pub buf_length: libc::c_uint,
    pub length: libc::c_uint,
    pub buffer: *mut libc::c_void,
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_space: libc::sockaddr_storage,
    pub ifru_flags: libc::c_short,
    pub ifru_addrflags: libc::c_int,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_dlt: libc::c_int,
    pub ifru_value: libc::c_uint,
    pub ifru_data: *mut libc::c_void,
    pub ifru_b: __c_anonymous_ifru_b,
}

#[cfg(target_os = "dragonfly")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[cfg(target_os = "dragonfly")]
#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_buffer: ifreq_buffer,
    pub ifru_flags: [libc::c_short; 2],
    pub ifru_index: libc::c_short,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_phys: libc::c_int,
    pub ifru_media: libc::c_int,
    pub ifru_data: *mut libc::c_void,
    pub ifru_cap: [libc::c_int; 2],
    pub ifru_pollcpu: libc::c_int,
    pub ifru_tsolen: libc::c_int,
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct __c_anonymous_ifru_b {
    pub b_buflen: u32,
    pub b_buf: *mut libc::c_void,
}

#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ifreq_buffer {
    pub length: libc::size_t,
    pub buffer: *mut libc::c_void,
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCIFCREATE: libc::c_ulong = _IOW::<ifreq>(b'i', 122);
#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCIFCREATE2: libc::c_ulong = _IOWR::<ifreq>(b'i', 124);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub const SIOCIFDESTROY: libc::c_ulong = _IOW::<ifreq>(b'i', 121);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub const SIOCGIFFLAGS: libc::c_ulong = _IOWR::<ifreq>(b'i', 17);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub const SIOCSIFFLAGS: libc::c_ulong = _IOW::<ifreq>(b'i', 16);

#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCGIFMTU: libc::c_ulong = 0xc0906933;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCGIFMTU: libc::c_ulong = _IOWR::<ifreq>(b'i', 126);

#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCSIFMTU: libc::c_ulong = 0x80906934;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCSIFMTU: libc::c_ulong = _IOW::<ifreq>(b'i', 127);
