// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]

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

#[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "macos"))]
pub const SCOPE6_ID_MAX: usize = 16;

#[allow(unused)]
pub const IOCPARM_MASK: u64 = 0x1fff; // parameter length, at most 13 bits
#[allow(unused)]
pub const IOCPARM_SHIFT: usize = 16;
#[allow(unused)]
pub const IOCGROUP_SHIFT: usize = 8;

#[allow(unused)]
pub const IOC_VOID: u64 = 0x20000000; // no parameters
#[allow(unused)]
pub const IOC_OUT: u64 = 0x40000000; // copy parameters out
#[allow(unused)]
pub const IOC_IN: u64 = 0x80000000; // copy parameters in
#[allow(unused)]
pub const IOC_INOUT: u64 = IOC_IN | IOC_OUT; // copy parameters in and out
#[allow(unused)]
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

/*
#[cfg(target_os = "linux")]
#[allow(non_snake_case)]
pub const fn NLMSG_LENGTH(len: usize) -> usize {
    len + NLMSG_HDRLEN
}
*/

#[cfg(target_os = "linux")]
#[allow(non_snake_case)]
pub const fn NLMSG_ALIGN(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[allow(non_snake_case)]
pub const fn RT_ROUNDUP(len: usize) -> usize {
    if len == 0 {
        return mem::size_of::<libc::c_long>();
    } else {
        1 + ((len - 1) | (mem::size_of::<libc::c_long>() - 1))
    }
}

/*
#[cfg(target_os = "linux")]
pub const NLMSG_HDRLEN: usize = NLMSG_ALIGN(mem::size_of::<libc::nlmsghdr>());
*/
#[cfg(target_os = "linux")]
pub const NLMSG_ALIGNTO: usize = 4;

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "openbsd"))]
pub type caddr_t = *mut libc::c_char;

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct sockaddr_nl {
    pub nl_family: libc::sa_family_t,
    pub nl_pad: libc::c_ushort,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: libc::c_uchar,
    pub ifa_prefixlen: libc::c_uchar,
    pub ifa_flags: libc::c_uchar,
    pub ifa_scope: libc::c_uchar,
    pub ifa_index: libc::c_uint,
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct ndmsg {
    pub ndm_index: libc::c_int,
    pub ndm_state: u16,
    pub ndm_flags: u8,
    pub ndm_type: u8,
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct rtmsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/*
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct rta_cacheinfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: i32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}
*/

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_phys: libc::c_int,
    pub ifru_media: libc::c_int,
    pub ifru_intval: libc::c_int,
    pub ifru_data: caddr_t,
    pub ifru_devmtu: ifdevmtu,
    pub ifru_kpi: libc::ifkpi,
    pub ifru_wake_flags: u32,
    pub ifru_route_refcnt: u32,
    pub ifru_cap: [libc::c_int; 2],
    pub ifru_functional_type: u32,
    pub ifru_is_directlink: u8,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifdevmtu {
    ifdm_current: libc::c_int,
    ifdm_min: libc::c_int,
    ifdm_max: libc::c_int,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifkpi {
    pub ifk_module_id: libc::c_uint,
    pub ifk_type: libc::c_uint,
    pub ifk_data: __c_anonymous_ifk_data,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct __c_anonymous_ifk_data {
    pub ifk_ptr: *mut libc::c_void,
    pub ifk_value: libc::c_int,
}

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

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
pub struct in6_ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_in6_ifr_ifru,
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
#[derive(Clone, Copy)]
pub union __c_anonymous_in6_ifr_ifru {
    pub ifru_addr: libc::sockaddr_in6,
    pub ifru_dstaddr: libc::sockaddr_in6,
    pub ifru_flags: libc::c_short,
    pub ifru_flags6: libc::c_int,
    pub ifru_metric: libc::c_int,
    #[cfg(target_os = "macos")]
    pub ifru_intval: libc::c_int,
    pub ifru_data: *mut libc::c_void,
    pub ifru_lifetime: in6_addrlifetime,
    pub ifru_stat: in6_ifstat,
    pub ifru_icmp6stat: icmp6_ifstat,
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "macos"))]
    pub ifru_scope_id: [u32; SCOPE6_ID_MAX],
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_ifstat {
    pub ifs6_in_receive: u64,
    pub ifs6_in_hdrerr: u64,
    pub ifs6_in_toobig: u64,
    pub ifs6_in_noroute: u64,
    pub ifs6_in_addrerr: u64,
    pub ifs6_in_protounknown: u64,
    pub ifs6_in_truncated: u64,
    pub ifs6_in_discard: u64,
    pub ifs6_in_deliver: u64,
    pub ifs6_out_forward: u64,
    pub ifs6_out_request: u64,
    pub ifs6_out_discard: u64,
    pub ifs6_out_fragok: u64,
    pub ifs6_out_fragfail: u64,
    pub ifs6_out_fragcreat: u64,
    pub ifs6_reass_reqd: u64,
    pub ifs6_reass_ok: u64,
    pub ifs6_atmfrag_rcvd: u64,
    pub ifs6_reass_fail: u64,
    pub ifs6_in_mcast: u64,
    pub ifs6_out_mcast: u64,
    pub ifs6_cantfoward_icmp6: u64,
    pub ifs6_addr_expiry_cnt: u64,
    pub ifs6_pfx_expiry_cnt: u64,
    pub ifs6_defrtr_expiry_cnt: u64,
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_ifstat {
    pub ifs6_in_receive: u64,
    pub ifs6_in_hdrerr: u64,
    pub ifs6_in_toobig: u64,
    pub ifs6_in_noroute: u64,
    pub ifs6_in_addrerr: u64,
    pub ifs6_in_protounknown: u64,
    pub fs6_in_truncated: u64,
    pub ifs6_in_discard: u64,
    pub ifs6_in_deliver: u64,
    pub ifs6_out_forward: u64,
    pub ifs6_out_request: u64,
    pub ifs6_out_discard: u64,
    pub ifs6_out_fragok: u64,
    pub ifs6_out_fragfail: u64,
    pub ifs6_out_fragcreat: u64,
    pub ifs6_reass_reqd: u64,
    pub ifs6_reass_ok: u64,
    pub ifs6_reass_fail: u64,
    pub ifs6_in_mcast: u64,
    pub ifs6_out_mcast: u64,
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct icmp6_ifstat {
    pub ifs6_in_msg: u64,
    pub ifs6_in_error: u64,
    pub ifs6_in_dstunreach: u64,
    pub ifs6_in_adminprohib: u64,
    pub ifs6_in_timeexceed: u64,
    pub ifs6_in_paramprob: u64,
    pub ifs6_in_pkttoobig: u64,
    pub ifs6_in_echo: u64,
    pub ifs6_in_echoreply: u64,
    pub ifs6_in_routersolicit: u64,
    pub ifs6_in_routeradvert: u64,
    pub ifs6_in_neighborsolicit: u64,
    pub ifs6_in_neighboradvert: u64,
    pub ifs6_in_redirect: u64,
    pub ifs6_in_mldquery: u64,
    pub ifs6_in_mldreport: u64,
    pub ifs6_in_mlddone: u64,
    pub ifs6_out_msg: u64,
    pub ifs6_out_error: u64,
    pub ifs6_out_dstunreach: u64,
    pub ifs6_out_adminprohib: u64,
    pub ifs6_out_timeexceed: u64,
    pub ifs6_out_paramprob: u64,
    pub ifs6_out_pkttoobig: u64,
    pub ifs6_out_echo: u64,
    pub ifs6_out_echoreply: u64,
    pub ifs6_out_routersolicit: u64,
    pub ifs6_out_routeradvert: u64,
    pub ifs6_out_neighborsolicit: u64,
    pub ifs6_out_neighboradvert: u64,
    pub ifs6_out_redirect: u64,
    pub ifs6_out_mldquery: u64,
    pub ifs6_out_mldreport: u64,
    pub ifs6_out_mlddone: u64,
}

// TODO: DragonFlyBSD technically has `sockaddr` rather than `sockaddr_in` but they size the same.
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
pub struct ifaliasreq {
    pub ifra_name: [libc::c_char; libc::IFNAMSIZ],
    #[cfg(not(target_os = "openbsd"))]
    pub ifra_addr: libc::sockaddr_in,
    #[cfg(target_os = "openbsd")]
    pub ifra_ifrau: __c_anonymous_ifra_ifrau,
    pub ifra_broadaddr: libc::sockaddr_in, // Also potentially dstaddr
    pub ifra_mask: libc::sockaddr_in,
    #[cfg(target_os = "freebsd")]
    pub ifra_vhid: libc::c_int,
}

#[cfg(target_os = "openbsd")]
#[repr(C)]
pub union __c_anonymous_ifra_ifrau {
    pub ifrau_addr: libc::sockaddr_in,
    pub ifrau_align: libc::c_int,
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[repr(C)]
pub struct in6_aliasreq {
    pub ifra_name: [libc::c_char; libc::IFNAMSIZ],
    #[cfg(not(target_os = "openbsd"))]
    pub ifra_addr: libc::sockaddr_in6,
    #[cfg(target_os = "openbsd")]
    pub ifra_ifrau: __c_anonymous_in6_ifra_ifrau,
    pub ifra_broadaddr: libc::sockaddr_in6, // Also dstaddr
    pub ifra_prefixmask: libc::sockaddr_in6,
    pub ifra_flags: libc::c_int,
    pub ifra_lifetime: in6_addrlifetime,
    #[cfg(target_os = "freebsd")]
    pub ifra_vhid: libc::c_int,
}

#[cfg(target_os = "openbsd")]
#[repr(C)]
pub union __c_anonymous_in6_ifra_ifrau {
    pub ifrau_addr: libc::sockaddr_in6,
    pub ifrau_align: libc::c_int,
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct in6_addrlifetime {
    pub ia6t_expire: libc::time_t,
    pub ia6t_preferred: libc::time_t,
    pub ia6t_vltime: u32,
    pub ia6t_pltime: u32,
}

#[cfg(target_os = "macos")]
pub use libc::ifa_msghdr;

#[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifa_msghdr {
    pub ifam_msglen: libc::c_ushort,
    pub ifam_version: libc::c_uchar,
    pub ifam_type: libc::c_uchar,
    #[cfg(target_os = "openbsd")]
    pub ifam_hdrlen: libc::c_ushort,
    pub ifam_index: libc::c_ushort,
    #[cfg(target_os = "openbsd")]
    pub ifam_tableid: libc::c_ushort,
    #[cfg(target_os = "openbsd")]
    pub ifam_pad1: libc::c_uchar,
    #[cfg(target_os = "openbsd")]
    pub ifam_pad2: libc::c_uchar,
    #[cfg(target_os = "dragonfly")]
    pub ifam_flags: libc::c_int,
    pub ifam_addrs: libc::c_int,
    #[cfg(target_os = "openbsd")]
    pub ifam_flags: libc::c_int,
    #[cfg(target_os = "dragonfly")]
    pub ifam_addrflags: libc::c_int,
    pub ifam_metric: libc::c_int,
}

#[cfg(target_os = "freebsd")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifa_msghdr {
    pub ifam_msglen: libc::c_ushort,
    pub ifam_version: libc::c_uchar,
    pub ifam_type: libc::c_uchar,
    pub ifam_addrs: libc::c_int,
    pub ifam_flags: libc::c_int,
    pub ifam_index: libc::c_ushort,
    pub _ifam_spare1: libc::c_ushort,
    pub ifam_metric: libc::c_int,
}

#[cfg(target_os = "netbsd")]
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct ifa_msghdr {
    pub ifam_msglen: libc::c_ushort,
    pub ifam_version: libc::c_uchar,
    pub ifam_type: libc::c_uchar,
    pub ifam_index: libc::c_ushort,
    pub ifam_flags: libc::c_int,
    pub ifam_addrs: libc::c_int,
    pub ifam_pid: libc::pid_t,
    pub ifam_addrflags: libc::c_int,
    pub ifam_metric: libc::c_int,
}

/*
#[cfg(target_os = "macos")]
pub use libc::rt_msghdr;

#[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort,
    pub rtm_version: libc::c_uchar,
    pub rtm_type: libc::c_uchar,
    #[cfg(target_os = "openbsd")]
    pub rtm_hdrlen: libc::c_ushort,
    pub rtm_index: libc::c_ushort,
    #[cfg(target_os = "openbsd")]
    pub rtm_tableid: libc::c_ushort,
    #[cfg(target_os = "openbsd")]
    pub rtm_priority: libc::c_uchar,
    #[cfg(target_os = "openbsd")]
    pub rtm_mpls: libc::c_uchar,
    #[cfg(target_os = "freebsd")]
    pub _rtm_spare1: libc::c_ushort,
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    pub rtm_flags: libc::c_int,
    pub rtm_addrs: libc::c_int,
    #[cfg(target_os = "openbsd")]
    pub rtm_flags: libc::c_int,
    #[cfg(target_os = "openbsd")]
    pub rtm_fmask: libc::c_int,
    pub rtm_pid: libc::pid_t,
    pub rtm_seq: libc::c_int,
    pub rtm_errno: libc::c_int,
    #[cfg(target_os = "dragonfly")]
    pub rtm_use: libc::c_int,
    #[cfg(target_os = "freebsd")]
    pub rtm_fmask: libc::c_int,
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    pub rtm_inits: libc::c_ulong,
    #[cfg(target_os = "openbsd")]
    pub rtm_inits: libc::c_uint,
    pub rtm_rmx: rt_metrics,
}

#[cfg(target_os = "freebsd")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort,
    pub rtm_version: libc::c_uchar,
    pub rtm_type: libc::c_uchar,
    pub rtm_index: libc::c_ushort,
    pub _rtm_spare1: libc::c_ushort,
    pub rtm_flags: libc::c_int,
    pub rtm_addrs: libc::c_int,
    pub rtm_pid: libc::pid_t,
    pub rtm_seq: libc::c_int,
    pub rtm_errno: libc::c_int,
    pub rtm_fmask: libc::c_int,
    pub rtm_inits: libc::c_ulong,
    pub rtm_rmx: rt_metrics,
}

#[cfg(target_os = "netbsd")]
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort,
    pub rtm_version: libc::c_uchar,
    pub rtm_type: libc::c_uchar,
    pub rtm_index: libc::c_ushort,
    pub rtm_flags: libc::c_int,
    pub rtm_addrs: libc::c_int,
    pub rtm_pid: libc::pid_t,
    pub rtm_seq: libc::c_int,
    pub rtm_errno: libc::c_int,
    pub rtm_use: libc::c_int,
    pub rtm_inits: libc::c_int,
    pub rtm_rmx: rt_metrics,
}

#[cfg(target_os = "dragonfly")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_metrics {
    /* grouped for locality of reference */
    pub rmx_locks: libc::c_ulong,
    pub rmx_mtu: libc::c_ulong,
    pub rmx_pksent: libc::c_ulong,
    pub rmx_expire: libc::c_ulong,
    pub rmx_sendpipe: libc::c_ulong,
    pub rmx_ssthresh: libc::c_ulong,
    pub rmx_rtt: libc::c_ulong,
    pub rmx_rttvar: libc::c_ulong,
    pub rmx_recvpipe: libc::c_ulong,
    pub rmx_hopcount: libc::c_ulong,
    pub rmx_mssopt: libc::c_ushort,
    pub rmx_pad: libc::c_ushort,
    pub rmx_msl: libc::c_ulong,
    pub rmx_iwmaxsegs: libc::c_ulong,
    pub rmx_iwcapsegs: libc::c_ulong,
}

#[cfg(target_os = "openbsd")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_metrics {
    pub rmx_pksent: u64,
    pub rmx_expire: i64,
    pub rmx_locks: libc::c_uint,
    pub rmx_mtu: libc::c_uint,
    pub rmx_refcnt: libc::c_uint,
    pub rmx_hopcount: libc::c_uint,
    pub rmx_recvpipe: libc::c_uint,
    pub rmx_sendpipe: libc::c_uint,
    pub rmx_ssthresh: libc::c_uint,
    pub rmx_rtt: libc::c_uint,
    pub rmx_rttvar: libc::c_uint,
    pub rmx_pad: libc::c_uint,
}

#[cfg(target_os = "freebsd")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_metrics {
    /* grouped for locality of reference */
    pub rmx_locks: libc::c_ulong,
    pub rmx_mtu: libc::c_ulong,
    pub rmx_hopcount: libc::c_ulong,
    pub rmx_expire: libc::c_ulong,
    pub rmx_recvpipe: libc::c_ulong,
    pub rmx_sendpipe: libc::c_ulong,
    pub rmx_ssthresh: libc::c_ulong,
    pub rmx_rtt: libc::c_ulong,
    pub rmx_rttvar: libc::c_ulong,
    pub rmx_pksent: libc::c_ulong,
    pub rmx_weight: libc::c_ulong,
    pub rmx_nhidx: libc::c_ulong,
    pub rmx_filter: [libc::c_ulong; 2],
}

#[cfg(target_os = "netbsd")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct rt_metrics {
    /* grouped for locality of reference */
    pub rmx_locks: libc::c_ulong,
    pub rmx_mtu: libc::c_ulong,
    pub rmx_hopcount: libc::c_ulong,
    pub rmx_recvpipe: libc::c_ulong,
    pub rmx_sendpipe: libc::c_ulong,
    pub rmx_ssthresh: libc::c_ulong,
    pub rmx_rtt: libc::c_ulong,
    pub rmx_rttvar: libc::c_ulong,
    pub rmx_expire: libc::time_t,
    pub rmx_pktsent: libc::time_t,
}
*/

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct if_fake_request {
    pub iffr_reserved: [u64; 4],
    pub iffr_u: __c_anonymous_iffr_u,
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub union __c_anonymous_iffr_u {
    pub iffru_buf: [libc::c_char; 128],
    pub iffru_media: if_fake_media,
    pub iffru_peer_name: [libc::c_char; libc::IFNAMSIZ],
    pub iffru_dequeue_stall: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct if_fake_media {
    pub iffm_current: i32,
    pub iffm_count: u32,
    pub iffm_reserved: [u32; 3],
    pub iffm_list: [i32; IF_FAKE_MEDIA_LIST_MAX],
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct ifdrv {
    pub ifd_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifd_cmd: libc::c_ulong,
    pub ifd_len: libc::size_t,
    pub ifd_data: *mut libc::c_void,
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct sockaddr_ndrv {
    pub snd_len: libc::c_uchar,
    pub snd_family: libc::c_uchar,
    pub snd_name: [libc::c_uchar; libc::IFNAMSIZ],
}

// <net/if_fake_var.h>
#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_S_CMD_NONE: u64 = 0;
#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_S_CMD_SET_PEER: u64 = 1;
#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_S_CMD_SET_MEDIA: u64 = 2;
#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_S_CMD_SET_DEQUEUE_STALL: u64 = 3;

#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_G_CMD_NONE: u64 = 0;
#[cfg(target_os = "macos")]
#[allow(unused)]
pub const IF_FAKE_G_CMD_GET_PEER: u64 = 1;
#[cfg(target_os = "macos")]
pub const IF_FAKE_MEDIA_LIST_MAX: usize = 27;

#[cfg(target_os = "macos")]
pub const SIOCIFCREATE: libc::c_ulong = _IOWR::<ifreq>(b'i', 120);
//#[cfg(target_os = "macos")]
//pub const SIOCIFCREATE2: libc::c_ulong = _IOWR::<ifreq>(b'i', 122);
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCIFCREATE: libc::c_ulong = _IOW::<ifreq>(b'i', 122);
#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCIFCREATE2: libc::c_ulong = _IOWR::<ifreq>(b'i', 124);
//#[cfg(target_os = "macos")]
//pub const SIOCGDRVSPEC: libc::c_ulong = _IOWR::<ifdrv>(b'i', 123);
#[cfg(target_os = "macos")]
pub const SIOCSDRVSPEC: libc::c_ulong = _IOW::<ifdrv>(b'i', 123);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub const SIOCIFDESTROY: libc::c_ulong = _IOW::<ifreq>(b'i', 121);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub const SIOCGIFFLAGS: libc::c_ulong = _IOWR::<ifreq>(b'i', 17);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub const SIOCSIFFLAGS: libc::c_ulong = _IOW::<ifreq>(b'i', 16);
#[cfg(target_os = "macos")]
pub const SIOCGIFDEVMTU: libc::c_ulong = _IOWR::<ifreq>(b'i', 68);
#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCGIFMTU: libc::c_ulong = 0xc0906933;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCGIFMTU: libc::c_ulong = _IOWR::<ifreq>(b'i', 126);

#[cfg(target_os = "macos")]
pub const SIOCSIFMTU: libc::c_ulong = _IOW::<ifreq>(b'i', 52);
#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
pub const SIOCSIFMTU: libc::c_ulong = 0x80906934;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
pub const SIOCSIFMTU: libc::c_ulong = _IOW::<ifreq>(b'i', 127);

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub const SIOCDIFADDR: libc::c_ulong = _IOW::<ifreq>(b'i', 25);

#[cfg(any(
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub const SIOCAIFADDR: libc::c_ulong = _IOW::<ifaliasreq>(b'i', 26);
#[cfg(target_os = "freebsd")]
pub const SIOCAIFADDR: libc::c_ulong = _IOW::<ifaliasreq>(b'i', 43);

#[cfg(target_os = "macos")]
pub const SIOCSIFLLADDR: libc::c_ulong = _IOW::<ifreq>(b'i', 60);
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub const SIOCDIFADDR_IN6: libc::c_ulong = _IOW::<in6_ifreq>(b'i', 25);

#[cfg(any(target_os = "dragonfly", target_os = "macos", target_os = "openbsd"))]
pub const SIOCAIFADDR_IN6: libc::c_ulong = _IOW::<in6_aliasreq>(b'i', 26);
#[cfg(target_os = "freebsd")]
pub const SIOCAIFADDR_IN6: libc::c_ulong = _IOW::<in6_aliasreq>(b'i', 27);
#[cfg(target_os = "netbsd")]
pub const SIOCAIFADDR_IN6: libc::c_ulong = _IOW::<in6_aliasreq>(b'i', 107);

#[allow(unused)]
pub const RTA_DST: libc::c_int = 0x1;
#[allow(unused)]
pub const RTA_GATEWAY: libc::c_int = 0x2;
#[allow(unused)]
pub const RTA_NETMASK: libc::c_int = 0x4;
#[allow(unused)]
pub const RTA_GENMASK: libc::c_int = 0x8;
#[allow(unused)]
pub const RTA_IFP: libc::c_int = 0x10;
#[allow(unused)]
pub const RTA_IFA: libc::c_int = 0x20;
#[allow(unused)]
pub const RTA_AUTHOR: libc::c_int = 0x40;
#[allow(unused)]
pub const RTA_BRD: libc::c_int = 0x80;

#[allow(unused)]
pub const RTAX_DST: libc::c_int = 0;
#[allow(unused)]
pub const RTAX_GATEWAY: libc::c_int = 1;
#[allow(unused)]
pub const RTAX_NETMASK: libc::c_int = 2;
#[allow(unused)]
pub const RTAX_GENMASK: libc::c_int = 3;
#[allow(unused)]
pub const RTAX_IFP: libc::c_int = 4;
#[allow(unused)]
pub const RTAX_IFA: libc::c_int = 5;
#[allow(unused)]
pub const RTAX_AUTHOR: libc::c_int = 6;
#[allow(unused)]
pub const RTAX_BRD: libc::c_int = 7;

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd"
))]
#[allow(unused)]
pub const RTM_NEWADDR: libc::c_int = 0xc;
#[cfg(target_os = "netbsd")]
#[allow(unused)]
pub const RTM_NEWADDR: libc::c_int = 0x16;

#[cfg(target_os = "macos")]
pub const AF_LINK: libc::c_int = 18;
#[cfg(target_os = "macos")]
pub const AF_NDRV: libc::c_int = 27;

#[allow(unused)]
pub const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
