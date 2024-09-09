// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(feature = "wintun-runtime")]
mod dlopen;
#[cfg(not(feature = "wintun-runtime"))]
mod link;

use std::ptr::NonNull;

#[cfg(feature = "wintun-runtime")]
pub use dlopen::Wintun;
#[cfg(not(feature = "wintun-runtime"))]
pub use link::Wintun;

use windows_sys::core::PCWSTR;

/*
/// The minimum ring capacity of a Wintun interface.
pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x20000; // 128kiB
/// The maximum ring capacity of a Wintun interface.
pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x4000000; // 64MiB
/// The maximum IP packet size that can be moved through a Wintun interface.
const WINTUN_MAX_IP_PACKET_SIZE: u32 = 0xFFFF;
*/

/// An opaque Wintun adapter type that WINTUN_ADAPTER_HANDLE would point to.
pub type WintunAdapter = libc::c_void;

/// An opaque Wintun session type that WINTUN_SESSION_HANDLE would point to.
pub type WintunSession = libc::c_void;

pub type WintunPacket = NonNull<u8>;

/// Called by internal logger to report diagnostic messages.
///
/// #Arguments
/// * `level` The log level of the message
/// * `timestamp` The time at which the message was logged, measured in 100ns intervals since
/// 1601-01-01 UTC
/// * `message` The text of the log message
pub type WintunLoggerCallback =
    unsafe extern "C" fn(level: WintunLoggerLevel, timestamp: u64, message: PCWSTR);

#[repr(C)]
pub enum WintunLoggerLevel {
    /// Informational logs
    Info,
    /// Warning logs
    Warn,
    /// Error logs
    Err,
}
