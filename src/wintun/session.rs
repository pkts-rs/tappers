// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//!
//!
//!

#[cfg(target_os = "windows")]
use std::os::windows::raw::HANDLE;
use std::time::Duration;
use std::{cmp, io, ptr, thread};

use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use super::dll::WintunSession;
use super::TunAdapter;

/// A Wintun Session.
///
/// Each Session has its own unique ring for sending and receiving packets.
pub struct TunSession<'a> {
    adapter: &'a TunAdapter,
    session: *mut WintunSession,
    nonblocking: bool,
}

impl<'a> TunSession<'a> {
    pub const DEFAULT_RING_SIZE: u32 = 0x200000; // 128 kiB

    /*
    /// The default ring buffer size used for a `TunSession` (2 MiB).

    /// The minimum permitted ring buffer size that can be used for a `TunSession`.
    pub const MIN_RING_SIZE: u32 = 0x20000; // 2 MiB
    /// The maximum permitted ring buffer size that can be used for a `TunSession`.
    pub const MAX_RING_CAPACITY: u32 = 0x4000000; // 64 MiB
    */

    const SEND_MAX_BLOCKING_INTERVAL: u64 = 100;

    /// Creates a new `TunSession`.
    pub(crate) fn new(adapter: &'a TunAdapter, session: *mut WintunSession) -> Self {
        Self {
            adapter,
            session,
            nonblocking: false,
        }
    }

    /// Returns a `HANDLE` that can be used to poll for incoming packets.
    #[inline]
    pub fn read_handle(&self) -> HANDLE {
        Self::read_handle_impl(&self.adapter, self.session)
    }

    pub(crate) fn read_handle_impl(adapter: &TunAdapter, session: *mut WintunSession) -> HANDLE {
        // SAFETY: read_event_handle is thread-safe and does not actually mutate the `WintunSession`
        adapter.wintun.read_event_handle(session)
    }

    /// Sends a packet out on the TUN interface.
    ///
    /// If the sent packet would exceed the length of `buf`, the packet will be truncated to
    /// fit the receive buffer. As of current Wintun versions, a packet is guaranteed to be less
    /// than 65536 (2^16) bytes in length. As this could potentially change in future Wintun
    /// releases, received packets that are equal to the length of `buf` should be treated as if
    /// they have been truncated.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY:
        // Immutable `self` passes through a `*mut WintunSession` that is subsequently used.
        // To ensure this isn't UB, we need to:
        // 1. Ensure any use of this mutable pointer is thread-safe
        // 2. Watch out for mutation to the WintunSession while another reference is relying on its
        // state (e.g. iterator invalidation).
        Self::send_impl(&self.adapter, self.session, self.nonblocking, buf)
    }

    pub(crate) fn send_impl(
        adapter: &TunAdapter,
        session: *mut WintunSession,
        nonblocking: bool,
        buf: &[u8],
    ) -> io::Result<usize> {
        let packet_size = cmp::min(buf.len(), u16::MAX as usize);

        let mut timeout = 1; // 1 millisecond timeout initially
        let pkt = loop {
            // SAFETY: allocate_packet is thread-safe
            let pkt_res = adapter.wintun.allocate_packet(session, packet_size as u32);
            if nonblocking {
                break pkt_res.map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            } else {
                // Wintun doesn't implement blocking send, so we simulate its behavior here.
                match pkt_res {
                    Ok(pkt) => break pkt,
                    Err(_) => timeout = cmp::min(timeout * 2, Self::SEND_MAX_BLOCKING_INTERVAL),
                }
            }

            thread::sleep(Duration::from_millis(timeout));
        };

        unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), pkt.as_ptr(), packet_size) };

        // SAFETY: send_packet is thread-safe
        adapter.wintun.send_packet(session, pkt);

        Ok(packet_size)
    }

    /// Receives a packet from the TUN interface.
    ///
    /// If the received packet would exceed the length of `buf`, the packet will be truncated to
    /// fit the receive buffer. As of current Wintun versions, a packet is guaranteed to be less
    /// than 65536 (2^16) bytes in length. As this could potentially change in future Wintun
    /// releases, received packets that are equal to the length of `buf` should always be treated
    /// as if they have been truncated.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY:
        // Immutable `self` passes through a `*mut WintunSession` that is subsequently used.
        // To ensure this isn't UB, we need to:
        // 1. Ensure any use of this mutable pointer is thread-safe
        // 2. Watch out for mutation to the WintunSession while another reference is relying on its
        // state (e.g. iterator invalidation).
        Self::recv_impl(&self.adapter, self.session, self.nonblocking, buf)
    }

    pub(crate) fn recv_impl(
        adapter: &TunAdapter,
        session: *mut WintunSession,
        nonblocking: bool,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let mut packet_size = 0u32;

        // SAFETY: recv_packet is thread-safe
        let recv_pkt = match adapter.wintun.recv_packet(session, &mut packet_size) {
            Ok(pkt) => pkt,
            Err(e) if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) => loop {
                if nonblocking {
                    return Err(io::ErrorKind::WouldBlock.into());
                }

                let read_handle = adapter.wintun.read_event_handle(session);
                unsafe { WaitForSingleObject(read_handle, INFINITE) };
                if let Ok(pkt) = adapter.wintun.recv_packet(session, &mut packet_size) {
                    break pkt;
                }
            },
            Err(e) => return Err(e),
        };

        let output_size = cmp::min(packet_size as usize, buf.len());
        unsafe {
            ptr::copy_nonoverlapping(recv_pkt.as_ptr(), buf.as_mut_ptr(), output_size);
        }

        // SAFETY: free_packet is thread-safe
        adapter.wintun.free_packet(session, recv_pkt);

        Ok(output_size)
    }

    /// Indicates whether the `TunSession` is in nonblocking mode.
    ///
    /// See [`set_nonblocking()`](Self::set_nonblocking) for more information on blocking and
    /// nonblocking operation.
    pub fn nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Sets whether the session blocks on calls to [`send()`](Self::send) and
    /// [`recv()`](Self::recv).
    ///
    /// When the `TunSession` is set to nonblocking, these calls will return an [`io::Error`] of type
    /// [`ErrorKind::WouldBlock`](io::ErrorKind::WouldBlock) if no packets are ready to be sent
    /// or received. When the `TunSession` is set to blocking, these calls will block indefinitely
    /// until a packet can be sent or received.
    ///
    /// A NOTE FOR PERFORMANCE: Wintun does not natively support blocking `send()` or `recv()`; this
    /// functionality is provided by the `tappers` library. `recv()` is implemented via polling, but
    /// Wintun does not provide any ability to poll on `send()` when the packet queue is full.
    /// `tappers` overcomes this by calling nonblocking `send()` and sleeping between failed calls.
    /// The sleep interval begins at 1ms and doubles in length until maxing out at 100ms intervals
    /// (this algorithm is an opaque implementation detail that may change in the future).
    /// A consequence of this is that sending packets when a queue is full may be delayed by up to
    /// 100ms; if this is unacceptable for performance, consider using nonblocking `send()`/`recv()`
    /// and implementing a tighter resend loop.
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }
}

impl Drop for TunSession<'_> {
    fn drop(&mut self) {
        unsafe {
            self.adapter.wintun.end_session(self.session);
        }
    }
}
