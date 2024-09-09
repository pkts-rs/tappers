// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Run-time dynamic linking of the Wintun library.

#![allow(non_snake_case)]

use std::ptr::NonNull;
use std::{io, ptr};

use windows_sys::core::{GUID, PCWSTR};
use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use super::{WintunAdapter, WintunLoggerCallback, WintunPacket, WintunSession};

#[link(name = "wintun", kind = "raw-dylib")]
extern "C" {
    /// Creates a new Wintun adapter.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the adapter. Must be null-terminated and less than `MAX_ADAPTER_NAME`
    /// characters.
    /// * `tunnel_type` - The name of the adapter tunnel type. Must be null-terminated and less than
    /// `MAX_ADAPTER_NAME` characters.
    fn WintunCreateAdapter(
        name: PCWSTR,
        tunnel_type: PCWSTR,
        requested_guid: GUID,
    ) -> *mut WintunAdapter;

    /// Opens an existing Wintun adapter.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the adapter. Must be null-terminated and less than `MAX_ADAPTER_NAME`
    fn WintunOpenAdapter(name: PCWSTR) -> *mut WintunAdapter;

    /// Releases resources for the specified adapter. If `adapter` was created with
    /// `WintunCreateAdapter`, removes the adapter from the system.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The handle of the adapter to be closed.
    fn WintunCloseAdapter(adapter: *mut WintunAdapter);

    /// Deletes the Wintun driver. If any adapters are currently in use, this call will fail
    ///
    fn WintunDeleteDriver() -> BOOL;

    /// Returns the LUID of the adapter.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The handle of the adapter to obtain the LUID for.
    /// * `luid` - A pointer that receives the adapter LUID
    fn WintunGetAdapterLUID(adapter: *mut WintunAdapter, luid: *mut NET_LUID_LH);

    /// Returns the version number for the loaded Wintun driver.
    ///
    /// # Errors
    ///
    /// If Wintun is not loaded at the time this method is called, a value of 0 will be returned
    /// and `ERROR_FILE_NOT_FOUND` will be added to the error queue.
    fn WintunGetRunningDriverVersion() -> u32;

    /// Sets the callback function to be calledd at each log event.
    fn WintunSetLogger(log_callback: WintunLoggerCallback);

    /// Starts a Wintun session.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The adapter the session will be running on
    /// * `capacity` - The capacity of the ring buffer used for the session. Must be a power of
    /// two.
    fn WintunStartSession(adapter: *mut WintunAdapter, capacity: u32) -> *mut WintunSession;

    /// Ends the given Wintun session.
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session to be ended.
    fn WintunEndSession(session: *mut WintunSession);

    /// Gets the Wintun session's read-wait event handle to use for waiting for available reads.
    fn WintunGetReadWaitEvent(session: *mut WintunSession) -> HANDLE;

    /// Retrieves a single packet from the Wintun interface.
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session to receive packets from
    /// * `packet_size` - The size of the returned `BYTE` buffer
    ///
    /// # Safety
    ///
    /// The `BYTE` buffer received by this function must be released using
    /// `WintunReleaseReceivePacket`. This function is thread-safe.
    fn WintunReceivePacket(session: *mut WintunSession, packet_size: *mut u32) -> *mut u8;

    /// Releases internal resources for a packet received on the given Wintun session.
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session the packet was received from
    /// * `packet` - A packet obtained with `WintunReceivePacket`
    fn WintunReleaseReceivePacket(session: *mut WintunSession, packet: *mut u8);

    /// Allocates a packet to be sent over the Wintun session.
    ///
    /// Note that the order in which packets are allocated using this function determines the
    /// order in which they are sent. For example, if packet A, B, C are allocated in order and then
    /// sent in reverse (C, B, A), the order in which they are actually sent over the interface will
    /// still be (A, B, C).
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session the packets will be sent over
    /// * `packet_size` - The exact packet size (must be less than or equal to
    /// `WINTUN_MAX_IP_PACKET_SIZE`).
    ///
    /// # Errors
    ///
    /// On failure, this function will return a NULL pointer and add an error to the queue. The
    /// error may be one of the following:
    ///
    /// * `ERROR_HANDLE_EOF` - The Wintun adapter is terminating.
    /// * `ERROR_BUFFER_OVERFLOW` - There is insufficient space in the Wintun session's internal
    /// buffer to allocate an additional buffer. The application should generally wait some time for
    /// packets to be sent over the interface and then try again.
    ///
    /// # Safety
    ///
    /// This function is thread-safe.
    fn WintunAllocateSendPacket(session: *mut WintunSession, packet_size: u32) -> *mut u8;

    /// Sends the packet and releases its internal buffer.
    ///
    /// # Safety
    ///
    /// This function is thread-safe.
    fn WintunSendPacket(session: *mut WintunSession, packet: *mut u8);
}

pub struct Wintun;

impl Wintun {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }

    pub fn driver_version(&self) -> io::Result<u32> {
        let version = unsafe { WintunGetRunningDriverVersion() };
        match version {
            0 => Err(io::Error::last_os_error()),
            v => Ok(v),
        }
    }

    pub fn create_adapter(
        &self,
        name: &[u16],
        tunnel_type: &[u16],
        requested_guid: GUID,
    ) -> io::Result<NonNull<WintunAdapter>> {
        if name.last() != Some(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "adapter name not null-terminated",
            ));
        }

        if tunnel_type.last() != Some(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tunnel type not null-terminated",
            ));
        }

        let handle =
            unsafe { WintunCreateAdapter(name.as_ptr(), tunnel_type.as_ptr(), requested_guid) };
        NonNull::new(handle).ok_or(io::Error::last_os_error())
    }

    pub fn open_adapter(&self, name: &[u16]) -> io::Result<NonNull<WintunAdapter>> {
        if name.last() != Some(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "adapter name not null-terminated",
            ));
        }

        let handle = unsafe { WintunOpenAdapter(name.as_ptr()) };
        NonNull::new(handle).ok_or(io::Error::last_os_error())
    }

    pub unsafe fn close_adapter(&self, adapter: *mut WintunAdapter) {
        WintunCloseAdapter(adapter)
    }

    pub fn delete_driver(&self) -> io::Result<()> {
        if unsafe { WintunDeleteDriver() } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn get_adapter_luid(&self, adapter: &mut WintunAdapter) -> NET_LUID_LH {
        let mut luid = NET_LUID_LH { Value: 0 };

        unsafe {
            WintunGetAdapterLUID(adapter, ptr::addr_of_mut!(luid));
        }

        luid
    }

    pub unsafe fn set_logger(&self, log_callback: WintunLoggerCallback) {
        WintunSetLogger(log_callback);
    }

    pub fn start_session(
        &self,
        adapter: &mut WintunAdapter,
        capacity: u32,
    ) -> io::Result<NonNull<WintunSession>> {
        let session = unsafe { WintunStartSession(adapter, capacity) };
        NonNull::new(session).ok_or(io::Error::last_os_error())
    }

    pub unsafe fn end_session(&self, session: *mut WintunSession) {
        WintunEndSession(session)
    }

    pub fn read_event_handle(&self, session: &mut WintunSession) -> HANDLE {
        unsafe { WintunGetReadWaitEvent(session) }
    }

    pub fn recv_packet(
        &self,
        session: &mut WintunSession,
        packet_size: &mut u32,
    ) -> io::Result<WintunPacket> {
        let pkt = unsafe { WintunReceivePacket(session, packet_size) };
        NonNull::new(pkt).ok_or(io::Error::last_os_error())
    }

    pub fn free_packet(&self, session: &mut WintunSession, packet: WintunPacket) {
        unsafe {
            WintunReleaseReceivePacket(session, packet.as_ptr());
        }
    }

    pub fn allocate_packet(
        &self,
        session: &mut WintunSession,
        packet_size: u32,
    ) -> io::Result<WintunPacket> {
        let pkt = unsafe { WintunAllocateSendPacket(session, packet_size) };
        NonNull::new(pkt).ok_or(io::Error::last_os_error())
    }

    pub fn send_packet(&self, session: &mut WintunSession, packet: WintunPacket) {
        unsafe { WintunSendPacket(session, packet.as_ptr()) }
    }
}
