// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Run-time dynamic loading of the Wintun library.

#![allow(non_snake_case)]

use std::ffi::{CStr, OsStr};
use std::fs::{File, OpenOptions};
#[cfg(any(not(doc), target_os = "windows"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(any(not(doc), target_os = "windows"))]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(any(not(doc), target_os = "windows"))]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::{io, mem};

use windows_sys::core::{BOOL, GUID, PCWSTR};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use super::{WintunAdapter, WintunLoggerCallback, WintunPacket, WintunSession};

const WINTUN_LIB: &str = "wintun.dll";

pub struct Wintun {
    api: WintunApi,
}

struct WintunApi {
    /// Creates a new Wintun adapter.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the adapter. Must be null-terminated and less than `MAX_ADAPTER_NAME`
    ///   characters.
    /// * `tunnel_type` - The name of the adapter tunnel type. Must be null-terminated and less than
    ///   `MAX_ADAPTER_NAME` characters.
    WintunCreateAdapter: unsafe extern "C" fn(
        name: PCWSTR,
        tunnel_type: PCWSTR,
        requested_guid: GUID,
    ) -> *mut WintunAdapter,

    /// Opens an existing Wintun adapter.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the adapter. Must be null-terminated and less than `MAX_ADAPTER_NAME`
    WintunOpenAdapter: unsafe extern "C" fn(name: PCWSTR) -> *mut WintunAdapter,

    /// Releases resources for the specified adapter. If `adapter` was created with
    /// `WintunCreateAdapter`, removes the adapter from the system.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The handle of the adapter to be closed.
    WintunCloseAdapter: unsafe extern "C" fn(adapter: *mut WintunAdapter),

    /// Deletes the Wintun driver. If any adapters are currently in use, this call will fail
    ///
    WintunDeleteDriver: unsafe extern "C" fn() -> BOOL,

    /// Returns the LUID of the adapter.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The handle of the adapter to obtain the LUID for.
    /// * `luid` - A pointer that receives the adapter LUID
    WintunGetAdapterLUID: unsafe extern "C" fn(adapter: *mut WintunAdapter, luid: *mut NET_LUID_LH),

    /// Returns the version number for the loaded Wintun driver.
    ///
    /// # Errors
    ///
    /// If Wintun is not loaded at the time this method is called, a value of 0 will be returned
    /// and `ERROR_FILE_NOT_FOUND` will be added to the error queue.
    WintunGetRunningDriverVersion: unsafe extern "C" fn() -> u32,

    /// Sets the callback function to be called at each log event.
    WintunSetLogger: unsafe extern "C" fn(log_callback: WintunLoggerCallback),

    /// Starts a Wintun session.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The adapter the session will be running on
    /// * `capacity` - The capacity of the ring buffer used for the session. Must be a power of
    ///   two.
    WintunStartSession:
        unsafe extern "C" fn(adapter: *mut WintunAdapter, capacity: u32) -> *mut WintunSession,

    /// Ends the given Wintun session.
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session to be ended.
    WintunEndSession: unsafe extern "C" fn(session: *mut WintunSession),

    /// Gets the Wintun session's read-wait event handle to use for waiting for available reads.
    WintunGetReadWaitEvent: unsafe extern "C" fn(session: *mut WintunSession) -> HANDLE,

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
    WintunReceivePacket:
        unsafe extern "C" fn(session: *mut WintunSession, packet_size: *mut u32) -> *mut u8,

    /// Releases internal resources for a packet received on the given Wintun session.
    ///
    /// # Arguments
    ///
    /// * `session` - The Wintun session the packet was received from
    /// * `packet` - A packet obtained with `WintunReceivePacket`
    WintunReleaseReceivePacket: unsafe extern "C" fn(session: *mut WintunSession, packet: *mut u8),

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
    ///   `WINTUN_MAX_IP_PACKET_SIZE`).
    ///
    /// # Errors
    ///
    /// On failure, this function will return a NULL pointer and add an error to the queue. The
    /// error may be one of the following:
    ///
    /// * `ERROR_HANDLE_EOF` - The Wintun adapter is terminating.
    /// * `ERROR_BUFFER_OVERFLOW` - There is insufficient space in the Wintun session's internal
    ///   buffer to allocate an additional buffer. The application should generally wait some time for
    ///   packets to be sent over the interface and then try again.
    ///
    /// # Safety
    ///
    /// This function is thread-safe.
    WintunAllocateSendPacket:
        unsafe extern "C" fn(session: *mut WintunSession, packet_size: u32) -> *mut u8,

    /// Sends the packet and releases its internal buffer.
    ///
    /// # Safety
    ///
    /// This function is thread-safe.
    WintunSendPacket: unsafe extern "C" fn(session: *mut WintunSession, packet: *mut u8),
}

impl Wintun {
    ///
    ///
    /// # Safety
    ///
    /// This function must be supplied a null-terminated `func_name`.
    ///
    /// This function must only be used for creating function pointer types.
    unsafe fn resolve_func(
        lib: *mut libc::c_void,
        func_name: &'static CStr,
    ) -> io::Result<*const libc::c_void> {
        GetProcAddress(lib, func_name.as_ptr().cast())
            .ok_or(io::Error::last_os_error())
            .map(|f| f as *const libc::c_void)
    }

    #[allow(clippy::missing_transmute_annotations)]
    unsafe fn resolve_api(lib: *mut libc::c_void) -> io::Result<WintunApi> {
        Ok(WintunApi {
            WintunCreateAdapter: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunCreateAdapter",
            )?),
            WintunOpenAdapter: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunOpenAdapter",
            )?),
            WintunCloseAdapter: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunCloseAdapter",
            )?),
            WintunDeleteDriver: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunDeleteDriver",
            )?),
            WintunGetAdapterLUID: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunGetAdapterLUID",
            )?),
            WintunGetRunningDriverVersion: mem::transmute::<*const libc::c_void, _>(
                Self::resolve_func(lib, c"WintunGetRunningDriverVersion")?,
            ),
            WintunSetLogger: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunSetLogger",
            )?),
            WintunStartSession: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunStartSession",
            )?),
            WintunEndSession: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunEndSession",
            )?),
            WintunGetReadWaitEvent: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunGetReadWaitEvent",
            )?),
            WintunReceivePacket: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunReceivePacket",
            )?),
            WintunReleaseReceivePacket: mem::transmute::<*const libc::c_void, _>(
                Self::resolve_func(lib, c"WintunReleaseReceivePacket")?,
            ),
            WintunAllocateSendPacket: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunAllocateSendPacket",
            )?),
            WintunSendPacket: mem::transmute::<*const libc::c_void, _>(Self::resolve_func(
                lib,
                c"WintunSendPacket",
            )?),
        })
    }

    /// Opens a new Wintun DLL.
    ///
    /// The DLL is searched for only in the directory of the running executable and in the System32
    /// directory; the current directory and `PATH` are not searched.
    ///
    /// # Errors
    ///
    /// If required functions were missing from the Wintun DLL, this function will return an error
    /// of kind [`ErrorKind::NotFound`](io::ErrorKind::NotFound).
    pub fn new() -> io::Result<Self> {
        let lib_name: Vec<u16> = OsStr::new(WINTUN_LIB)
            .encode_wide()
            .chain(Some(0))
            .collect();

        unsafe {
            let lib = LoadLibraryExW(
                lib_name.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if lib.is_null() {
                return Err(io::Error::last_os_error());
            }

            let api =
                Self::resolve_api(lib).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

            Ok(Self { api })
        }
    }

    /// Opens the Wintun DLL located at the given absolute path.
    ///
    /// If `verify_signature` is set, the Authenticode signature of the file is verified before it
    /// is loaded. The file is held open without write or delete sharing from the verification until
    /// it is loaded, so it cannot be replaced in between.
    ///
    /// # Errors
    ///
    /// If `path` is not absolute, an error of kind
    /// [`ErrorKind::InvalidInput`](io::ErrorKind::InvalidInput) is returned. If the signature
    /// could not be verified, an error of kind
    /// [`ErrorKind::PermissionDenied`](io::ErrorKind::PermissionDenied) is returned. If required
    /// functions were missing from the DLL, an error of kind
    /// [`ErrorKind::NotFound`](io::ErrorKind::NotFound) is returned.
    pub fn from_path(path: &Path, verify_signature: bool) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun DLL path must be absolute",
            ));
        }

        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)?;

        let path_utf16: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

        if verify_signature {
            Self::verify_signature(&path_utf16, &file)?;
        }

        unsafe {
            // The DLL itself is loaded from `path`; only its dependencies are searched for in
            // System32.
            let lib = LoadLibraryExW(
                path_utf16.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if lib.is_null() {
                return Err(io::Error::last_os_error());
            }

            drop(file);

            let api =
                Self::resolve_api(lib).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

            Ok(Self { api })
        }
    }

    /// Verifies the Authenticode signature of the file opened as `file`.
    ///
    /// Only the validity of the signature is checked, not the identity of the signer. Revocation
    /// is not checked, so verification does not need network access.
    fn verify_signature(path_utf16: &[u16], file: &File) -> io::Result<()> {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_utf16.as_ptr(),
            hFile: file.as_raw_handle(),
            pgKnownSubject: ptr::null_mut(),
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &raw mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: 0,
            dwUIContext: 0,
            pSignatureSettings: ptr::null_mut(),
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &raw mut action,
                (&raw mut trust_data).cast(),
            )
        };

        // The state data allocated by the verification must be released regardless of its result.
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &raw mut action,
                (&raw mut trust_data).cast(),
            );
        }

        match status {
            0 => Ok(()),
            e => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Wintun DLL signature could not be verified: {}",
                    io::Error::from_raw_os_error(e)
                ),
            )),
        }
    }

    pub fn driver_version(&self) -> io::Result<u32> {
        let version = unsafe { (self.api.WintunGetRunningDriverVersion)() };
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

        let handle = unsafe {
            (self.api.WintunCreateAdapter)(name.as_ptr(), tunnel_type.as_ptr(), requested_guid)
        };
        NonNull::new(handle).ok_or(io::Error::last_os_error())
    }

    pub fn open_adapter(&self, name: &[u16]) -> io::Result<NonNull<WintunAdapter>> {
        if name.last() != Some(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "adapter name not null-terminated",
            ));
        }

        let handle = unsafe { (self.api.WintunOpenAdapter)(name.as_ptr()) };
        NonNull::new(handle).ok_or(io::Error::last_os_error())
    }

    pub unsafe fn close_adapter(&self, adapter: *mut WintunAdapter) {
        (self.api.WintunCloseAdapter)(adapter)
    }

    pub fn delete_driver(&self) -> io::Result<()> {
        if unsafe { (self.api.WintunDeleteDriver)() } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(unused)]
    pub fn get_adapter_luid(&self, adapter: &mut WintunAdapter) -> NET_LUID_LH {
        let mut luid = NET_LUID_LH { Value: 0 };

        unsafe {
            (self.api.WintunGetAdapterLUID)(adapter, &raw mut luid);
        }

        luid
    }

    pub fn set_logger(&self, log_callback: WintunLoggerCallback) {
        unsafe { (self.api.WintunSetLogger)(log_callback) }
    }

    pub fn start_session(
        &self,
        adapter: &mut WintunAdapter,
        capacity: u32,
    ) -> io::Result<NonNull<WintunSession>> {
        let session = unsafe { (self.api.WintunStartSession)(adapter, capacity) };
        NonNull::new(session).ok_or(io::Error::last_os_error())
    }

    pub unsafe fn end_session(&self, session: *mut WintunSession) {
        (self.api.WintunEndSession)(session)
    }

    pub fn read_event_handle(&self, session: *mut WintunSession) -> HANDLE {
        unsafe { (self.api.WintunGetReadWaitEvent)(session) }
    }

    pub fn recv_packet(
        &self,
        session: *mut WintunSession,
        packet_size: &mut u32,
    ) -> io::Result<WintunPacket> {
        let pkt = unsafe { (self.api.WintunReceivePacket)(session, packet_size) };
        NonNull::new(pkt).ok_or(io::Error::last_os_error())
    }

    pub fn free_packet(&self, session: *mut WintunSession, packet: WintunPacket) {
        unsafe {
            (self.api.WintunReleaseReceivePacket)(session, packet.as_ptr());
        }
    }

    pub fn allocate_packet(
        &self,
        session: *mut WintunSession,
        packet_size: u32,
    ) -> io::Result<WintunPacket> {
        let pkt = unsafe { (self.api.WintunAllocateSendPacket)(session, packet_size) };
        NonNull::new(pkt).ok_or(io::Error::last_os_error())
    }

    pub fn send_packet(&self, session: *mut WintunSession, packet: WintunPacket) {
        unsafe { (self.api.WintunSendPacket)(session, packet.as_ptr()) }
    }
}
