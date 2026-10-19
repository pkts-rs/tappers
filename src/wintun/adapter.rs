// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
#[cfg(any(not(doc), target_os = "windows"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(feature = "wintun-runtime")]
use std::path::Path;
use std::ptr::NonNull;
use std::{io, mem, ptr};

use once_cell::sync::OnceCell;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIfEntry, GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIfEntry, SetIpInterfaceEntry,
    MIB_IFROW, MIB_IF_ADMIN_STATUS_DOWN, MIB_IF_ADMIN_STATUS_UP, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::{DeviceState, Interface};

use super::dll::{Wintun, WintunAdapter};
use super::{TunSession, WintunLoggerCallback};

// TODO: Once `std::cell::OnceCell` has the `get_or_try_init()` API, we can switch this.
#[doc(hidden)]
static WINTUN_API: OnceCell<Wintun> = OnceCell::new();

/// A Wintun TUN interface adapter that includes Windows-specific functionality.
pub struct TunAdapter {
    pub(crate) adapter: NonNull<WintunAdapter>,
    pub(crate) if_name: Interface,
    pub(crate) wintun: &'static Wintun,
}

impl TunAdapter {
    /// Creates a new TUN adapter of the specified interface name.
    pub fn new_named(if_name: Interface) -> Result<Self, io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;

        let tunnel_type = "Wintun";

        let name_utf16: Vec<u16> = if_name.name().encode_wide().chain(Some(0)).collect();
        let type_utf16: Vec<u16> = tunnel_type.encode_utf16().chain(Some(0)).collect();
        let guid = Self::generate_guid(if_name, tunnel_type);

        let adapter = wintun.create_adapter(&name_utf16, &type_utf16, guid)?;

        Ok(Self {
            adapter,
            if_name,
            wintun,
        })
    }

    /// Creates a new TUN adapter of the specified device number.
    pub fn new_numbered(device_num: u32) -> Result<Self, io::Error> {
        let device_string = format!("tun{}", device_num);
        let if_name = Interface::new(&device_string).unwrap();
        Self::new_named(if_name)
    }

    /// Opens an existing TUN adapter.
    pub fn open(if_name: Interface) -> Result<Self, io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;
        let name_utf16: Vec<u16> = if_name.name().encode_wide().chain(Some(0)).collect();
        let adapter = wintun.open_adapter(&name_utf16).map_err(|e| {
            // Wintun reports a missing adapter as `ERROR_NOT_FOUND`, which `io::ErrorKind` does
            // not map to `NotFound`.
            if e.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                io::Error::new(io::ErrorKind::NotFound, e)
            } else {
                e
            }
        })?;

        Ok(Self {
            adapter,
            if_name,
            wintun,
        })
    }

    /// Returns the currently installed driver version.
    ///
    /// This function will return an error if the Wintun driver is not currently loaded. Creating
    /// a new `TunAdapter` generally causes the driver to be loaded if it is not already, so it is
    /// best to call this function after [`create()`](Self::create) or [`open()`](Self::open).
    pub fn driver_version() -> Result<u32, io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;
        wintun.driver_version()
    }

    /// Sets the callback function to be called whenever Wintun has an event to log.
    pub fn set_log_callback(cb: WintunLoggerCallback) -> Result<(), io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;
        wintun.set_logger(cb);
        Ok(())
    }

    /// Loads the Wintun library from the given absolute path.
    ///
    /// By default, `wintun.dll` is loaded on first use from the directory of the running
    /// executable or from the System32 directory. This function loads it from `path` instead. It
    /// must be called before any other function that uses Wintun; if the library has already been
    /// loaded, an error of kind [`AlreadyExists`](io::ErrorKind::AlreadyExists) is returned.
    #[cfg(feature = "wintun-runtime")]
    pub fn load_wintun<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
        Self::load_wintun_impl(path.as_ref(), false)
    }

    /// Loads the Wintun library from the given absolute path after verifying its Authenticode
    /// signature.
    ///
    /// The file is kept from being modified between the verification and the loading. Only the
    /// validity of the signature is checked, not the identity of the signer, and revocation is not
    /// checked. Otherwise, this function behaves as [`load_wintun()`](Self::load_wintun).
    #[cfg(feature = "wintun-runtime")]
    pub fn load_wintun_verified<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
        Self::load_wintun_impl(path.as_ref(), true)
    }

    #[cfg(feature = "wintun-runtime")]
    fn load_wintun_impl(path: &Path, verify_signature: bool) -> Result<(), io::Error> {
        let mut loaded = false;
        WINTUN_API.get_or_try_init(|| {
            loaded = true;
            Wintun::from_path(path, verify_signature)
        })?;

        if loaded {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Wintun library already loaded",
            ))
        }
    }

    /// Returns the interface name of the TUN adapter.
    #[inline]
    pub fn name(&self) -> Interface {
        self.if_name
    }

    /// Returns the Locally-Unique ID (LUID) associated with the TUN adapter.
    pub fn luid(&mut self) -> NET_LUID_LH {
        self.wintun
            .get_adapter_luid(unsafe { self.adapter.as_mut() })
    }

    /// Returns the device state of the adapter.
    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        let mut row = MIB_IFROW {
            wszName: [0; 256],
            dwIndex: self.if_name.index()?,
            dwType: 0,
            dwMtu: 0,
            dwSpeed: 0,
            dwPhysAddrLen: 0,
            bPhysAddr: [0; 8],
            dwAdminStatus: 0,
            dwOperStatus: 0,
            dwLastChange: 0,
            dwInOctets: 0,
            dwInUcastPkts: 0,
            dwInNUcastPkts: 0,
            dwInDiscards: 0,
            dwInErrors: 0,
            dwInUnknownProtos: 0,
            dwOutOctets: 0,
            dwOutUcastPkts: 0,
            dwOutNUcastPkts: 0,
            dwOutDiscards: 0,
            dwOutErrors: 0,
            dwOutQLen: 0,
            dwDescrLen: 0,
            bDescr: [0; 256],
        };

        match unsafe { GetIfEntry(ptr::addr_of_mut!(row)) } {
            0 => match row.dwAdminStatus {
                MIB_IF_ADMIN_STATUS_UP => Ok(DeviceState::Up),
                MIB_IF_ADMIN_STATUS_DOWN => Ok(DeviceState::Down),
                s => Err(io::Error::other(format!(
                    "invalid device state {} returned",
                    s
                ))),
            },
            e => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// Sets the adapter state of the TUN device (e.g. "up" or "down").
    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let admin_status = match state {
            DeviceState::Up => MIB_IF_ADMIN_STATUS_UP,
            DeviceState::Down => MIB_IF_ADMIN_STATUS_DOWN,
        };

        let mut row = MIB_IFROW {
            wszName: [0; 256],
            dwIndex: self.if_name.index()?,
            dwType: 0,
            dwMtu: 0,
            dwSpeed: 0,
            dwPhysAddrLen: 0,
            bPhysAddr: [0; 8],
            dwAdminStatus: 0,
            dwOperStatus: 0,
            dwLastChange: 0,
            dwInOctets: 0,
            dwInUcastPkts: 0,
            dwInNUcastPkts: 0,
            dwInDiscards: 0,
            dwInErrors: 0,
            dwInUnknownProtos: 0,
            dwOutOctets: 0,
            dwOutUcastPkts: 0,
            dwOutNUcastPkts: 0,
            dwOutDiscards: 0,
            dwOutErrors: 0,
            dwOutQLen: 0,
            dwDescrLen: 0,
            bDescr: [0; 256],
        };

        let res = unsafe { GetIfEntry(ptr::addr_of_mut!(row)) };
        if res != 0 {
            return Err(io::Error::from_raw_os_error(res as i32));
        }

        row.dwAdminStatus = admin_status;

        match unsafe { SetIfEntry(ptr::addr_of!(row)) } {
            0 => Ok(()),
            e => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// Retrieves the Maximum Transmission Unit (MTU) of the adapter.
    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        let mut row = MIB_IFROW {
            wszName: [0; 256],
            dwIndex: self.if_name.index()?,
            dwType: 0,
            dwMtu: 0,
            dwSpeed: 0,
            dwPhysAddrLen: 0,
            bPhysAddr: [0; 8],
            dwAdminStatus: 0,
            dwOperStatus: 0,
            dwLastChange: 0,
            dwInOctets: 0,
            dwInUcastPkts: 0,
            dwInNUcastPkts: 0,
            dwInDiscards: 0,
            dwInErrors: 0,
            dwInUnknownProtos: 0,
            dwOutOctets: 0,
            dwOutUcastPkts: 0,
            dwOutNUcastPkts: 0,
            dwOutDiscards: 0,
            dwOutErrors: 0,
            dwOutQLen: 0,
            dwDescrLen: 0,
            bDescr: [0; 256],
        };

        match unsafe { GetIfEntry(ptr::addr_of_mut!(row)) } {
            0 => Ok(row.dwMtu as usize),
            e => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// Sets the Maximum Transmission Unit (MTU) of the adapter for both IPv4 and IPv6.
    pub fn set_mtu(&self, mtu: usize) -> io::Result<()> {
        let mtu = u32::try_from(mtu)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MTU too large"))?;
        let index = self.if_name.index()?;

        for family in [AF_INET, AF_INET6] {
            let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
            unsafe { InitializeIpInterfaceEntry(ptr::addr_of_mut!(row)) };
            row.Family = family;
            row.InterfaceIndex = index;

            match unsafe { GetIpInterfaceEntry(ptr::addr_of_mut!(row)) } {
                0 => (),
                // IPv6 may be disabled on the adapter.
                ERROR_NOT_FOUND if family == AF_INET6 => continue,
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }

            row.NlMtu = mtu;
            // `SetIpInterfaceEntry()` rejects an IPv4 entry whose `SitePrefixLength` is not 0.
            row.SitePrefixLength = 0;

            match unsafe { SetIpInterfaceEntry(ptr::addr_of_mut!(row)) } {
                0 => (),
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }

        Ok(())
    }

    /// Starts a single session on the given adapter.
    ///
    /// `ring_size` indicates the size of the buffer allocated for transmitting and receiving
    /// packets in the session. Its value must be a power of 2 between 0x20000 (128 kiB) and
    /// 0x4000000 (64 MiB), inclusive.
    pub fn start_session(&mut self, ring_size: u32) -> Result<TunSession<'_>, io::Error> {
        let session = self
            .wintun
            .start_session(unsafe { self.adapter.as_mut() }, ring_size)?;
        Ok(TunSession::new(self, session.as_ptr()))
    }

    // TODO: is start_sessions() allowed?

    /// Starts a specified number of sessions on the given adapter.
    ///
    /// `ring_size` indicates the size of the buffer allocated for transmitting and receiving
    /// packets in each session. Its value must be a power of 2 between 0x20000 (128 kiB) and
    /// 0x4000000 (64 MiB), inclusive.
    #[allow(unused)]
    fn start_sessions(
        &mut self,
        ring_size: u32,
        num_sessions: usize,
    ) -> io::Result<Vec<TunSession<'_>>> {
        let mut sessions = Vec::new();
        let mut session_ptrs = Vec::new();

        for _ in 0..num_sessions {
            let session = self
                .wintun
                .start_session(unsafe { self.adapter.as_mut() }, ring_size)?;
            session_ptrs.push(session);
        }

        for session in session_ptrs {
            sessions.push(TunSession::new(self, session.as_ptr()));
        }

        Ok(sessions)
    }

    #[doc(hidden)]
    const GUID_MSB_SEED: u64 = 0x00;
    #[doc(hidden)]
    const GUID_LSB_SEED: u64 = 0x01;

    #[doc(hidden)]
    fn generate_guid(name: Interface, tunnel_type: &str) -> GUID {
        let mut state = DefaultHasher::new();
        Self::GUID_MSB_SEED.hash(&mut state);
        name.name().hash(&mut state);
        tunnel_type.hash(&mut state);
        let msb_hash = state.finish();

        let mut state = DefaultHasher::new();
        Self::GUID_LSB_SEED.hash(&mut state);
        name.name().hash(&mut state);
        tunnel_type.hash(&mut state);
        let lsb_hash = state.finish();

        GUID {
            data1: (msb_hash >> 32) as u32,
            data2: ((msb_hash >> 16) & 0xffff) as u16,
            data3: (msb_hash & 0xffff) as u16,
            data4: lsb_hash.to_ne_bytes(),
        }
    }
}

impl Drop for TunAdapter {
    fn drop(&mut self) {
        unsafe {
            self.wintun.close_adapter(self.adapter.as_ptr());
            // Ignore this failure--other programs could be using Wintun.
            let _ = self.wintun.delete_driver();
        }
    }
}

// SAFETY: the NonNull pointer in `TunAdapter` references data not on the stack, so it is safe to
// move across thread boundaries
unsafe impl Send for TunAdapter {}

// SAFETY: the NonNull pointer in `TunAdapter` is only used in a thread-safe manner, so `TunAdapter`
// can be immutably shared across threads.
unsafe impl Sync for TunAdapter {}

#[cfg(test)]
mod tests {
    use super::*;

    // The CI places `wintun.dll` in the crate root.
    #[cfg(feature = "wintun-runtime")]
    fn wintun_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("wintun.dll")
    }

    fn load_wintun() {
        #[cfg(feature = "wintun-runtime")]
        match TunAdapter::load_wintun_verified(wintun_path()) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => panic!("failed to load Wintun: {}", e),
        }
    }

    fn ip_mtu(adapter: &TunAdapter, family: u16) -> Option<u32> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(ptr::addr_of_mut!(row)) };
        row.Family = family;
        row.InterfaceIndex = adapter.name().index().unwrap();

        match unsafe { GetIpInterfaceEntry(ptr::addr_of_mut!(row)) } {
            0 => Some(row.NlMtu),
            ERROR_NOT_FOUND => None,
            e => panic!("{}", io::Error::from_raw_os_error(e as i32)),
        }
    }

    #[cfg(feature = "wintun-runtime")]
    #[test]
    fn load_relative_path() {
        let err = Wintun::from_path(Path::new("wintun.dll"), false)
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(feature = "wintun-runtime")]
    #[test]
    fn load_unsigned() {
        let path = std::env::temp_dir().join("tappers-unsigned-wintun.dll");
        std::fs::write(&path, b"MZ").unwrap();

        let res = Wintun::from_path(&path, true);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(res.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(feature = "wintun-runtime")]
    #[test]
    fn load_signed() {
        Wintun::from_path(&wintun_path(), true).unwrap();
    }

    #[test]
    fn set_mtu() {
        load_wintun();
        let adapter = TunAdapter::new_numbered(9).unwrap();

        adapter.set_mtu(1400).unwrap();
        assert_eq!(ip_mtu(&adapter, AF_INET), Some(1400));
        if let Some(mtu) = ip_mtu(&adapter, AF_INET6) {
            assert_eq!(mtu, 1400);
        }

        adapter.set_mtu(1280).unwrap();
        assert_eq!(ip_mtu(&adapter, AF_INET), Some(1280));
    }
}
