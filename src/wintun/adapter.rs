use std::hash::{DefaultHasher, Hash, Hasher};
use std::os::windows::ffi::OsStrExt;
use std::ptr::NonNull;
use std::{io, ptr};

use once_cell::sync::OnceCell;
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIfEntry, SetIfEntry, MIB_IFROW, MIB_IF_ADMIN_STATUS_DOWN, MIB_IF_ADMIN_STATUS_UP,
};

use crate::{DeviceState, Interface};

use super::dll::{Wintun, WintunAdapter};
use super::{TunSession, WintunLoggerCallback};

// TODO: Once `std::cell::OnceCell` has the `get_or_try_init()` API, we can switch this.
#[doc(hidden)]
static WINTUN_API: OnceCell<Wintun> = OnceCell::new();

/// A TUN interface adapter for Wintun.
pub struct TunAdapter {
    pub(crate) adapter: NonNull<WintunAdapter>,
    pub(crate) if_name: Interface,
    pub(crate) wintun: &'static Wintun,
}

impl TunAdapter {
    /// Creates a new TUN adapter.
    ///
    /// The TUN interface will be destroyed when the `TunAdapter` created by this method is
    /// dropped.
    pub fn create(if_name: Interface) -> Result<Self, io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;

        let tunnel_type = "Tappers";

        let name_utf16: Vec<u16> = if_name.name().encode_wide().collect();
        let type_utf16: Vec<u16> = tunnel_type.encode_utf16().collect();
        let guid = Self::generate_guid(if_name, tunnel_type);

        let adapter = wintun.create_adapter(&name_utf16, &type_utf16, guid)?;

        Ok(Self {
            adapter,
            if_name,
            wintun,
        })
    }

    /// Opens an existing TUN adapter.
    pub fn open(if_name: Interface) -> Result<Self, io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;
        let name_utf16: Vec<u16> = if_name.encode_wide().collect();
        let adapter = wintun.open_adapter(&name_utf16)?;

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
        Ok(wintun.driver_version()?)
    }

    /// Sets the callback function to be called whenever Wintun has an event to log.
    pub unsafe fn set_log_callback(cb: WintunLoggerCallback) -> Result<(), io::Error> {
        let wintun = WINTUN_API.get_or_try_init(Wintun::new)?;
        wintun.set_logger(cb);
        Ok(())
    }

    #[inline]
    pub fn name(&self) -> Interface {
        self.if_name
    }

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
                s => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid device state {} returned", s),
                )),
            },
            e => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        let admin_status = match state {
            DeviceState::Up => MIB_IF_ADMIN_STATUS_UP,
            DeviceState::Down => MIB_IF_ADMIN_STATUS_DOWN,
        };

        let row = MIB_IFROW {
            wszName: [0; 256],
            dwIndex: self.if_name.index()?,
            dwType: 0,
            dwMtu: 0,
            dwSpeed: 0,
            dwPhysAddrLen: 0,
            bPhysAddr: [0; 8],
            dwAdminStatus: admin_status,
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

        match unsafe { SetIfEntry(ptr::addr_of!(row)) } {
            0 => Ok(()),
            e => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

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

    /// Starts a single session on the given adapter.
    pub fn start_session(&mut self, ring_size: u32) -> Result<TunSession<'_>, io::Error> {
        let session = self
            .wintun
            .start_session(unsafe { self.adapter.as_mut() }, ring_size)?;
        Ok(TunSession::new(self, session))
    }

    /// Starts a specified number of sessions on the given adapter.
    pub fn start_sessions(
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
            sessions.push(TunSession::new(self, session));
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
