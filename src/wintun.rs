// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Windows) TUN-specific interfaces provided by the `wintun` driver.
//!
//!
//!

mod adapter;
mod dll;
mod session;

use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

pub use adapter::TunAdapter;
pub use dll::WintunLoggerCallback;
pub use session::TunSession;

use dll::WintunSession;
use windows_sys::Win32::Foundation::HANDLE;

use crate::{DeviceState, Interface};

pub(crate) struct TunImpl {
    adapter: TunAdapter,
    session: NonNull<WintunSession>,
    #[allow(unused)]
    ring_size: u32,
    nonblocking: AtomicBool,
}

impl TunImpl {
    #[cfg(feature = "portable-racy")]
    pub fn new() -> io::Result<Self> {
        const MAX_TUN_ID: u32 = 1000;
        for tun_id in 0..MAX_TUN_ID {
            let device_str = format!("tun{}", tun_id);
            let if_name = Interface::new(&device_str).unwrap();

            match TunAdapter::new_named(if_name) {
                Ok(mut adapter) => match adapter.wintun.start_session(
                    unsafe { adapter.adapter.as_mut() },
                    TunSession::DEFAULT_RING_SIZE,
                ) {
                    Ok(session) => {
                        return Ok(Self {
                            adapter,
                            session,
                            ring_size: TunSession::DEFAULT_RING_SIZE,
                            nonblocking: AtomicBool::new(false),
                        })
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                },
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no unused TUN number could be found for use",
        ))
    }

    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let mut adapter = match TunAdapter::new_named(if_name) {
            Ok(adapter) => adapter,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // There is a minor race condition where create() fails but another device deletes
                // its existing open Wintun adapter before open() is called here. In this case, we
                // pretend that we won the race but that the adapter had a session already attached
                // to it (hence io::ErrorKind::ResourceBusy).
                match TunAdapter::open(if_name) {
                    Ok(adapter) => adapter,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Err(io::Error::new(
                            io::ErrorKind::ResourceBusy,
                            "device currently in use",
                        ))
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };

        let session = adapter.wintun.start_session(
            unsafe { adapter.adapter.as_mut() },
            TunSession::DEFAULT_RING_SIZE,
        )?;

        Ok(Self {
            adapter,
            session,
            ring_size: TunSession::DEFAULT_RING_SIZE,
            nonblocking: AtomicBool::new(false),
        })
    }

    pub fn new_numbered(device_num: u32) -> io::Result<Self> {
        let device_string = format!("tun{}", device_num);
        let if_name = Interface::new(&device_string).unwrap();
        Self::new_named(if_name)
    }

    pub fn exists(if_name: Interface) -> io::Result<bool> {
        match TunAdapter::open(if_name) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn exists_numbered(device_num: u32) -> io::Result<bool> {
        let if_name = Interface::new(format!("tun{}", device_num)).unwrap();
        Self::exists(if_name)
    }

    pub fn open(device_num: u32) -> io::Result<Self> {
        let device_string = format!("tun{}", device_num);
        let if_name = Interface::new(&device_string).unwrap();
        Self::open_named(if_name)
    }

    pub fn open_named(if_name: Interface) -> io::Result<Self> {
        let mut adapter = TunAdapter::open(if_name)?;
        let session = adapter.wintun.start_session(
            unsafe { adapter.adapter.as_mut() },
            TunSession::DEFAULT_RING_SIZE,
        )?;

        Ok(Self {
            adapter,
            session,
            ring_size: TunSession::DEFAULT_RING_SIZE,
            nonblocking: AtomicBool::new(false),
        })
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.adapter.name())
    }

    #[inline]
    pub fn state(&self) -> io::Result<DeviceState> {
        self.adapter.state()
    }

    #[inline]
    pub fn set_state(&self, state: DeviceState) -> io::Result<()> {
        self.adapter.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.adapter.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        Ok(self.nonblocking.load(Ordering::Relaxed))
    }

    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let nonblocking = self.nonblocking.load(Ordering::Relaxed);
        TunSession::send_impl(&self.adapter, self.session.as_ptr(), nonblocking, buf)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let nonblocking = self.nonblocking.load(Ordering::Relaxed);
        TunSession::recv_impl(&self.adapter, self.session.as_ptr(), nonblocking, buf)
    }

    #[inline]
    pub fn read_handle(&self) -> HANDLE {
        TunSession::read_handle_impl(&self.adapter, self.session.as_ptr())
    }
}

// SAFETY: the NonNull pointer in `TunImpl` references data not on the stack, so it is safe to
// move across thread boundaries
unsafe impl Send for TunImpl {}

// SAFETY: the NonNull pointer in `TunImpl` is only used in a thread-safe manner, so `TunImpl`
// can be immutably shared across threads.
unsafe impl Sync for TunImpl {}

/*
TODO: add IP address setting like so:

MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }

*/
