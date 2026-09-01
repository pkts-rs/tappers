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

pub use adapter::TunAdapter;
pub use dll::WintunLoggerCallback;
pub use session::TunSession;

use dll::WintunSession;
use windows_sys::Win32::Foundation::HANDLE;

use crate::{DeviceState, Interface};

pub(crate) struct TunImpl {
    adapter: TunAdapter,
    session: NonNull<WintunSession>,
    ring_size: u32,
    nonblocking: bool,
}

impl TunImpl {
    const MAX_TUN_ID: u32 = 1000;

    pub fn create() -> io::Result<Interface> {
        for tun_id in 0..1000 {
            let if_name = format!("tun{}", tun_id);
            let iface = Interface::new(&if_name).unwrap();

            match TunAdapter::create(iface) {
                Ok(_) => Ok(if_name),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        };

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no unused TUN number could be found for use",
        ))
    }

    pub fn create_named(if_name: Interface) -> io::Result<()> {
        match TunAdapter::create(iface) {
            Ok(adapter) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn create_numbered(device_num: u32) -> io::Result<()> {
        let devicd_string = format!("tun{}", device_num);
        let if_name = Interface::new(&device_string).unwrap();
        Self::create_named(if_name)
    }

    pub fn open(device_num: u32) -> io::Result<()> {
        let devicd_string = format!("tun{}", device_num);
        let if_name = Interface::new(&device_string).unwrap();
        Self::open_named(if_name)
    }

    pub fn open_named(if_name: Interface) -> io::Result<()> {
        let adapter = TunAdapter::open(if_name)?;
        let session = adapter.wintun.start_session(
            unsafe { adapter.adapter.as_mut() },
            TunSession::DEFAULT_RING_SIZE,
        )?;

        Ok(Self {
            adapter,
            session,
            ring_size: TunSession::DEFAULT_RING_SIZE,
            nonblocking: false,
        })
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        Ok(self.adapter.name())
    }

    #[inline]
    pub fn set_up(&self) -> io::Result<()> {
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
        TunSession::send_impl(&self.adapter, self.session.as_ptr(), self.nonblocking, buf)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        TunSession::recv_impl(&self.adapter, self.session.as_ptr(), self.nonblocking, buf)
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
