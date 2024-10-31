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

    /// Creates a new, unique TUN device.
    #[inline]
    pub fn new() -> io::Result<Self> {
        let mut tun_id = 0;

        let mut adapter = loop {
            let if_name = format!("Tun{}", tun_id);
            let iface = Interface::new(&if_name).unwrap();

            if TunAdapter::open(iface).is_err() {
                match TunAdapter::create(iface) {
                    Ok(adapter) => break adapter,
                    Err(e) => {
                        if e.kind() != io::ErrorKind::AlreadyExists {
                            return Err(e);
                        }
                    }
                }
            }

            tun_id += 1;
            if tun_id > Self::MAX_TUN_ID {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "no unused adapter could be found",
                ));
            }
        };

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

    /// Opens or creates a TUN device of the given name.
    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        let mut race_retry = false;

        let mut adapter = loop {
            match TunAdapter::open(if_name) {
                Ok(adapter) => break adapter,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    match TunAdapter::create(if_name) {
                        Ok(adapter) => break adapter,
                        Err(e) => {
                            if e.kind() != io::ErrorKind::AlreadyExists {
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }

            // There is a race condition between the time `open()` and `create()` are called. IF
            // that race is detected (e.g. `open()` returns NotFound and `create()` returns exists),
            // we try again.
            if race_retry {
                // Only retry once--should be probabilistically sufficient for non-adversarial races
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "TUN interface is both present and absent (race condition)",
                ));
            }
            race_retry = true;
        };

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
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.adapter.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.adapter.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        Ok(self.nonblocking)
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
