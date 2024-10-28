// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Async `Tun`/`Tap` interfaces compatible with `mio`.

#[cfg(not(target_os = "windows"))]
mod tap;
mod tun;

#[cfg(not(target_os = "windows"))]
pub use tap::AsyncTap;
pub use tun::AsyncTun;

// mio:
// No current solution

// tokio:
// `tokio::io::unix::AsyncFd`
//
// Windows variant currently blocking on issue:
// https://github.com/tokio-rs/tokio/issues/3781

// Workaround: `FromRawHandle` for `File`

// async-std:
// FromRawFd for UdpStream
// FromRawHandle for File

// smol:
// `async-io` crate
// `async-io::Async<T>`

// ```
// impl<T: AsFd> Async<T>
//
// pub fn new(io: T) -> Result<Async<T>>
//
// Creates an async I/O handle.
//
// This method will put the handle in non-blocking mode and register it in epoll/kqueue/event ports/IOCP.
//
// On Unix systems, the handle must implement AsFd, while on Windows it must implement AsSocket.
// ```
//
// Workaround: use `FromRawHandle` for `File` type for reads.

// So convert pointer to u64; it's safe.
