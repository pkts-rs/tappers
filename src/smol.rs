// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Async `Tun`/`Tap` interfaces compatible with `smol`.

#[cfg(not(target_os = "windows"))]
mod tap;
mod tun;

#[cfg(not(target_os = "windows"))]
pub use tap::AsyncTap;
pub use tun::AsyncTun;
