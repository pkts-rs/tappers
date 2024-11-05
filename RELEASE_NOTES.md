# Release History:

* 0.4.2
  - Fix breaking issues for ARM builds
  - Add arm-linux-stable to CI

* 0.4.1
  - Revise internals of async `send()`/`recv()` to fix issues polling HANDLEs in Windows
  - Separate `async_io` interfaces into `smol` and `async_std`

* 0.4.0
  - Change `send()`, `recv()` functions to be immutable
  - Add async implementations for `async-std`, `mio`, `smol`, `tokio`
  - Move Rust MSRV up to 1.70 (to support `mio`)

* 0.3.1
  - Make docs show platform-specific APIS
  - Update documentation
  - Add examples to main README/module root

* 0.3.0
  - Add IP address assignment/removal support for all but Windows

* 0.2.0 (2024-09-25)
  - Add TUN/TAP support for *BSD variants
  - Add CI for DragonFly BSD, FreeBSD, NetBSD and OpenBSD
  - Add additional cross-platform unit tests

* 0.1.1 (2024-09-17)
  - Fix bug in `Interface::new` method
  - Fix bug in getting/setting nonblocking for MacOS TUN, TAP

* 0.1.0 (2024-09-09)
  - Initial release
  - Linux/Windows/MacOS TUN support
  - Linux/MacOS TAP support
  - Cross-platform `Tun`/`Tap` types
  - Cross-platform CI

