# Tappers

---

**Tappers is a library for creating, managing and exchanging packets on TUN/TAP interfaces.**

`tappers` provides both platform-specific and cross-platform APIs for managing TUN/TAP devices and
virtual ethernet pairs. It supports the following features for each platform:

| Platform      | TUN  | TAP | vETH |
| ------------- | ---- | --- | ---- |
| Linux         | ✅   | ✅  | ⬜   |
| MacOS         | ✅   | ✅  | ⬜   |
| Windows       | ✅   | ⬜  | N/A  |
| FreeBSD       | ✅   | ✅  | ⬜   |
| OpenBSD       | ✅   | ✅  | ⬜   |
| NetBSD        | ✅   | ✅  | ⬜   |
| DragonFly BSD | ✅   | ✅  | N/A  |
| Solaris       | ⬜   | ⬜  | N/A  |
| IllumOS       | ⬜   | ⬜  | N/A  |
| AIX           | ⬜   | ⬜  | N/A  |

`N/A` - platform does not have any virtual Ethernet implementation.

Note that this library is currently a work in progress--more platforms will be supported soon!

## Feature Comparison to Other Libraries

| Feature                                     | `tappers` | `tun`          | `tun2`           | `tun-tap`  | `utuntap` | `tokio-tun` |
| ------------------------------------------- | --------- | -------------- | ---------------- | ---------- | --------- | ----------- |
| Consistent packet format across platforms   | ✅        | ⬜             | ⬜               | Linux only | ⬜        | Linux only  |
| Uses no subprocess commands (only `ioctl`s) | ✅        | ✅             | ⬜               | ✅         | ✅        | ✅          |
| Supports multiple TUN/TAP creation          | ✅        | Not on Windows | ✅               | ✅         | ✅        | ✅          |
| IPv4 routing support                        | Planned   | ✅             | ✅               | ⬜         | ⬜        | ✅          |
| IPv6 routing support                        | Planned   | ⬜             | Linux only       | ⬜         | ⬜        | ⬜          |
| Unit testing for `TUN` devices              | ✅        | ✅             | ✅               | ✅         | ✅        | ⬜          |
| Unit testing for `TAP` devices              | ✅        | ⬜             | ⬜               | ⬜         | ⬜        | ⬜          |
| Cross-platform CI tests                     | ✅        | ⬜             | ⬜               | N/A        | ⬜        | N/A         |
| TUN/TAP support for Linux                   | ✅        | TUN only       | TUN only         | ✅         | ✅        | ✅          |
| TUN/TAP support for MacOS                   | ✅        | TUN only       | TUN only         | ⬜         | TUN only  | ⬜          |
| TUN/TAP support for Windows                 | TUN only  | TUN only       | TUN only         | ⬜         | ⬜        | ⬜          |
| TUN/TAP support for *BSD                    | ✅        | ⬜             | FreeBSD/TUN only | ⬜         | OpenBSD   | ⬜          |
| TUN/TAP support for Solaris/IllumOS         | ⬜        | ⬜             | ⬜               | ⬜         | ⬜        | ⬜          |
| non-`async` support                         | ✅        | ✅             | ✅               | ✅         | ✅        | ⬜          |
| `async` support                             | Planned   | ✅             | Unix only        | ✅         | ⬜        | ✅          |

## Additional Notes on Platform Support

Not all platforms implement the standard `/dev/tun` interface for TUN/TAP creation; there are
special instances where TUN and TAP devices are provided either through the use of custom drivers
(such as for Windows) or via special alternative network APIs (such as for MacOS). These are
outlined below. The TL;DR is that *nix platforms are supported natively, Windows is supported
provided extra open-source drivers are installed, and mobile platfroms are too restrictive for
`tappers` to work well with.

### Windows

Windows provides no TUN/TAP interface support by default. Instead, there are two open-source
drivers that provide roughly equivalent functionality: the Wireguard-supported `wintun` driver, and
the OpenVPN-supported `tap-windows6` driver. `wintun` provides only TUN support, whereas
`tap-windows6` provides TAP and "simulated" TUN support. In either case, the appropriate driver must
be installed; otherwise, instantiation of `Tun` and `Tap` types will fail with an error.

### MacOS

MacOS provides a kind of TUN interface via the `utun` API, which acts mostly the same as `tun` on
other platforms. While MacOS has no explicit `tap` API, it does have a relatively-undocumented
`feth` interface (see
[if_fake.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_fake.c)) that is
nearly equivalent in functionality to TAP interfaces. Despite its missing documentation, `feth`
interfaces are supported in MacOS releases as early as 10.13 (High Sierra), and their API has
remained relatively stable since its inception.

In short, neither TUN nor TAP interfaces are formally supported on MacOS, but `tappers` provides
equivalent functionality for its `Tun`/`Tap` types via `utun` and `feth`.

### Android

Android techincally does offer the `/dev/net/tun` API, but it is only accessible to applications
with root privileges. As most Android distributions do not allow applications to run with root
privileges, this is not a feasible solution for most use cases. Android instead offers the
`VpnService` Java API that allows for the creation of a single TUN interface through which traffic
from the device is routed. If your intent is to create a VPN or proxy application, you'll likely
find `VpnService` to be better suited to your needs than this crate. Note that `VpnService` has
no native API equivalent in Android, so `tappers` does not currently wrap it.

### iOS

iOS provides the `NEPacketTunnelProvider` API for VPN/proxy applications (similar to Android's
`VpnProvider`). iOS does not support the creation of arbitrary TUN interfaces, and it provides no
support for TAP interfaces. `NEPacketTunnelProvider` has no native API equivalent, so `tappers`
does not currently wrap it.

## Virtual Ethernet (vETH) Pairs

Virtual Ethernet (or vETH) pairs can be thought of as a

## `async` Runtime Support

All `Tun` and `Tap` types implement synchronous blocking/nonblocking `send()` and `recv()` APIs.
In addition to this, `tappers` will aim to provide first-class support for the following `async`
runtimes:

| `async` Runtime | Supported?    |
| --------------- | ------------- |
| `mio`           | ⬜            |
| `tokio`         | ⬜            |
| `futures`       | ⬜            |
| `async-std`     | Via `futures` |
| `smol`          | Via `futures` |

Note that this library is currently a work in progress--`async` runtimes will soon be supported.

## Dependency Policy

Like other crates managed by pkts.org, `tappers` aims to rely on a minimal set of dependencies
that are vetted and well-used in the Rust ecosystem. As such, `tappers` makes use of only the
following dependencies:

* `libc`, `windows-sys` - Provides needed types and functions for creating/managing TUN/TAP
interfaces across various platforms.
* `once_cell` - Used in Windows implementation of `Tun`/`Tap`. Will be replaced with standard
library once certain OnceCell APIs are stabilized.

We do not plan on adding in any additional dependencies to `tappers`. The one exception to this
rule is that some common structs (e.g. `MacAddr`, `Interface`) may be split out into a separate
crate in a future release.

## License

This project is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-MIT))

at your option.

## Contributing

`tappers` is open to contribution--feel free to submit an Issue or Pull Request if there's
something you'd like to add to this library.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`tappers` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
