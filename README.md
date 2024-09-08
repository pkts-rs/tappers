# Tappers

---

**Tappers is a library for creating, managing and exchanging packets on TUN/TAP interfaces.**

`tappers` provides both platform-specific and cross-platform APIs for managing TUN and TAP
devices. It supports the following features for each platform:

| Platform | TUN                   | TAP                   | Kernel BPF           |
| -------- | --------------------- | --------------------- | -------------------- |
| Linux    | :white_check_mark:    | :white_check_mark:    | :white_large_square: |
| MacOS    | :white_check_mark:    | :white_check_mark:    | :white_large_square: |
| Windows  | :white_check_mark:    | :white_large_square:  | N/A                  |
| FreeBSD  | :white_large_square:  | :white_large_square:  | :white_large_square: |
| OpenBSD  | :white_large_square:  | :white_large_square:  | :white_large_square: |
| NetBSD   | :white_large_square:  | :white_large_square:  | :white_large_square: |
| Solaris  | :white_large_square:  | :white_large_square:  | :white_large_square: |
| IllumOS  | :white_large_square:  | :white_large_square:  | :white_large_square: |
| Android  | :white_large_square:* | :white_large_square:* | N/A                  |
| iOS      | :white_large_square:  | N/A                   | N/A                  |

`N/A` - platform does not support specified feature

`*` - only supported on rooted Android

Note that this library is currently a work in progress--more platforms will be supported soon!

# Feature Comparison to Other Libraries

| Feature                                     | `tappers`            | `tun`                | `tun2`               | `tun-tap`            | `utuntap`            | `tokio-tun`          |
| ------------------------------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- | -------------------- |
| Consistent packet format across platforms   | :heavy-check-mark:   | :white_large_square: | :white_large_square: | Linux only           | :white_large_square: | Linux only           |
| Uses no subprocess commands (only `ioctl`s) | :white_check_mark:   | :white_check_mark:   | :white_large_square: | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   |
| Supports multiple TUN/TAP creation          | :white_check_mark:   | Not on Windows       | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   |
| IPv4 routing support                        | Planned              | :white_check_mark:   | :white_check_mark:   | :white_large_square: | :white_large_square: | :white_check_mark:   |
| IPv6 routing support                        | Planned              | :white_large_square: | Linux only           | :white_large_square: | :white_large_square: | :white_large_square: |
| Unit testing for `TUN` devices              | Planned              | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_large_square: |
| Unit testing for `TAP` devices              | Planned              | :white_large_square: | :white_large_square: | :white_large_square: | :white_large_square: | :white_large_square: |
| Cross-platform CI tests                     | Planned              | :white_large_square: | :white_large_square: | N/A                  | :white_large_square: | N/A                  |
| TUN/TAP support for Linux                   | :white_check_mark:   | TUN only             | TUN only             | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   |
| TUN/TAP support for MacOS                   | :white_check_mark:   | TUN only             | TUN only             | :white_large_square: | TUN only             | :white_large_square: |
| TUN/TAP support for Windows                 | TUN only             | TUN only             | TUN only             | :white_large_square: | :white_large_square: | :white_large_square: |
| TUN/TAP support for *BSD                    | Planned              | :white_large_square: | FreeBSD/TUN only     | :white_large_square: | OpenBSD              | :white_large_square: |
| TUN/TAP support for Solaris/IllumOS         | :white_large_square: | :white_large_square: | :white_large_square: | :white_large_square: | :white_large_square: | :white_large_square: |
| non-`async` support                         | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_check_mark:   | :white_large_square: |
| `async` support                             | Planned              | :white_check_mark:   | Unix only            | :white_check_mark:   | :white_large_square: | :white_check_mark:   |

# Additional Notes on Platform Support

Not all platforms implement the standard `/dev/net/tun` interface for TUN/TAP creation; there are
special instances where TUN and TAP devices are provided either through the use of custom drivers
(such as for Windows) or via special alternative network APIs (such as for MacOS). These are
outlined below. The TL;DR is that *nix platforms are supported natively, Windows is supported
provided extra open-source drivers are installed, and mobile platfroms are too restrictive for
`tappers` to work well with.

## Windows

Windows provides no TUN/TAP interface support by default. Instead, there are two open-source
drivers that provide roughly equivalent functionality: the Wireguard-supported `wintun` driver, and
the OpenVPN-supported `tap-windows6` driver. `wintun` provides only TUN support, whereas
`tap-windows6` provides TAP and "simulated" TUN support. In either case, the appropriate driver must
be installed; otherwise, instantiation of `Tun` and `Tap` types will fail with an error.

## MacOS

MacOS provides a kind of TUN interface via the `utun` API, which acts mostly the same as `tun` on
other platforms. While MacOS has no explicit `tap` API, it does have a relatively-undocumented
`feth` interface (see
(if_fake.c)[https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_fake.c]) that is
nearly equivalent in functionality to TAP interfaces. Despite its missing documentation, `feth`
interfaces are supported in MacOS releases as early as 10.13 (High Sierra), and their API has
remained relatively stable since its inception.

In short, neither TUN nor TAP interfaces are formally supported on MacOS, but `tappers` provides
equivalent functionality for its `Tun`/`Tap` types via `utun` and `feth`.

## Android

Android techincally does offer the `/dev/net/tun` API, but it is only accessible to applications
with root privileges. As most Android distributions do not allow applications to run with root
privileges, this is not a feasible solution for most use cases. Android instead offers the
`VpnService` Java API that allows for the creation of a single TUN interface through which traffic
from the device is routed. If your intent is to create a VPN or proxy application, you'll likely
find `VpnService` to be better suited to your needs than this crate. Note that `VpnService` has
no native API equivalent in Android, so `tappers` does not currently wrap it.

For the (relatively slimmer) use case where users would like to run code on rooted Android devices,
`tappers` provides bindings to Android's TUN/TAP interfaces.

## iOS

iOS provides the `NEPacketTunnelProvider` API for VPN/proxy applications (similar to Android's
`VpnProvider`). iOS does not support the creation of arbitrary TUN interfaces, and it provides no
support for TAP interfaces. `NEPacketTunnelProvider` has no native API equivalent, so `tappers`
does not currently wrap it.

# `async` Runtime Support

All `Tun` and `Tap` types implement synchronous blocking/nonblocking `send()` and `recv()` APIs.
In addition to this, `tappers` will aim to provide first-class support for the following `async`
runtimes:

| `async` Runtime | Supported?           |
| --------------- | -------------        |
| `mio`           | :white_large_square: |
| `tokio`         | :white_large_square: |
| `futures`       | :white_large_square: |
| `async-std`     | Via `futures`        |
| `smol`          | Via `futures`        |

Note that this library is currently a work in progress--`async` runtimes will soon be supported.

# Dependency Policy

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
