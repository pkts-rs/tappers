# Tappers

[![Cross-Platform]][CI Status] [![Latest Version]][crates.io] [![Documentation]][docs.rs] [![v1.70+]][Rust 1.70]

[Cross-Platform]: https://github.com/pkts-rs/tappers/actions/workflows/full_ci.yml/badge.svg
[CI Status]: https://github.com/pkts-rs/tappers/actions
[Documentation]: https://docs.rs/tappers/badge.svg
[docs.rs]: https://docs.rs/tappers/
[Latest Version]: https://img.shields.io/crates/v/tappers.svg
[crates.io]: https://crates.io/crates/tappers
[v1.70+]: https://img.shields.io/badge/MSRV-rustc_1.70+-blue.svg
[Rust 1.70]: https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html

---

**Tappers is a library for creating, managing and exchanging packets on TUN, TAP and vETH interfaces.**

`tappers` provides both platform-specific and cross-platform APIs for managing TUN/TAP devices and
virtual ethernet (vETH) pairs. It supports the following features for each platform:

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

`N/A` - platform does not provide any virtual Ethernet functionality.

Note that this library is currently a work in progress--more features and platforms will be supported soon!

## Getting Started

To create a TUN device and begin synchronously receiving packets from it:
 
```rust
use std::io;
use std::net::Ipv4Addr;
use tappers::Tun;

let mut tun = Tun::new()?; 
tun.add_addr(Ipv4Addr::new(10, 100, 0, 1))?;
tun.set_up()?; // Enables the TUN device to exchange packets

let mut recv_buf = [0; 65536];

loop {
    let amount = tun.recv(&mut recv_buf)?;
    println!("Received packet: {:?}", &recv_buf[0..amount]);
}
```

Tappers additionally allows for more complex configuration of interfaces:

```rust
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tappers::{AddAddressV4, AddAddressV6, AddressInfo, DeviceState, Interface, Tap};

// Select an existing (or new) TAP interface name to open
let tap_name = Interface::new("tap10")?;

// Open the TAP device named "tap10" (or create it if it doesn't exist)
let mut tap = Tap::new_named(tap_name)?;

// Add a new address with associated info to the TAP device
let new_addr = Ipv4Addr::new(10, 100, 0, 1);
let mut addr_req = AddAddressV4::new(new_addr);
addr_req.set_netmask(24);
addr_req.set_broadcast(Ipv4Addr::new(10, 100, 0, 255));

tap.add_addr(addr_req)?;

// Retrieve information on the IPv4/IPv6 addresses bound to the TAP device
let addrs = tap.addrs()?;
for addr_info in addrs {
    println!("IP address: {}", addr_info.address());
    if let Some(netmask) = addr_info.netmask() {
        println!("Netmask: {}", netmask);
    }
    if let Some(broadcast) = addr_info.broadcast() {
        println!("Broadcast: {}", broadcast);
    }
}

// Remove an address from the TAP device
tap.remove_addr(IpAddr::V4(new_addr))?;

// Configure whether the TAP device performs non-blocking reads/writes
tap.set_nonblocking(true)?;

// Bring the device up to enable packet exchange
tap.set_state(DeviceState::Up);

let mut buf = [0; 65536];

// Receive packets from the interface
let amount = tap.recv(&mut buf)?;

// Send packets over the interface
let amount = tap.send(&buf[..amount])?;

// Bring the device down to disable packet exchange
tap.set_state(DeviceState::Down);

// The TUN device represented by `tun` is automatically be removed from the system when dropped.
```


## Feature Comparison to Similar Libraries

| Feature                                     | `tappers` | `tun`          | `tun2`           | `tun-tap`  | `utuntap` | `tokio-tun` |
| ------------------------------------------- | --------- | -------------- | ---------------- | ---------- | --------- | ----------- |
| Consistent packet format across platforms   | ✅        | ⬜             | ⬜               | Linux only | ⬜        | Linux only  |
| Uses no subprocess commands (only `ioctl`s) | ✅        | ⬜             | ⬜               | ✅         | ✅        | ✅          |
| Supports multiple TUN/TAP creation          | ✅        | Not on Windows | ✅               | ✅         | ✅        | ✅          |
| IPv4 address assignment                     | ✅*       | ✅             | ✅               | ⬜         | ⬜        | ✅          |
| IPv6 address assignment                     | ✅*       | ⬜             | Linux only       | ⬜         | ⬜        | ⬜          |
| Unit testing for `TUN` devices              | ✅        | ✅             | ✅               | ✅         | ✅        | ⬜          |
| Unit testing for `TAP` devices              | ✅        | ⬜             | ⬜               | ⬜         | ⬜        | ⬜          |
| Cross-platform CI testing                   | ✅        | ⬜             | ⬜               | N/A        | ⬜        | N/A         |
| TUN/TAP support for Linux                   | ✅        | TUN only       | TUN only         | ✅         | ✅        | ✅          |
| TUN/TAP support for MacOS                   | ✅        | TUN only       | TUN only         | ⬜         | TUN only  | ⬜          |
| TUN/TAP support for Windows                 | TUN only  | TUN only       | TUN only         | ⬜         | ⬜        | ⬜          |
| TUN/TAP support for *BSD                    | ✅        | ⬜             | FreeBSD/TUN only | ⬜         | OpenBSD   | ⬜          |
| TUN/TAP support for Solaris/IllumOS         | ⬜        | ⬜             | ⬜               | ⬜         | ⬜        | ⬜          |
| non-`async` support                         | ✅        | ✅             | ✅               | ✅         | ✅        | ⬜          |
| `async` support                             | ✅        | ✅             | Unix only        | ✅         | ⬜        | ✅          |

`*` - `tappers` doesn't currently support setting or deleting IP addresses in Windows. This because
Windows fundamentally lacks support for adding or changing IPv6 interface addresses in current APIs.
This issue will be resolved when I find the time to reverse-engineer whatever opaque ioctl calls the
`netsh` command uses to assign IPv6 addresses to TUN and TAP interfaces.

## Planned Features

The following are currently being worked on or are in the roadmap of near-future releases:

- Support for adding routes to TUN/TAP devices programatically
- Unit tests for `send()`/`recv()` (currently blocking on route support)
- Cross-platform vETH interfaces
- `async` read and write for TUN/TAP/vETH interfaces
- More specific settings for TUN/TAP/vETH interfaces (setting MTU, getting and setting IP metric
  and flags, etc.)
- Windows TAP supported via the openvpn `tap-windows6` driver
- Windows support for programatically adding/removing IP addresses from interfaces
- Solaris/IllumOS support

If one of these features is particularly needed for your use case, feel free to open a Github issue
and I'll try to prioritize its implementation.

## Additional Notes on Platform Support

Not all platforms implement the standard `/dev/tun` interface for TUN/TAP creation; there are
special instances where TUN and TAP devices are provided either through the use of custom drivers
(such as for Windows) or via special alternative network APIs (such as for MacOS). These are
outlined below. The TL;DR is that *nix platforms are supported natively, Windows is supported
as long as extra open-source drivers are installed, and mobile platfroms are too restrictive for
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

### DragonFly BSD

DragonFly does not load the needed `if_tap` module by default. Make sure to load this using
`kldload if_tap` prior to running any program that uses `tappers`. Note that this will only load
the TAP kernel module until the next boot; refer to DragonFly documentation for further information
on how to persistently load kernel modules.

### Android

Android techincally does offer the `/dev/net/tun` API, but it is only accessible to applications
with root privileges. As most Android distributions do not allow applications to run with root
privileges, this is not a feasible solution for most use cases. Android instead offers the
`VpnService` Java API that allows for the creation of a single TUN interface through which traffic
from the device is routed. If your intent is to create a VPN or proxy application, you'll likely
find `VpnService` to be better suited to your needs than this crate. Note that `VpnService` has
no native API equivalent in Android, so `tappers` does not wrap it.

### iOS

iOS provides the `NEPacketTunnelProvider` API for VPN/proxy applications (similar to Android's
`VpnProvider`). iOS does not support the creation of arbitrary TUN interfaces, and it provides no
support for TAP interfaces. `NEPacketTunnelProvider` has no native API equivalent, so `tappers`
does not wrap it.

## Virtual Ethernet (vETH) Pairs

Virtual Ethernet (or vETH) pairs provide link-layer communication between two network interfaces
without any underlying physical hardware. They are particularly useful in virtualization contexts,
though they can also be used to simulate network topologies. `tappers` doesn't support vETH devices
at the moment, but they are a planned feature for the near future.

## `async` Runtime Support

All `Tun` and `Tap` types implement synchronous blocking/nonblocking `send()` and `recv()` APIs.
In addition to this, `tappers` provides first-class support for the following `async`
runtimes:

| `async` Runtime | Supported? |
| --------------- | ---------- |
| `async-std`     | ✅         |
| `smol`          | ✅         |
| `mio`           | ✅*        |
| `tokio`         | ✅         |

`*` - on all platforms except for Windows

## Dependency Policy

Like other crates managed by pkts.org, `tappers` aims to rely on a minimal set of dependencies
that are vetted and well-used in the Rust ecosystem. As such, `tappers` has only the following
dependencies:

* `libc`, `windows-sys` - Provides needed types and functions for creating/managing TUN/TAP
interfaces across various platforms.
* `once_cell` - Used in Windows implementation of `Tun`/`Tap`. Will be replaced with the standard
library once certain OnceCell APIs are stabilized.

The following optional dependencies are only included when various async runtime features are enabled:
* `async-std` - Included for async compatibility with the `async-std` runtime
* `mio` - Included for async compatibility with the `mio` runtime
* `smol` - Included for async compatibility with the `smol` runtime
* `tokio` - Included for async compatibility with the `tokio` runtime
* `async-io` - Additional dependency for the `async-std` and `smol` runtimes

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

`tappers` is open to contribution--feel free to submit an issue or pull request if there's
something you'd like to add to the library.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`tappers` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
