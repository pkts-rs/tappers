# Frequently Asked Questions

**Why isn't there a `new_named()`/`create_named()` interface for cross-platform `Tun`/`Tap` types?**

TUN/TAP devices aren't all named the same across platforms; for instance, MacOS has a specific naming convention of `utunX` (where X is an integer), which stands distinct from Linux and other BSD operating systems default of `tunX`. The `wintun` and `tap-win6` implementations have their own entirely different naming convention for interfaces. Thus, to avoid confusion and frustration by those who don't know these peculiarities, we insead just expose the `new_numbered()` API to cross-platform use, which handles naming differences under the hood. The same goes for `create_named()`.
