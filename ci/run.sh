#!/usr/bin/env sh

# Builds and runs tests for a particular target passed as an argument to this
# script.

set -ex

: "${TOOLCHAIN?The TOOLCHAIN environment variable must be set.}"
: "${OS?The OS environment variable must be set.}"

RUST=${TOOLCHAIN}

cat << 'EOF' >> Cargo.toml

[patch.crates-io]
rustix = { git = "https://github.com/nathaniel-bennett/rustix.git", branch = "0.38" }
EOF

echo "Testing Rust ${RUST} on ${OS}"

case "${OS}" in
    openbsd*)
        # OpenBSD does not have rustup support
	export PATH="/usr/local/bin:/usr/local/sbin:$PATH"
        ;;
    dragonfly*)
        # DragonFlyBSD does not have rustup support
        ;;
    *)
        # FIXME: rustup often fails to download some artifacts due to network
        # issues, so we retry this N times.
        N=5
        n=0
        until [ $n -ge $N ]
        do
            if rustup override set "${RUST}" ; then
                break
            fi
            n=$((n+1))
            sleep 1
        done
        ;;
esac

case "${OS}" in
    windows*)
        # The runner in `.cargo/config.toml` starts tests in a new elevated window and returns
        # without waiting for them. CI is already elevated, so run tests directly instead.
        export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=env

        # `wintun-runtime` loads `wintun.dll` from the directory of the test executable
        mkdir -p target/debug/deps
        cp -f wintun.dll target/debug/deps/

        cargo test --all-targets -- --nocapture

        cargo test --all-targets --features wintun -- --nocapture

        cargo test --all-targets --features wintun-runtime -- --nocapture

        cargo test --all-targets --features tapwin6 -- --nocapture

        cargo test --all-targets --features tapwin6-runtime -- --nocapture

        cargo test --all-targets --all-features -- --nocapture

        cargo test --doc --features ""

        cargo test --doc --all-features
        ;;
    *)
        # No extra features in any platform other than windows

        cargo test --all-targets -- --nocapture

        cargo test --all-targets --features async-std -- --nocapture

        cargo test --all-targets --features mio -- --nocapture

        cargo test --all-targets --features smol -- --nocapture

        cargo test --all-targets --features tokio -- --nocapture

        cargo test --all-targets --all-features -- --nocapture

        cargo test --doc --features ""

        cargo test --doc --all-features
        ;;
esac
