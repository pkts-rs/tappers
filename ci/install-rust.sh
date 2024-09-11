#!/usr/bin/env sh
# This is intended to be used in CI only.

set -ex

echo "Setup toolchain"
toolchain=
if [ -n "$TOOLCHAIN" ]; then
  toolchain=$TOOLCHAIN
else
  toolchain=stable
fi
if [ "$OS" = "windows" ]; then
  : "${TARGET?The TARGET environment variable must be set.}"
  rustup set profile minimal
  rustup update --force "$toolchain-$TARGET"
  rustup default "$toolchain-$TARGET"
else
  rustup set profile minimal
  rustup update --force "$toolchain"
  rustup default "$toolchain"
fi

if [ -n "$TARGET" ]; then
  echo "Install target"
  rustup target add "$TARGET"
fi

if [ -n "$INSTALL_RUST_SRC" ]; then
  echo "Install rust-src"
  rustup component add rust-src
fi

if [ "$OS" = "windows" ]; then
  echo "Install Wintun"
  curl.exe -o wintun.zip https://www.wintun.net/builds/wintun-0.14.1.zip
  powershell.exe -NoP -NonI -Command "Expand-Archive './wintun.zip' './'"
  cp -f "./wintun/bin/amd64/wintun.dll" "./"
  rm -rf "./wintun"
fi

echo "Query rust and cargo versions"
command -v rustc
command -v cargo
command -v rustup
rustc -Vv
cargo -V
rustup -Vv
rustup show

echo "Generate lockfile"
N=5
n=0
until [ $n -ge $N ]
do
  if cargo generate-lockfile; then
    break
  fi
  n=$((n+1))
  sleep 1
done