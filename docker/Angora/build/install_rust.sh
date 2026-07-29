#!/bin/bash

set -euxo pipefail

# from https://github.com/rust-lang-nursery/docker-rust-nightly/blob/master/nightly/Dockerfile

url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
if [ -f "./rustup-init" ]; then
  :
elif [ -f "/FuzzingTools/preload/rustup-init" ]; then
  cp /FuzzingTools/preload/rustup-init ./rustup-init
else
  wget --tries=5 --waitretry=3 --timeout=20 --read-timeout=20 "$url" \
    || curl -fL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 300 -o rustup-init "$url"
fi
chmod +x rustup-init
# RUSTUP_DIST_SERVER="https://mirrors.ustc.edu.cn/rust-static" RUSTUP_UPDATE_ROOT="https://mirrors.ustc.edu.cn/rust-static/rustup" 
./rustup-init -y --no-modify-path --default-toolchain stable
# ./rustup-init -y --no-modify-path --default-toolchain nightly

rm rustup-init
chmod -R a+w $RUSTUP_HOME $CARGO_HOME
rustup --version
cargo --version
rustc --version
