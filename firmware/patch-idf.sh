#!/bin/sh
# Sets up the ESP-IDF tree the firmware builds against (IDF_PATH in .cargo/config.toml):
# v5.5.5 plus patches/esp-tee-rom-read.patch. Without the patch, TEE flash reads return
# garbage once the app's flash driver has run, and the TEE loses its attestation key on
# every boot. The tree sits outside esp-idf-sys's managed checkout because esp-idf-sys
# deletes and re-clones that checkout whenever it has local changes.
set -eu

cd "$(dirname "$0")"
version=v5.5.5
tree=.embuild/esp-idf
managed=.embuild/espressif/esp-idf/$version
patch="$PWD/patches/esp-tee-rom-read.patch"

if [ ! -d "$tree" ]; then
    # Built under another name so an interrupted run never leaves a partial $tree.
    partial=$tree.partial
    rm -rf "$partial"
    if [ -d "$managed/.git" ]; then
        echo "copying ESP-IDF $version from $managed"
        cp -cR "$managed" "$partial" 2>/dev/null || { rm -rf "$partial"; cp -R "$managed" "$partial"; }
    else
        git clone --depth 1 --shallow-submodules --recursive --branch "$version" \
            https://github.com/espressif/esp-idf.git "$partial"
    fi
    mv "$partial" "$tree"
fi

if git -C "$tree" apply --reverse --check "$patch" 2>/dev/null; then
    echo "ESP-IDF patch already applied"
    exit 0
fi

# esp-idf-sys doesn't watch ESP-IDF's sources, so force its libraries to rebuild. Clean
# first: if cleaning fails, the tree stays unpatched and the next run tries again.
cargo clean --release -p esp-idf-sys
cargo clean -p esp-idf-sys

if ! git -C "$tree" apply "$patch"; then
    echo "patches/esp-tee-rom-read.patch does not apply to $tree" >&2
    exit 1
fi
echo "ESP-IDF patch applied"
