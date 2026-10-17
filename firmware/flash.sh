#!/bin/sh
# Cargo runner: writes the bootloader, partition table, TEE and app by offset, since
# espflash can't parse the tee_0 partition subtype, then opens the serial monitor.
#
# TEE_PROVISION=1 first erases secure_storage. Do that on a board's first TEE flash,
# or if the region held anything else; it also gives the TEE a new attestation key,
# which then has to be enrolled again.
set -eu

elf=$1
out=$(dirname "$elf")
here=$(cd "$(dirname "$0")" && pwd)
idf=${IDF_PATH:-$here/.embuild/esp-idf}
# Cargo has used both build/esp-idf-sys-<hash>/ and build/esp-idf-sys/<hash>/.
tee_bin=$(ls -t "$out"/build/esp-idf-sys*/out/build/esp_tee/esp_tee.bin \
    "$out"/build/esp-idf-sys/*/out/build/esp_tee/esp_tee.bin 2>/dev/null | head -n 1)
if [ -z "$tee_bin" ]; then
    echo "no esp_tee.bin under $out/build; is CONFIG_SECURE_ENABLE_TEE set?" >&2
    exit 1
fi

python3 -I "$idf/components/partition_table/gen_esp32part.py" -q "$here/partitions.csv" "$out/partitions.bin"
espflash save-image --chip esp32c6 "$elf" "$out/app.bin"

if [ "${TEE_PROVISION:-}" = 1 ]; then
    espflash erase-region --after no-reset 0x40000 0x10000
fi
espflash write-bin --after no-reset 0x0 "$out/build/bootloader.bin"
espflash write-bin --after no-reset 0x8000 "$out/partitions.bin"
espflash write-bin --after no-reset 0x10000 "$tee_bin"
espflash write-bin --after no-reset 0x50000 "$out/app.bin"

# The monitor does the one reset; resetting after each write races its attach.
# --elf decodes panic backtraces.
if [ -t 0 ]; then
    exec espflash monitor --elf "$elf"
else
    exec espflash monitor --non-interactive --elf "$elf"
fi
