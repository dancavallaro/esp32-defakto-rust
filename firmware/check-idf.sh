#!/bin/sh
# Cargo's rustc wrapper. When a fresh build compiles core (from build-std, so first), it
# checks that ./patch-idf.sh has set up IDF_PATH, since esp-idf-sys's error doesn't say to.
case " $* " in
*" --crate-name core "*)
    if [ ! -f "$IDF_PATH/tools/cmake/version.cmake" ]; then
        echo "ESP-IDF isn't set up at $IDF_PATH; run ./patch-idf.sh" >&2
        exit 1
    fi ;;
esac
exec "$@"
