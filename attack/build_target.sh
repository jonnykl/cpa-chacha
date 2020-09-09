#!/bin/bash


# Builds the binaries needed to program the target device.


cd "$(dirname "$0")"/../target/simpleserial-chacha
make PLATFORM=CWLITEARM

