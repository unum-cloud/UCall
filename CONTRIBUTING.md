# Contributing to UCall Development

## Setup the Environment

Ideally, for development, you'd need a Linux machine with a recent kernel version.
Docker also works, but may cause additional overhead.

```bash
# Install the required packages
sudo apt-get install -y build-essential cmake 
```

## Build the Project



```bash
git clone https://github.com/unum-cloud/ucall.git

cmake -DUCALL_BUILD_ALL=1 -B build_debug
cmake --build ./build_debug --config Debug          # Which will produce the following targets:
./build_debug/stringzilla_test_cpp20                # Unit test for the entire library compiled for current hardware
./build_debug/stringzilla_test_cpp20_x86_serial     # x86 variant compiled for IvyBridge - last arch. before AVX2
./build_debug/stringzilla_test_cpp20_arm_serial     # Arm variant compiled without Neon
```

## Test and Debug in C

## Test and Debug in Python

