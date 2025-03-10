#!/bin/bash

# Build script optimized for ARMv7-A with NEON support for rooted Android 5

# Clean previous build
make distclean || echo "Already clean"

# Run autogen if needed
./autogen.sh || echo "Autogen already run"

# Get Termux prefix path
TERMUX_PREFIX=$(dirname $(dirname $(which sh)))
echo "Using Termux prefix: $TERMUX_PREFIX"

# Check if we have root access
if [ "$(id -u)" -ne 0 ]; then
    echo "Warning: Not running as root. Some libraries might not be accessible."
    echo "Consider running this script with 'su -c ./build_armv7a.sh'"
fi

# Define optimized compiler flags for ARMv7-A
CFLAGS="-O3 -march=armv7-a -mcpu=cortex-a15 -mtune=cortex-a15 -mfpu=neon-vfpv4 -mfloat-abi=hard"
CFLAGS="$CFLAGS -ffast-math -funroll-loops -finline-functions -ftree-vectorize"
CFLAGS="$CFLAGS -fomit-frame-pointer -fpic -pthread -fno-stack-protector"
CFLAGS="$CFLAGS -DUSE_AESB -D_REENTRANT -falign-functions=16"
CFLAGS="$CFLAGS -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-value"

# Define linker flags - avoid using lld which causes errors
LDFLAGS="-Wl,-z,relro,-z,now"
# Add both Termux and system library paths
LDFLAGS="$LDFLAGS -L$TERMUX_PREFIX/lib -L/system/lib"

# Set the compiler to use the system dynamic linker
export LD_LIBRARY_PATH="/system/lib:$TERMUX_PREFIX/lib:$LD_LIBRARY_PATH"

# Run the fix_headers script first
./fix_headers.sh

# Configure with optimized flags
./configure CFLAGS="$CFLAGS" CXXFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" \
    --prefix=$TERMUX_PREFIX \
    --enable-static=no --enable-shared=yes

# Build with all cores
make -j$(nproc)

echo "Build completed. If successful, the binary is ready for ARMv7-A with NEON." 