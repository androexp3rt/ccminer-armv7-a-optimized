#!/bin/bash

# Setup script for Android 5 to create symbolic links to system libraries
# This script must be run as root

# Check if we have root access
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root!"
    echo "Please run with: su -c ./setup_android5.sh"
    exit 1
fi

echo "Setting up system libraries for ccminer on Android 5..."

# Get Termux prefix path
TERMUX_PREFIX=$(dirname $(dirname $(which sh)))
echo "Using Termux prefix: $TERMUX_PREFIX"

# Create lib directory if it doesn't exist
mkdir -p "$TERMUX_PREFIX/lib"

# List of system libraries to link
SYSTEM_LIBS=(
    "libdl.so"
    "libc.so"
    "libm.so"
    "libstdc++.so"
    "liblog.so"
    "libcutils.so"
)

# Find system libraries and create symbolic links
for lib in "${SYSTEM_LIBS[@]}"; do
    # Find the actual library file in system directories
    SYSTEM_LIB_PATH=$(find /system/lib -name "$lib*" | head -n 1)
    
    if [ -n "$SYSTEM_LIB_PATH" ]; then
        echo "Found system library: $SYSTEM_LIB_PATH"
        
        # Create symbolic link in Termux lib directory
        ln -sf "$SYSTEM_LIB_PATH" "$TERMUX_PREFIX/lib/$lib"
        echo "Created symbolic link: $TERMUX_PREFIX/lib/$lib -> $SYSTEM_LIB_PATH"
    else
        echo "Warning: Could not find system library $lib"
    fi
done

# Create a special case for libdl.so if it wasn't found
if [ ! -f "$TERMUX_PREFIX/lib/libdl.so" ]; then
    echo "Creating special case for libdl.so..."
    echo "void dlopen() {}" > /tmp/dummy.c
    gcc -shared -o "$TERMUX_PREFIX/lib/libdl.so" /tmp/dummy.c
    rm /tmp/dummy.c
fi

echo "Setup completed. Now run ./build_armv7a.sh to build ccminer." 