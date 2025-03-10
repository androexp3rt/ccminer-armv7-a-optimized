#!/bin/bash

# Script to fix ARM NEON headers in sse2neon.h

echo "Checking for ARM NEON headers..."

# Find sse2neon.h
SSE2NEON_FILE=$(find . -name "sse2neon.h")

if [ -z "$SSE2NEON_FILE" ]; then
    echo "Error: sse2neon.h not found!"
    exit 1
fi

echo "Found sse2neon.h at: $SSE2NEON_FILE"

# Check if arm_neon.h is already included
if grep -q "#include <arm_neon.h>" "$SSE2NEON_FILE"; then
    echo "arm_neon.h is already included."
else
    # Add arm_neon.h include at the beginning of the file
    echo "Adding arm_neon.h include..."
    sed -i '1i#include <arm_neon.h>' "$SSE2NEON_FILE"
fi

# Check if stdint.h is already included (for float32_t, etc.)
if grep -q "#include <stdint.h>" "$SSE2NEON_FILE"; then
    echo "stdint.h is already included."
else
    # Add stdint.h include
    echo "Adding stdint.h include..."
    sed -i '1i#include <stdint.h>' "$SSE2NEON_FILE"
fi

echo "Header fixes applied to $SSE2NEON_FILE"
echo "Now try building again with ./build_armv7a.sh" 