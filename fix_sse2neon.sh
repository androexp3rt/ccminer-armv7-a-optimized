#!/bin/bash

# Script to directly fix sse2neon.h by adding necessary type definitions

echo "Fixing sse2neon.h for ARM NEON compatibility..."

# Find sse2neon.h
SSE2NEON_FILE=$(find . -name "sse2neon.h")

if [ -z "$SSE2NEON_FILE" ]; then
    echo "Error: sse2neon.h not found!"
    exit 1
fi

echo "Found sse2neon.h at: $SSE2NEON_FILE"

# Create a temporary file with the ARM NEON header includes
cat > /tmp/neon_header.txt << 'EOF'
#ifndef SSE2NEON_H
#define SSE2NEON_H

#include <arm_neon.h>
#include <stdint.h>

/* Define ARM NEON types that might be missing */
#ifndef float32_t
typedef float float32_t;
#endif

#ifndef float64_t
typedef double float64_t;
#endif

/* ARM NEON optimizations */
#define ARMV7A_OPTIMIZATIONS
#define NEON_MEMORY_ALIGNMENT 32

EOF

# Check if the file already has the SSE2NEON_H guard
if grep -q "#ifndef SSE2NEON_H" "$SSE2NEON_FILE"; then
    # Replace the existing header guard with our enhanced version
    sed -i '1,/#define SSE2NEON_H/d' "$SSE2NEON_FILE"
    cat /tmp/neon_header.txt "$SSE2NEON_FILE" > /tmp/fixed_sse2neon.h
    mv /tmp/fixed_sse2neon.h "$SSE2NEON_FILE"
else
    # Add our header at the beginning of the file
    cat /tmp/neon_header.txt "$SSE2NEON_FILE" > /tmp/fixed_sse2neon.h
    mv /tmp/fixed_sse2neon.h "$SSE2NEON_FILE"
fi

# Make sure the file ends with an #endif
if ! grep -q "#endif.*SSE2NEON_H" "$SSE2NEON_FILE"; then
    echo -e "\n#endif /* SSE2NEON_H */" >> "$SSE2NEON_FILE"
fi

rm -f /tmp/neon_header.txt

echo "Fixed sse2neon.h with proper ARM NEON type definitions" 