#!/bin/bash

# Wrapper script to build ccminer with root privileges on Android 5

echo "=== CCMiner Build Wrapper for Rooted Android 5 ==="
echo "This script will run the necessary setup and build steps with root privileges."

# Get the current directory as absolute path
CURRENT_DIR=$(pwd)
echo "Working directory: $CURRENT_DIR"

# Make all scripts executable
chmod +x fix_headers.sh
chmod +x fix_sse2neon.sh
chmod +x setup_android5.sh
chmod +x build_armv7a.sh

# Run the header fix scripts (doesn't need root)
echo -e "\n=== Running basic header fixes ==="
./fix_headers.sh

echo -e "\n=== Running advanced sse2neon fixes ==="
./fix_sse2neon.sh

# Run the setup script with root (using absolute path)
echo -e "\n=== Running system library setup with root ==="
su -c "cd $CURRENT_DIR && ./setup_android5.sh"

# Run the build script with root (using absolute path)
echo -e "\n=== Building CCMiner with root ==="
su -c "cd $CURRENT_DIR && ./build_armv7a.sh"

echo -e "\n=== Build process completed ==="
echo "If successful, the ccminer binary should be ready to use." 