#!/bin/bash

# Wrapper script to build ccminer with root privileges on Android 5

echo "=== CCMiner Build Wrapper for Rooted Android 5 ==="
echo "This script will run the necessary setup and build steps with root privileges."

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

# Run the setup script with root
echo -e "\n=== Running system library setup with root ==="
su -c ./setup_android5.sh

# Run the build script with root
echo -e "\n=== Building CCMiner with root ==="
su -c ./build_armv7a.sh

echo -e "\n=== Build process completed ==="
echo "If successful, the ccminer binary should be ready to use." 