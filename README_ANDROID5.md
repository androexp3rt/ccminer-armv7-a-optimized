# Building CCMiner on Android 5 (Rooted)

This guide provides instructions for building CCMiner on a rooted Android 5 device using Termux.

## Prerequisites

1. Rooted Android 5 device
2. Termux app installed
3. Basic development packages installed in Termux:
   ```
   pkg update
   pkg install build-essential clang make autoconf automake libtool curl git
   ```

## Setup and Build Process

### 1. Clone the Repository

```bash
git clone https://github.com/tpruvot/ccminer.git
cd ccminer
```

### 2. Run the Build Wrapper Script

The easiest way to build is to use the provided wrapper script:

```bash
chmod +x build_with_root.sh
./build_with_root.sh
```

This script will:

1. Fix header files for ARM compatibility
2. Set up system library links (requires root)
3. Build CCMiner with optimized settings for ARMv7-A

### 3. Manual Build Process (Alternative)

If you prefer to run the steps manually:

#### a. Fix the headers

```bash
chmod +x fix_headers.sh
./fix_headers.sh

chmod +x fix_sse2neon.sh
./fix_sse2neon.sh
```

#### b. Set up system libraries (requires root)

```bash
chmod +x setup_android5.sh
su -c ./setup_android5.sh
```

#### c. Build CCMiner (requires root)

```bash
chmod +x build_armv7a.sh
su -c ./build_armv7a.sh
```

## Troubleshooting

### Library Not Found Errors

If you encounter "unable to find library" errors:

1. Check if the library exists in the system:

   ```bash
   su -c find /system -name "libdl.so*"
   ```

2. Manually create symbolic links:
   ```bash
   su
   ln -sf /system/lib/libdl.so /data/data/com.termux/files/usr/lib/libdl.so
   exit
   ```

### Compilation Errors

If you encounter compilation errors related to ARM NEON:

1. Check if your device supports NEON:

   ```bash
   cat /proc/cpuinfo | grep neon
   ```

2. If NEON is not supported, edit `build_armv7a.sh` and remove NEON-specific flags.

## Running CCMiner

After successful compilation, you can run CCMiner:

```bash
./ccminer --help
```

Example mining command:

```bash
./ccminer -a algorithm -o stratum+tcp://pool:port -u username -p password
```

## Performance Considerations

- Mining on Android devices will be significantly slower than dedicated hardware
- Watch for overheating - consider using cooling solutions
- Battery drain will be substantial - keep the device plugged in
- Background processes may affect mining performance

## Credits

- Original CCMiner by Christian Buchner and Christian H.
- CUDA implementation by tpruvot
- Android 5 build scripts by [Your Name]
