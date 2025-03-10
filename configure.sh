# To change the CUDA architecture, edit Makefile.am and run ./build.sh
ld="-flto -Wl,-z,relro,-z,now"

# Remove unsupported flags: -ffinite-loops and -mvectorize-with-neon-quad
# Add better ARMv7-A specific optimizations
ef="-Rpass=loop-vectorize -funroll-loops -finline-functions"
ef="$ef -O3 -ffast-math -D_REENTRANT -falign-functions=16 -mllvm -enable-loop-distribute"
ef="$ef -fomit-frame-pointer -fpic -pthread -flto -fuse-ld=lld -fno-stack-protector"
ef="$ef -march=armv7-a -mcpu=cortex-a15 -mtune=cortex-a15 -mfpu=neon-vfpv4 -DUSE_AESB"
ef="$ef -mfloat-abi=hard -funsafe-math-optimizations -ftree-vectorize"

# Add warning suppressions to avoid compilation errors
ef="$ef -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-value"

autoreconf -fi
./configure CXXFLAGS="$ef" CFLAGS="$ef" CXX=clang++ CC=clang LDFLAGS="-v $ld" --host=armv7a-linux-android24 --enable-static --disable-shared
