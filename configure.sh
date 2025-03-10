# To change the CUDA architecture, edit Makefile.am and run ./build.sh
ld="-flto -Wl,-z,relro,-z,now"

ef="-Rpass=missed-loop-vectorize -Rpass-analysis=loop-vectorize -funroll-loops -finline-functions"
ef="$ef -O3 -ffinite-loops -ffast-math -D_REENTRANT -falign-functions=16 -mllvm -enable-loop-distribute"
ef="$ef -fomit-frame-pointer -fpic -pthread -flto -fuse-ld=lld -fno-stack-protector"
ef="$ef -march=armv7-a -mcpu=cortex-a15 -mtune=cortex-a15 -mfpu=neon-vfpv4 -DUSE_AESB"
ef="$ef -mvectorize-with-neon-quad -funsafe-math-optimizations"

autoreconf -fi
./configure CXXFLAGS="$ef" CFLAGS="$ef" CXX=clang++ CC=clang LDFLAGS="-v $ld" --host=armv7a-linux-android24 --enable-static --disable-shared
