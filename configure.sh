# To change the CUDA architecture, edit Makefile.am and run ./build.sh

ld="-flto -Wl,-z,relro,-z,now"

ef="-Rpass=missed-loop-vectorize -Rpass-analysis=loop-vectorize -funroll-loops -finline-functions"
ef="$ef -O3 -ffinite-loops -ffast-math -D_REENTRANT -falign-functions=16"
ef="$ef -fomit-frame-pointer -fpic -pthread -flto -fuse-ld=lld -fno-stack-protector"
ef="$ef -march=armv7-a -mcpu=cortex-a15 -mtune=cortex-a7 -mfpu=neon-vfpv4 -mllvm -enable-loop-distribute"

./configure CXXFLAGS="$ef" CFLAGS="$ef" CXX=clang++ CC=clang LDFLAGS="-v $ld" --host=armv7a-linux-android24
