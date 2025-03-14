/*
 * This uses veriations of the clhash algorithm for Verus Coin, licensed
 * with the Apache-2.0 open source license.
 * 
 * Copyright (c) 2018 Michael Toutonghi
 * Distributed under the Apache 2.0 software license, available in the original form for clhash
 * here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
 * 
 * Original CLHash code and any portions herein, (C) 2017, 2018 Daniel Lemire and Owen Kaser
 * Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 * 
 * This implements an intermediate step in the last part of a Verus block hash. The intent of this step
 * is to more effectively equalize FPGAs over GPUs and CPUs.
 *
 **/


#include "verus_hash.h"

//#include "./boost/thread.hpp"

#include <assert.h>
#include <string.h>
#include <intrin.h>
//#include "cpu_verushash.hpp"

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

thread_local thread_specific_ptr verusclhasher_key;
thread_local thread_specific_ptr verusclhasher_descr;

#ifdef _WIN32
// attempt to workaround horrible mingw/gcc destructor bug on Windows, which passes garbage in the this pointer
// we use the opportunity of control here to clean up all of our tls variables. we could keep a list, but this is a quick hack
thread_specific_ptr::~thread_specific_ptr() {
    if (verusclhasher_key.ptr)
    {
        verusclhasher_key.reset();
    }
    if (verusclhasher_descr.ptr)
    {
        verusclhasher_descr.reset();
    }
}
#endif

int __cpuverusoptimized = 0x80;

// multiply the length and the some key, no modulo
static inline int32x4_t lazyLengthHash(uint64_t keylength, uint64_t length) {
    const int32x4_t lengthvector = _mm_set_epi64x(keylength,length);
    const int32x4_t clprod1 = _mm_clmulepi64_si128( lengthvector, lengthvector, 0x10);
    return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
static inline int32x4_t precompReduction64_si128( int32x4_t A) {

    //const int32x4_t C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
    const int32x4_t C = _mm_cvtsi32_si128(27);
    int32x4_t Q2 = _mm_clmulepi64_si128( A, C, 0x01);
    int32x4_t Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
                                  _mm_srli_si128(Q2,8));
    int32x4_t Q4 = _mm_xor_si128(Q2,A);
    const int32x4_t final = _mm_xor_si128(Q3,Q4);
    return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

static inline uint64_t precompReduction64( int32x4_t A) {
    return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

// verus intermediate hash extra
static int32x4_t __verusclmulwithoutreduction64alignedrepeat(int32x4_t * __restrict randomsource, const int32x4_t *  __restrict buf, uint64_t keyMask, uint16_t * __restrict fixrand, uint16_t * __restrict fixrandex)
{
    int32x4_t const *pbuf;

    // divide key mask by 16 from bytes to int32x4_t
    keyMask >>= 4;
	
	int32x4_t acc = _mm_load_si128(randomsource + (keyMask + 2));
#ifdef VERUSHASHDEBUG
	printf("[CPU]BUF ito verusclmulithout C++    : ");
	for (int i = 0; i < 64; i++)
		printf("%02x", ((uint8_t*)buf)[i]);
	printf("\n");
	printf("[CPU]KEy ito verusclmulithout C++    : ");
	for (int i = 0; i < 64; i++)
		printf("%02x", ((uint8_t*)&randomsource[0])[i]);
	printf("\n");
	printf("[CPU]ACC ito verusclmulithout C++    : ");
	for (int i = 0; i < 16; i++)
		printf("%02x", ((uint8_t*)&acc)[i]);
	printf("\n");
#endif
    // the random buffer must have at least 32 16 byte dwords after the keymask to work with this
    // algorithm. we take the value from the last element inside the keyMask + 2, as that will never
    // be used to xor into the accumulator before it is hashed with other values first

	  for (uint64_t i = 0; i < 32; i++)
    {
		  
		const uint64_t selector = _mm_cvtsi128_si64(acc);

	// get two random locations in the key, which will be mutated and swapped
	int32x4_t *prand = randomsource + ((selector >> 5) & keyMask);
	int32x4_t *prandex = randomsource + ((selector >> 32) & keyMask);

	// select random start and order of pbuf processing
	pbuf = buf + (selector & 3);
	uint32_t prand_idx = (selector >> 5) & keyMask;
	uint32_t prandex_idx = (selector >>32) & keyMask;
  

        switch (selector & 0x1c)
        {
            case 0:
            {
                const int32x4_t temp1 = _mm_load_si128(prandex);
                const int32x4_t temp2 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);
                const int32x4_t clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp1);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp1);

                const int32x4_t temp12 = _mm_load_si128(prand);
                _mm_store_si128(prand, tempa2);

                const int32x4_t temp22 = _mm_load_si128(pbuf);
                const int32x4_t add12 = _mm_xor_si128(temp12, temp22);
                const int32x4_t clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                acc = _mm_xor_si128(clprod12, acc);

                const int32x4_t tempb1 = _mm_mulhrs_epi16(acc, temp12);
                const int32x4_t tempb2 = _mm_xor_si128(tempb1, temp12);
                _mm_store_si128(prandex, tempb2);
                break;
            }
            case 4:
            {
                const int32x4_t temp1 = _mm_load_si128(prand);
                const int32x4_t temp2 = _mm_load_si128(pbuf);
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);
                const int32x4_t clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);
                const int32x4_t clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
                acc = _mm_xor_si128(clprod2, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp1);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp1);

                const int32x4_t temp12 = _mm_load_si128(prandex);
                _mm_store_si128(prandex, tempa2);

                const int32x4_t temp22 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                const int32x4_t add12 = _mm_xor_si128(temp12, temp22);
                acc = _mm_xor_si128(add12, acc);

                const int32x4_t tempb1 = _mm_mulhrs_epi16(acc, temp12);
                const int32x4_t tempb2 = _mm_xor_si128(tempb1, temp12);
                _mm_store_si128(prand, tempb2);
                break;
            }
            case 8:
            {
                const int32x4_t temp1 = _mm_load_si128(prandex);
                const int32x4_t temp2 = _mm_load_si128(pbuf);
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);
                acc = _mm_xor_si128(add1, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp1);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp1);

                const int32x4_t temp12 = _mm_load_si128(prand);
                _mm_store_si128(prand, tempa2);

                const int32x4_t temp22 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                const int32x4_t add12 = _mm_xor_si128(temp12, temp22);
                const int32x4_t clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                acc = _mm_xor_si128(clprod12, acc);
                const int32x4_t clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
                acc = _mm_xor_si128(clprod22, acc);

                const int32x4_t tempb1 = _mm_mulhrs_epi16(acc, temp12);
                const int32x4_t tempb2 = _mm_xor_si128(tempb1, temp12);
                _mm_store_si128(prandex, tempb2);
                break;
            }
            case 0xc:
            {
                const int32x4_t temp1 = _mm_load_si128(prand);
                const int32x4_t temp2 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);

                // cannot be zero here
                const int32_t divisor = (uint32_t)selector;

                acc = _mm_xor_si128(add1, acc);

                const int64_t dividend = _mm_cvtsi128_si64(acc);
                const int32x4_t modulo = _mm_cvtsi32_si128(dividend % divisor);
                acc = _mm_xor_si128(modulo, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp1);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp1);

                if (dividend & 1)
                {
                    const int32x4_t temp12 = _mm_load_si128(prandex);
                    _mm_store_si128(prandex, tempa2);

                    const int32x4_t temp22 = _mm_load_si128(pbuf);
                    const int32x4_t add12 = _mm_xor_si128(temp12, temp22);
                    const int32x4_t clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                    acc = _mm_xor_si128(clprod12, acc);
                    const int32x4_t clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
                    acc = _mm_xor_si128(clprod22, acc);

                    const int32x4_t tempb1 = _mm_mulhrs_epi16(acc, temp12);
                    const int32x4_t tempb2 = _mm_xor_si128(tempb1, temp12);
                    _mm_store_si128(prand, tempb2);
                }
                else
                {
                    const int32x4_t tempb3 = _mm_load_si128(prandex);
                    _mm_store_si128(prandex, tempa2);
                    _mm_store_si128(prand, tempb3);
                }

                break;
            }
            case 0x10:
            {
                // a few AES operations
                const int32x4_t *rc = prand;
                int32x4_t tmp;

                int32x4_t temp1 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                int32x4_t temp2 = _mm_load_si128(pbuf);

                AES2(temp1, temp2, 0);

				MIX2(temp1, temp2);

                AES2(temp1, temp2, 4);
                MIX2(temp1, temp2);

                AES2(temp1, temp2, 8);
                MIX2(temp1, temp2);		

                acc = _mm_xor_si128(temp2, _mm_xor_si128(temp1, acc));

                const int32x4_t tempa1 = _mm_load_si128(prand);
                const int32x4_t tempa2 = _mm_mulhrs_epi16(acc, tempa1);
                const int32x4_t tempa3 = _mm_xor_si128(tempa1, tempa2);

                const int32x4_t tempa4 = _mm_load_si128(prandex);
                _mm_store_si128(prandex, tempa3);
                _mm_store_si128(prand, tempa4);

                break;
            }
            case 0x14:
            {
                // we'll just call this one the monkins loop, inspired by Chris
                const int32x4_t *buftmp = pbuf - (((selector & 1) << 1) - 1);
                int32x4_t tmp; // used by MIX2

                uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
                int32x4_t *rc = prand;
                uint64_t aesroundoffset = 0,loop_c;
                int32x4_t onekey;

                do
                {
					loop_c = selector & (0x10000000 << rounds);
					if (loop_c)
                    {
                        onekey = _mm_load_si128(rc++);
                        const int32x4_t temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
                        const int32x4_t add1 = _mm_xor_si128(onekey, temp2);
                        const int32x4_t clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                        acc = _mm_xor_si128(clprod1, acc);
                    }
                    else
                    {
                        onekey = _mm_load_si128(rc++);
                        int32x4_t temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
						
                        AES2(onekey, temp2, aesroundoffset);
						
                        aesroundoffset += 4;
                        MIX2(onekey, temp2);
						
                        acc = _mm_xor_si128(onekey, acc);
                        acc = _mm_xor_si128(temp2, acc);
                    }
			
                } while (rounds--);

                const int32x4_t tempa1 = _mm_load_si128(prand);
                const int32x4_t tempa2 = _mm_mulhrs_epi16(acc, tempa1);
                const int32x4_t tempa3 = _mm_xor_si128(tempa1, tempa2);

                const int32x4_t tempa4 = _mm_load_si128(prandex);
                _mm_store_si128(prandex, tempa3);
                _mm_store_si128(prand, tempa4);

                break;
            }
            case 0x18:
            {
                const int32x4_t temp1 = _mm_load_si128(pbuf - (((selector & 1) << 1) - 1));
                const int32x4_t temp2 = _mm_load_si128(prand);
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);
                const int32x4_t clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp2);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp2);

                const int32x4_t tempb3 = _mm_load_si128(prandex);
                _mm_store_si128(prandex, tempa2);
                _mm_store_si128(prand, tempb3);
                break;
            }
            case 0x1c:
            {
                const int32x4_t temp1 = _mm_load_si128(pbuf);
                const int32x4_t temp2 = _mm_load_si128(prandex);
                const int32x4_t add1 = _mm_xor_si128(temp1, temp2);
                const int32x4_t clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);

                const int32x4_t tempa1 = _mm_mulhrs_epi16(acc, temp2);
                const int32x4_t tempa2 = _mm_xor_si128(tempa1, temp2);

                const int32x4_t tempa3 = _mm_load_si128(prand);
#ifdef VERUSHASHDEBUGo

				printf("[cpu] tempa1    : ");
				printf("%016llx%016llx", ((uint64_t*)&tempa1)[0], ((uint64_t*)&tempa1)[1]);
				printf("\n");
				printf("[cpu] tempa2    : ");
				printf("%016llx%016llx", ((uint64_t*)&tempa2)[0], ((uint64_t*)&tempa2)[1]);
				printf("\n");
				printf("[cpu] tempa3    : ");
				printf("%016llx%016llx", ((uint64_t*)&tempa3)[0], ((uint64_t*)&tempa3)[1]);
				printf("\n");

#endif
                _mm_store_si128(prand, tempa2);

                acc = _mm_xor_si128(tempa3, acc);

                const int32x4_t tempb1 = _mm_mulhrs_epi16(acc, tempa3);
                const int32x4_t tempb2 = _mm_xor_si128(tempb1, tempa3);
                _mm_store_si128(prandex, tempb2);


                break;
            }
        }

		fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;
    }

    return acc;
}

// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value
uint64_t verusclhash(void * random, const unsigned char buf[64], uint64_t keyMask, uint16_t *  __restrict fixrand, uint16_t * __restrict fixrandex) {
	const int32x4_t lazy = _mm_cvtsi32_si128( 0x00010000);
	int32x4_t  acc = __verusclmulwithoutreduction64alignedrepeat((int32x4_t *)random, (const int32x4_t *)buf, keyMask, fixrand, fixrandex);
    acc = _mm_xor_si128(acc, lazy);


    return precompReduction64(acc);
}

inline void haraka512_keyed_local(unsigned char *out, const unsigned char *in, const u128 *rc) {
  u128 s[4], tmp;

  s[0] = LOAD(in);
  s[1] = LOAD(in + 16);
  s[2] = LOAD(in + 32);
  s[3] = LOAD(in + 48);

  AES4(s[0], s[1], s[2], s[3], 0);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 8);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 16);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 24);

  //MIX4_LASTBUT1(s[0], s[1], s[2], s[3]);

 // AES4_LAST(s[2], 32);

//  MIX4(s[0], s[1], s[2], s[3]);

 // AES4(s[0], s[1], s[2], s[3], 32);
 // MIX4LAST(s[0], s[1], s[2], s[3]);

 // s[0] = _mm_xor_si128(s[0], LOAD(in));
 // s[1] = _mm_xor_si128(s[1], LOAD(in + 16));
  s[2] = _mm_xor_si128(s[2], LOAD(in + 46));
 // s[3] = _mm_xor_si128(s[3], LOAD(in + 48));

 // TRUNCSTORE(out, s[0], s[1], s[2], s[3]);
}
/*
void cpu_verushash::solve_verus_v2_opt(CBlockHeader &bh, 
	arith_uint256 &target,
	std::function<bool()> cancelf,
	std::function<void(const std::vector<uint32_t>&, size_t, const unsigned char*)> solutionf,
	std::function<void(void)> hashdonef,
	cpu_verushash &device_context)
{
	CVerusHashV2bWriter &vhw = *(device_context.pVHW2b);
	CVerusHashV2 &vh = vhw.GetState();
    verusclhasher &vclh = vh.vclh;

	alignas(32) uint256 curHash, curTarget = ArithToUint256(target);

    const uint64_t *compResult = (uint64_t *)&curHash;
    const uint64_t *compTarget = (uint64_t *)&curTarget;

    u128 *hashKey = (u128 *)verusclhasher_key.get();
    verusclhash_descr *pdesc = (verusclhash_descr *)verusclhasher_descr.get();
    void *hasherrefresh = ((unsigned char *)hashKey) + pdesc->keySizeInBytes;
    const int keyrefreshsize = vclh.keyrefreshsize(); // number of 256 bit blocks

	bh.nSolution = std::vector<unsigned char>(1344);
	bh.nSolution[0] = VERUSHHASH_SOLUTION_VERSION; // earliest VerusHash 2.0 solution version

	// prepare the hash state
	vhw.Reset();
	vhw << bh;

	int64_t *extraPtr = vhw.xI64p();
	unsigned char *curBuf = vh.CurBuffer();

    // skip keygen if it is the current key
    if (pdesc->seed != *((uint256 *)curBuf))
    {
        // generate a new key by chain hashing with Haraka256 from the last curbuf
        // assume 256 bit boundary
        int n256blks = pdesc->keySizeInBytes >> 5;
        unsigned char *pkey = ((unsigned char *)hashKey);
        unsigned char *psrc = curBuf;
        for (int i = 0; i < n256blks; i++)
        {
            haraka256(pkey, psrc);
            psrc = pkey;
            pkey += 32;
        }
        pdesc->seed = *((uint256 *)curBuf);
        memcpy(hasherrefresh, hashKey, pdesc->keySizeInBytes);
    }

    const int32x4_t shuf1 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0);
    const int32x4_t fill1 = _mm_shuffle_epi8(_mm_load_si128((u128 *)curBuf), shuf1);
    const int32x4_t shuf2 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0);
    unsigned char ch = curBuf[0];

	// loop the requested number of times or until canceled. determine if we 
	// found a winner, and send all winners found as solutions. count only one hash. 
	// hashrate is determined by multiplying hash by VERUSHASHES_PER_SOLVE, with VerusHash, only
	// hashrate and sharerate are valid, solutionrate will equal sharerate
	for (int64_t i = 0; i < VERUSHASHES_PER_SOLVE; i++)
	{
		*extraPtr = i;

		// prepare the buffer
        _mm_store_si128((u128 *)(&curBuf[32 + 16]), fill1);
        curBuf[32 + 15] = ch;

		// run verusclhash on the buffer
		const uint64_t intermediate = vclh(curBuf, hashKey);

		// fill buffer to the end with the result and final hash
        int32x4_t fill2 = _mm_shuffle_epi8(_mm_loadl_epi64((u128 *)&intermediate), shuf2);
        _mm_store_si128((u128 *)(&curBuf[32 + 16]), fill2);
        curBuf[32 + 15] = *((unsigned char *)&intermediate);

		haraka512_keyed_local((unsigned char *)&curHash, curBuf, hashKey + vh.IntermediateTo128Offset(intermediate));

        if (compResult[3] > compTarget[3] || (compResult[3] == compTarget[3] && compResult[2] > compTarget[2]) ||
            (compResult[3] == compTarget[3] && compResult[2] == compTarget[2] && compResult[1] > compTarget[1]) ||
            (compResult[3] == compTarget[3] && compResult[2] == compTarget[2] && compResult[1] == compTarget[1] && compResult[0] > compTarget[0]))
        {
            // refresh the key
            memcpy(hashKey, hasherrefresh, keyrefreshsize);
			continue;
        }

        std::vector<unsigned char> solution = bh.nSolution;
		int extraSpace = (solution.size() % 32) + 15;
		assert(solution.size() > 32);
		*((int64_t *)&(solution.data()[solution.size() - extraSpace])) = i;

		solutionf(std::vector<uint32_t>(0), solution.size(), solution.data());
		if (cancelf()) return;

        // refresh the key
        memcpy(hashKey, hasherrefresh, keyrefreshsize);
	}
	hashdonef();
}


void haraka512_keyed(unsigned char *out, const unsigned char *in, const u128 *rc) {
  u128 s[4], tmp;

  s[0] = LOAD(in);
  s[1] = LOAD(in + 16);
  s[2] = LOAD(in + 32);
  s[3] = LOAD(in + 48);

  AES4(s[0], s[1], s[2], s[3], 0);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 8);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 16);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 24);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 32);
  MIX4(s[0], s[1], s[2], s[3]);

  s[0] = _mm_xor_si128(s[0], LOAD(in));
  s[1] = _mm_xor_si128(s[1], LOAD(in + 16));
  s[2] = _mm_xor_si128(s[2], LOAD(in + 32));
  s[3] = _mm_xor_si128(s[3], LOAD(in + 48));

  TRUNCSTORE(out, s[0], s[1], s[2], s[3]);
}
*/

#ifdef _WIN32

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

void *alloc_aligned_buffer(uint64_t bufSize)
{
    void *answer = NULL;
    if (posix_memalign(&answer, sizeof(__m256i), bufSize))
    {
        return NULL;
    }
    else
    {
        return answer;
    }
}
