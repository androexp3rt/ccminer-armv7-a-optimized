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


#include "haraka_portable.h"
#include <arm_neon.h>
#include <assert.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#	pragma push_macro("FORCE_INLINE")
#	pragma push_macro("ALIGN_STRUCT")
#	define FORCE_INLINE       static inline __attribute__((always_inline))
#	define ALIGN_STRUCT(x)    __attribute__((aligned(x)))
#else
#	error "Macro name collisions may happens with unknown compiler"
#	define FORCE_INLINE       static inline
#	define ALIGN_STRUCT(x)    __declspec(align(x))
#endif


#ifdef __APPLE__
#include <sys/types.h>
#endif// APPLE

#ifdef _WIN32
#pragma warning (disable : 4146)
#include <intrin.h>
#else //NOT WIN32
#include "sse2neon.h"
#endif //WIN32

static inline uint32x4_t vmull_p64_arm(uint64_t a, uint64_t b) {
  return vcombine_u64(vcreate_u64(a) * vcreate_u64(b), vdup_n_u64(0));
}

#define AES2(s0, s1, rci) \
  s0 = _mm_aesenc_si128(s0, rc[rci]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 1]); \
  s0 = _mm_aesenc_si128(s0, rc[rci + 2]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 3]);

FORCE_INLINE int32x4_t _mm_clmulepi64_si128_emu(const int32x4_t a, const int32x4_t &b, int imm)
{
	int32x4_t result;
   
 // uint32x4_t aa = *(uint32x4_t*)&a;
 // uint32x4_t bb = *(uint32x4_t*)&b;

 result = (int32x4_t)vmull_p64_arm(vgetq_lane_u64(a, 1), vgetq_lane_u64(b,0)); 

	return result;
}

FORCE_INLINE int32x4_t _mm_mulhrs_epi16_emu(int32x4_t _a, int32x4_t _b)
{
//	int16_t result[8];
//	int16_t *a = (int16_t*)&_a, *b = (int16_t*)&_b;
//	for (int i = 0; i < 8; i++)
//	{
//		result[i] = (int16_t)((((int32_t)(a[i]) * (int32_t)(b[i])) + 0x4000) >> 15);
//	}

	return vqrdmulhq_s16(_a,_b); //*(int32x4_t *)result;
}

 int32x4_t _mm_set_epi64x_emu(uint64_t hi, uint64_t lo)
{
	int32x4_t result;
	((uint64_t *)&result)[0] = lo;
	((uint64_t *)&result)[1] = hi;
	return result;
}

 int32x4_t _mm_cvtsi64_si128_emu(uint64_t lo)
{
	int32x4_t result;
	((uint64_t *)&result)[0] = lo;
	((uint64_t *)&result)[1] = 0;
	return result;
}

 int64_t _mm_cvtsi128_si64_emu(const int32x4_t &a)
{
	return *(int64_t *)&a;
}

 int32_t _mm_cvtsi128_si32_emu(int32x4_t &a)
{
	return *(int32_t *)&a;
}

 FORCE_INLINE int32x4_t _mm_cvtsi32_si128_emu(uint32_t lo)
{
//	int32x4_t result;
//	((uint32_t *)&result)[0] = lo;
//	((uint32_t *)&result)[1] = 0;
//	((uint64_t *)&result)[1] = 0;
return vreinterpretq_m128i_s32(vsetq_lane_s32(lo, vdupq_n_s32(0), 0));
	/*
	const int32x4_t testresult = _mm_cvtsi32_si128(lo);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_cvtsi32_si128_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_cvtsi32_si128_emu: Portable version failed!\n");
	}
	*/

//	return result;
}
typedef uint8_t u_char;

int32x4_t _mm_setr_epi8_emu(u_char c0, u_char c1, u_char c2, u_char c3, u_char c4, u_char c5, u_char c6, u_char c7, u_char c8, u_char c9, u_char c10, u_char c11, u_char c12, u_char c13, u_char c14, u_char c15)
{
	int32x4_t result;
	((uint8_t *)&result)[0] = c0;
	((uint8_t *)&result)[1] = c1;
	((uint8_t *)&result)[2] = c2;
	((uint8_t *)&result)[3] = c3;
	((uint8_t *)&result)[4] = c4;
	((uint8_t *)&result)[5] = c5;
	((uint8_t *)&result)[6] = c6;
	((uint8_t *)&result)[7] = c7;
	((uint8_t *)&result)[8] = c8;
	((uint8_t *)&result)[9] = c9;
	((uint8_t *)&result)[10] = c10;
	((uint8_t *)&result)[11] = c11;
	((uint8_t *)&result)[12] = c12;
	((uint8_t *)&result)[13] = c13;
	((uint8_t *)&result)[14] = c14;
	((uint8_t *)&result)[15] = c15;

	/*
	const int32x4_t testresult = _mm_setr_epi8(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_setr_epi8_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_setr_epi8_emu: Portable version failed!\n");
	}
	*/

	return result;
}

#define _mm_srli_si128_emu(a, imm) \
({ \
	int32x4_t ret; \
	if ((imm) <= 0) { \
		ret = a; \
	} \
	else if ((imm) > 15) { \
		ret = _mm_setzero_si128(); \
	} \
	else { \
		ret = vreinterpretq_m128i_s8(vextq_s8(vreinterpretq_s8_m128i(a), vdupq_n_s8(0), (imm))); \
	} \
	ret; \
})

 int32x4_t _mm_srli_si128_emu_old(int32x4_t a, int imm8)
{
	unsigned char result[16];
	uint8_t shift = imm8 & 0xff;
	if (shift > 15) shift = 16;

	int i;
	for (i = 0; i < (16 - shift); i++)
	{
		result[i] = ((unsigned char *)&a)[shift + i];
	}
	for (; i < 16; i++)
	{
		result[i] = 0;
	}

	/*
	const int32x4_t tmp1 = _mm_load_si128(&a);
	int32x4_t testresult = _mm_srli_si128(tmp1, imm8);
	if (!memcmp(&testresult, result, 16))
	{
	printf("_mm_srli_si128_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_srli_si128_emu: Portable version failed! val: %lx%lx imm: %x emu: %lx%lx, intrin: %lx%lx\n",
	*((uint64_t *)&a + 1), *(uint64_t *)&a,
	imm8,
	*((uint64_t *)result + 1), *(uint64_t *)result,
	*((uint64_t *)&testresult + 1), *(uint64_t *)&testresult);
	}
	*/

	return *(int32x4_t *)result;
}

 int32x4_t _mm_xor_si128_emu(int32x4_t a, int32x4_t b)
{
	return a^ b; //vreinterpretq_m128i_s32( veorq_s32(vreinterpretq_s32_m128i(a), vreinterpretq_s32_m128i(b)) );

}

 int32x4_t _mm_load_si128_emu(const void *p)
{

return vreinterpretq_m128i_s32(vld1q_s32((int32_t *)p));
//	return *(int32x4_t *)p;
}

 void _mm_store_si128_emu(void *p, int32x4_t val)
{
	
  vst1q_s32((int32_t*) p, vreinterpretq_s32_m128i(val));
 // *(int32x4_t *)p = val;
}

int32x4_t _mm_shuffle_epi8_emu(int32x4_t a, int32x4_t b)
{
	int32x4_t result;
	for (int i = 0; i < 16; i++)
	{
		if (((uint8_t *)&b)[i] & 0x80)
		{
			((uint8_t *)&result)[i] = 0;
		}
		else
		{
			((uint8_t *)&result)[i] = ((uint8_t *)&a)[((uint8_t *)&b)[i] & 0xf];
		}
	}

	/*
	const int32x4_t tmp1 = _mm_load_si128(&a);
	const int32x4_t tmp2 = _mm_load_si128(&b);
	int32x4_t testresult = _mm_shuffle_epi8(tmp1, tmp2);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_shuffle_epi8_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_shuffle_epi8_emu: Portable version failed!\n");
	}
	*/

	return result;
}

// portable
int32x4_t lazyLengthHash_port(uint64_t keylength, uint64_t length) {
	const int32x4_t lengthvector = _mm_set_epi64x_emu(keylength, length);
	const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(lengthvector, lengthvector, 0x10);
	return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
int32x4_t precompReduction64_si128_port(int32x4_t A) {

	//const int32x4_t C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
	const int32x4_t C = _mm_cvtsi64_si128_emu((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	int32x4_t Q2 = _mm_clmulepi64_si128_emu(A, C, 0x01);
	int32x4_t Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
		_mm_srli_si128(Q2, 8));
	int32x4_t Q4 = _mm_xor_si128_emu(Q2, A);
	const int32x4_t final = _mm_xor_si128_emu(Q3, Q4);
	return final;/// WARNING: HIGH 64 BITS SHOULD BE ASSUMED TO CONTAIN GARBAGE
}

uint64_t precompReduction64_port(int32x4_t A) {
	int32x4_t tmp = precompReduction64_si128_port(A);
	return _mm_cvtsi128_si64_emu(tmp);
}

// uint8x16_t _mm_aesenc_si128 (uint8x16_t a, uint8x16_t RoundKey)
// {
//     return vaesmcq_u8(vaeseq_u8(a, (uint8x16_t){})) ^ RoundKey;
// }


// verus intermediate hash extra
int32x4_t __verusclmulwithoutreduction64alignedrepeat_port2_2(int32x4_t *randomsource, const int32x4_t buf[4], uint64_t keyMask, uint16_t * __restrict fixrand, 
										uint16_t * __restrict fixrandex, int32x4_t *g_prand, int32x4_t *g_prandex)
{
	int32x4_t const *pbuf, *pbsf;
   const int32x4_t pbuf_copy[4] = {_mm_xor_si128(buf[0],buf[2]), _mm_xor_si128(buf[1],buf[3]), buf[2], buf[3]}; 
	/*
	std::cout << "Random key start: ";
	std::cout << LEToHex(*randomsource) << ", ";
	std::cout << LEToHex(*(randomsource + 1));
	std::cout << std::endl;
	*/

	// divide key mask by 16 from bytes to int32x4_t
	//keyMask >>= 4;

	// the random buffer must have at least 32 16 byte dwords after the keymask to work with this
	// algorithm. we take the value from the last element inside the keyMask + 2, as that will never
	// be used to xor into the accumulator before it is hashed with other values first
	int32x4_t acc = _mm_load_si128_emu(randomsource + (keyMask + 2));

	for (uint64_t i = 0; i < 32; i++)
	{
		//std::cout << "LOOP " << i << " acc: " << LEToHex(acc) << std::endl;

		const uint64_t selector = _mm_cvtsi128_si64_emu(acc);
		const uint64_t selector_fudge = selector & 1 ? 1 : -1 ;

		// get two random locations in the key, which will be mutated and swapped
		fixrand[i]  = (uint16_t) ((selector >> 5) & keyMask);
		fixrandex[i] = (uint16_t) ((selector >>32) & keyMask);
		int32x4_t *prand = randomsource + fixrand[i];
		int32x4_t *prandex = randomsource + fixrandex[i];
		g_prand[i] = *prand;
		g_prandex[i] = *prandex;



		// select random start and order of pbuf processing
		pbuf = pbuf_copy + (selector & 3);
		pbsf = pbuf - selector_fudge;
  
   		//fixrand[i] = prand_idx;
		//fixrandex[i] = prandex_idx;


		switch (selector & 0x1c)
		{
		case 0:
		{
			const int32x4_t temp1 = _mm_load_si128_emu(prandex);
			const int32x4_t temp2 = _mm_load_si128_emu(pbsf);
			const int32x4_t add1 = _mm_xor_si128_emu(temp1, temp2);
			const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			/*
			std::cout << "temp1: " << LEToHex(temp1) << std::endl;
			std::cout << "temp2: " << LEToHex(temp2) << std::endl;
			std::cout << "add1: " << LEToHex(add1) << std::endl;
			std::cout << "clprod1: " << LEToHex(clprod1) << std::endl;
			std::cout << "acc: " << LEToHex(acc) << std::endl;
			*/

			const int32x4_t tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const int32x4_t tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const int32x4_t temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const int32x4_t temp22 = _mm_load_si128_emu(pbuf);
			const int32x4_t add12 = _mm_xor_si128_emu(temp12, temp22);
			const int32x4_t clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);

			const int32x4_t tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			//const int32x4_t tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			*prandex  = _mm_xor_si128_emu(tempb1, temp12);
			//_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 4:
		{
			const int32x4_t temp1 = _mm_load_si128_emu(prand);
			const int32x4_t temp2 = _mm_load_si128_emu(pbuf);
			const int32x4_t add1 = _mm_xor_si128_emu(temp1, temp2);
			const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);
			const int32x4_t clprod2 = _mm_clmulepi64_si128_emu(temp2, temp2, 0x10);
			acc = _mm_xor_si128_emu(clprod2, acc);

			const int32x4_t tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const int32x4_t tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const int32x4_t temp12 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa2);

			const int32x4_t temp22 = _mm_load_si128_emu(pbsf);
			const int32x4_t add12 = _mm_xor_si128_emu(temp12, temp22);
			acc = _mm_xor_si128_emu(add12, acc);

			const int32x4_t tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const int32x4_t tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prand, tempb2);
			break;
		}
		case 8:
		{
			const int32x4_t temp1 = _mm_load_si128_emu(prandex);
			const int32x4_t temp2 = _mm_load_si128_emu(pbuf);
			const int32x4_t add1 = _mm_xor_si128_emu(temp1, temp2);
			acc = _mm_xor_si128_emu(add1, acc);

			const int32x4_t tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const int32x4_t tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const int32x4_t temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const int32x4_t temp22 = _mm_load_si128_emu(pbsf);
			const int32x4_t add12 = _mm_xor_si128_emu(temp12, temp22);
			const int32x4_t clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);
			const int32x4_t clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
			acc = _mm_xor_si128_emu(clprod22, acc);

			const int32x4_t tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const int32x4_t tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 0xc:
		{
			const int32x4_t temp1 = _mm_load_si128_emu(prand);
			const int32x4_t temp2 = _mm_load_si128_emu(pbsf);
			const int32x4_t add1 = _mm_xor_si128_emu(temp1, temp2);

			// cannot be zero here
			const int32_t divisor = (uint32_t)selector;

			acc = _mm_xor_si128_emu(add1, acc);

			const int64_t dividend = _mm_cvtsi128_si64_emu(acc);
                        asm(".global __use_realtime_division\n");
			const int32x4_t modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
			acc = _mm_xor_si128_emu(modulo, acc);

			const int32x4_t tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const int32x4_t tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			if (dividend & 1)
			{
				const int32x4_t temp12 = _mm_load_si128_emu(prandex);
				_mm_store_si128_emu(prandex, tempa2);

				const int32x4_t temp22 = _mm_load_si128_emu(pbuf);
				const int32x4_t add12 = _mm_xor_si128_emu(temp12, temp22);
				const int32x4_t clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
				acc = _mm_xor_si128_emu(clprod12, acc);
				const int32x4_t clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
				acc = _mm_xor_si128_emu(clprod22, acc);

				const int32x4_t tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
				const int32x4_t tempb2 = _mm_xor_si128_emu(tempb1, temp12);
				_mm_store_si128_emu(prand, tempb2);
			}
			else
			{
				*prand = *prandex;
				_mm_store_si128_emu(prandex, tempa2);
				const int32x4_t tempb4 = _mm_load_si128_emu(pbuf);
				acc = _mm_xor_si128_emu(tempb4, acc);
			}
			break;
		}
		case 0x10:
		{
			// a few AES operations
			const int32x4_t *rc = prand;
			int32x4_t tmp;

			int32x4_t temp1 = _mm_load_si128_emu(pbsf);
			int32x4_t temp2 = _mm_load_si128_emu(pbuf);

			AES2(temp1, temp2, 0);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 4);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 8);
			MIX2_EMU(temp1, temp2);

			acc = _mm_xor_si128_emu(temp1, acc);
			acc = _mm_xor_si128_emu(temp2, acc);

			const int32x4_t tempa1 = _mm_load_si128_emu(prand);
			const int32x4_t tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);

			*prand = *prandex;
			*prandex = _mm_xor_si128_emu(tempa1, tempa2);
			break;
		}
		case 0x14:
		{
			// we'll just call this one the monkins loop, inspired by Chris
			const int32x4_t *buftmp = pbsf;
			int32x4_t tmp; // used by MIX2

			int64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			int32x4_t *rc = prand;
			uint64_t aesround = 0;
			int32x4_t onekey, temp1a, temp1b, temp2a, temp2b;

//			do
//			{
//				//std::cout << "acc: " << LEToHex(acc) << ", round check: " << LEToHex((selector & (0x10000000 << rounds))) << std::endl;
//
//				// note that due to compiler and CPUs, we expect this to do:
//				// if (selector & ((0x10000000 << rounds) & 0xffffffff) if rounds != 3 else selector & 0xffffffff80000000):
//				if (selector & ((uint64_t)0x10000000 << rounds))
//				{
//					onekey = _mm_load_si128_emu(rc++);
//					const int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : buftmp);
//					const int32x4_t add1 = _mm_xor_si128_emu(onekey, temp2);
//					const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
//					acc = _mm_xor_si128_emu(clprod1, acc);
//				}
//				else
//				{
//					onekey = _mm_load_si128_emu(rc++);
//					int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);
//					const uint64_t roundidx = aesround++ << 2;
//					AES2(onekey, temp2, roundidx);
//
//					/*
//					std::cout << " onekey1: " << LEToHex(onekey) << std::endl;
//					std::cout << "  temp21: " << LEToHex(temp2) << std::endl;
//					std::cout << "roundkey: " << LEToHex(rc[roundidx]) << std::endl;
//
//					aesenc((unsigned char *)&onekey, (unsigned char *)&(rc[roundidx]));
//
//					std::cout << "onekey2: " << LEToHex(onekey) << std::endl;
//					std::cout << "roundkey: " << LEToHex(rc[roundidx + 1]) << std::endl;
//
//					aesenc((unsigned char *)&temp2, (unsigned char *)&(rc[roundidx + 1]));
//
//					std::cout << " temp22: " << LEToHex(temp2) << std::endl;
//					std::cout << "roundkey: " << LEToHex(rc[roundidx + 2]) << std::endl;
//
//					aesenc((unsigned char *)&onekey, (unsigned char *)&(rc[roundidx + 2]));
//
//					std::cout << "onekey2: " << LEToHex(onekey) << std::endl;
//
//					aesenc((unsigned char *)&temp2, (unsigned char *)&(rc[roundidx + 3]));
//
//					std::cout << " temp22: " << LEToHex(temp2) << std::endl;
//					*/
//
//					MIX2_EMU(onekey, temp2);
//
//					/*
//					std::cout << "onekey3: " << LEToHex(onekey) << std::endl;
//					*/
//
//					acc = _mm_xor_si128_emu(onekey, acc);
//					acc = _mm_xor_si128_emu(temp2, acc);
//				}
//			} while (rounds--);
//
#pragma clang loop unroll(full)
                        //for ( int64_t count = 1; count <= 8; count++ )
                        for ( uint64_t count = 8; count--;  )
                        {
                                if ( rounds >= 0 )
                                {
                                                onekey = _mm_load_si128_emu(rc++);
                                                //printf("selector %" PRIu64 "\n", selector);

                                                if (selector & (0x10000000L << rounds))
                                                {
                                                        const int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : pbsf);  //rounds is odd
                                                        const int32x4_t add1 = _mm_xor_si128_emu(onekey, temp2);
                                                        const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
                                                        acc = _mm_xor_si128_emu(clprod1, acc);
                                                }
                                                else
                                                {
                                                        int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? pbsf : pbuf);  //rounds is odd
                                                        const uint64_t roundidx = aesround++ << 2;
                                                        AES2(onekey, temp2, roundidx);

                                                        MIX2_EMU(onekey, temp2);

                                                        acc ^= onekey ^ temp2;
                                                }
                                rounds--;
                                }
                        }


			const int32x4_t tempa1 = _mm_load_si128_emu(prand);
			const int32x4_t tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
			*prand = *prandex;
			*prandex = _mm_xor_si128_emu(tempa1, tempa2);

			break;
		}
		case 0x18:
   {   
             const int32x4_t *buftmp = pbsf;
                int32x4_t tmp; // used by MIX2

                int64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
                int32x4_t *rc = prand;
                int32x4_t onekey;

//                do
//                {
//                    if (selector & (((uint64_t)0x10000000) << rounds))
//                    {
//                        onekey = _mm_load_si128_emu(rc++);
//                        const int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : buftmp);
//                        onekey = _mm_xor_si128_emu(onekey, temp2);
//                        // cannot be zero here, may be negative
//                        const int32_t divisor = (uint32_t)selector;
//                        const int64_t dividend = _mm_cvtsi128_si64_emu(onekey);
//                        const int32x4_t modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
//                        acc = _mm_xor_si128_emu(modulo, acc);
//                    }
//                    else
//                    {
//                        onekey = _mm_load_si128_emu(rc++);
//                        int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);
//                        const int32x4_t add1 = _mm_xor_si128_emu(onekey, temp2);
//                        onekey = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
//                        const int32x4_t clprod2 = _mm_mulhrs_epi16_emu(acc, onekey);
//                        acc = _mm_xor_si128_emu(clprod2, acc);
//                    }
//                } while (rounds--);
  
#pragma clang loop unroll(full)
                for ( uint64_t count = 8; count--;  )
                {
                        if ( rounds >= 0 )
                        {
                                    onekey = _mm_load_si128_emu(rc++);
                                    if (selector & (0x10000000L << rounds))
                                    {
                                        const int32x4_t temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : pbsf );
                                        onekey = _mm_xor_si128_emu(onekey, temp2);
                                        // cannot be zero here, may be negative
  		                        const int32_t divisor = (uint32_t)selector;
                                        const int64_t dividend = _mm_cvtsi128_si64(onekey);
                                        asm(".global __use_realtime_division\n");
                                        const int32x4_t modulo = _mm_cvtsi32_si128(dividend % divisor);
                                        acc = _mm_xor_si128_emu(modulo, acc);
                                    }
                                    else
                                    {
                                        const int32x4_t temp4 = _mm_load_si128_emu(rounds & 1 ? pbsf : pbuf);
                                        const int32x4_t add1 = _mm_xor_si128_emu(onekey, temp4);
                                        onekey = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
                                        const int32x4_t clprod2 = _mm_mulhrs_epi16_emu(acc, onekey);
                                        acc = _mm_xor_si128_emu(clprod2, acc);
                                    }
                                    rounds--;
                        }
                }


                *prand = _mm_xor_si128_emu(*prandex, acc);
                _mm_store_si128_emu(prandex, onekey);
                break;
            }
		default: 
		{
			const int32x4_t temp1 = _mm_load_si128_emu(pbuf);
			const int32x4_t temp2 = _mm_load_si128_emu(prandex);
			const int32x4_t add1 = _mm_xor_si128_emu(temp1, temp2);
			const int32x4_t clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			const int32x4_t tempa1 = _mm_mulhrs_epi16_emu(acc, temp2);
			const int32x4_t tempa2 = _mm_xor_si128_emu(tempa1, temp2);

			const int32x4_t tempa3 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			acc = _mm_xor_si128_emu(tempa3, acc);
			const int32x4_t temp4 = _mm_load_si128_emu(pbsf);
			acc = _mm_xor_si128(temp4, acc);
			const int32x4_t tempb1 = _mm_mulhrs_epi16_emu(acc, tempa3);
			const int32x4_t tempb2 = _mm_xor_si128_emu(tempb1, tempa3);
			_mm_store_si128_emu(prandex, tempb2);
		//	break;
		}
		}

   
	}
	return acc;
}
// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value
uint64_t verusclhash_port2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint16_t *  __restrict fixrand, uint16_t * __restrict fixrandex,
								 int32x4_t *g_prand, int32x4_t *g_prandex) {
    const unsigned int  m = 128;// we process the data in chunks of 16 cache lines
    int32x4_t * rs64 = (int32x4_t *)random;
    const int32x4_t * string = (const int32x4_t *) buf;

    int32x4_t  acc = __verusclmulwithoutreduction64alignedrepeat_port2_2(rs64, string, keyMask, fixrand, fixrandex, g_prand, g_prandex);
    //acc = _mm_xor_si128_emu(acc, lazyLengthHash_port(1024, 64));
    acc = _mm_xor_si128_emu(acc, _mm_cvtsi32_si128_emu(0x10000));
    return precompReduction64_port(acc);
}
