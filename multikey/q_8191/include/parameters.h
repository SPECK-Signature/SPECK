/**
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#pragma once
#include <stdint.h>

/* Seed tree max size is computed according to Parameter Generation Script in Utilities folder */

/***************************** Common Parameters ******************************/
#define Q (8191)
#define Qm1 (Q-1)
#define FQ_ELEM uint16_t
#define FQ_DOUBLEPREC uint32_t
#define POSITION_T uint16_t

#define REPETITION_THRESHOLD 0

/********************************* Category 1 *********************************/

#if CATEGORY == 248
    #define N (248)
    #define K (112)
#else
    #define N (400)
    #define K (80)
#endif

#define SEED_LENGTH_BYTES (16)
#define SIGN_PIVOT_REUSE_LIMIT (25) // Ensures probability of non-CT operation is < 2^-64

//#if TARGET==133
//#define T (133)
//#define W (60)
//#define TREE_OFFSETS {0, 0, 0, 2, 2, 10, 10, 10, 10}
//#define TREE_NODES_PER_LEVEL {1, 2, 4, 6, 12, 16, 32, 64, 128}
//#define TREE_LEAVES_PER_LEVEL {0, 0, 1, 0, 4, 0, 0, 0, 128}
//#define TREE_SUBROOTS 3
//#define TREE_LEAVES_START_INDICES {137, 21, 6}
//#define TREE_CONSECUTIVE_LEAVES {128, 4, 1}
//#define TREE_NODES_TO_STORE 60
//#define MAX_PUBLISHED_SEEDS 70
//#define T (40)
#define W (19)
#define TREE_OFFSETS {0, 0, 0, 0, 0, 16, 16}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 16, 16, 32}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 0, 8, 0, 32}
#define TREE_SUBROOTS 2
#define TREE_LEAVES_START_INDICES {47, 23}
#define TREE_CONSECUTIVE_LEAVES {32, 8}
#define TREE_NODES_TO_STORE 20


#if TARGET == 32 
#define NUM_KEYPAIRS (32)
#define T (26)
#elif TARGET == 16
#define NUM_KEYPAIRS (16)
#define T (32)
#elif TARGET == 8
#define NUM_KEYPAIRS (8)
#define T (41)
#elif TARGET == 4
#define NUM_KEYPAIRS (4)
#define T (56)
#else
#define NUM_KEYPAIRS (2)
#define T (81)
#endif

#define MAX_PUBLISHED_SEEDS T
#define T_BYTES 1

#define VERIFY_PIVOT_REUSE_LIMIT K

/* number of bytes needed to store K or N bits */
//#define K8 ((K+7u)/8u)
//#define N8 ((N+7u)/8u)

/// rounds x to the next multiple of n
#define NEXT_MULTIPLE(x,n) ((((x)+((n)-1u))/(n))*(n))

#if defined(USE_AVX2) || defined(USE_NEON)
/// In case of the optimized implementation, we need that all vectors
/// are of a length, which is a multiple of 16
#define N_K_pad NEXT_MULTIPLE(N-K, 16)
#define N_pad   NEXT_MULTIPLE(N, 16)
#define K_pad   NEXT_MULTIPLE(K, 16)
#else
/// in case of the reference implementation, we do not need this behaviour.
#define N_K_pad (N-K)
#define N_pad   N
#define K_pad   K
#endif

#define Q_pad   NEXT_MULTIPLE(Q, 8)

/***************** Derived parameters *****************************************/
/*length of the output of the cryptographic hash, in bytes */
#define HASH_DIGEST_LENGTH (2*SEED_LENGTH_BYTES)
#define SALT_LENGTH_BYTES HASH_DIGEST_LENGTH


/* length of the private key seed doubled to avoid multikey attacks */
#define PRIVATE_KEY_SEED_LENGTH_BYTES (2*SEED_LENGTH_BYTES)

#define MASK_Q ((1 << BITS_TO_REPRESENT(Q)) - 1)
#define MASK_N ((1 << BITS_TO_REPRESENT(N)) - 1)


#define IS_REPRESENTABLE_IN_D_BITS(D, N)                \
  (((unsigned long) N>=(1UL << (D-1)) && (unsigned long) N<(1UL << D)) ? D : -1)

#define BITS_TO_REPRESENT(N)                            \
  (N == 0 ? 1 : (15                                     \
                 + IS_REPRESENTABLE_IN_D_BITS( 1, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 2, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 3, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 4, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 5, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 6, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 7, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 8, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 9, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(10, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(11, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(12, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(13, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(14, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(15, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(16, N)    \
                 )                                      \
   )

#define LOG2(L) ( (BITS_TO_REPRESENT(L) > BITS_TO_REPRESENT(L-1)) ? (BITS_TO_REPRESENT(L-1)) : (BITS_TO_REPRESENT(L)) )

#define NUM_LEAVES_SEED_TREE (T)
#define NUM_NODES_SEED_TREE ((2*NUM_LEAVES_SEED_TREE) - 1)

#define RREF_MAT_PACKEDBYTES ((BITS_TO_REPRESENT(Q)*(N-K)*K + 7)/8 + (N + 7)/8)
#define SPECK_RREF_MAT_PACKEDBYTES ((BITS_TO_REPRESENT(Q)*(N-K)*K + 7)/8)
#define SPECK_C1S_PACKEDBYTES ((BITS_TO_REPRESENT(Q)*(K)*T + 15)/16)

#define SEED_TREE_MAX_PUBLISHED_BYTES (MAX_PUBLISHED_SEEDS*SEED_LENGTH_BYTES + 1)

//#define SPECK_RESAMPLE_G // <- Resample G0 in Sign and Verify
#define SPECK_FULL_G // <- Compress/Expand G0 in Keygen/Sign and Verify 
//#define SPECK_COMPRESS_G // <- Compress/Expand G0 in Keygen/Sign and Verify 

#define SPECK_COMPRESS_GP 

#define SPECK_COMPRESS_C1S

#ifdef SPECK_COMPRESS_C1S
//#define SPECK_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + SPECK_C1S_PACKEDBYTES + NR_LEAVES*SEED_LENGTH_BYTES + 1)
#define SPECK_SIGNATURE_SIZE(NR_SEEDS) (HASH_DIGEST_LENGTH*2 + ((BITS_TO_REPRESENT(Q)*(K)*(T-NR_SEEDS) + 7)/8) + NR_SEEDS*SEED_LENGTH_BYTES + 1)
#else
//#define SPECK_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + 2*W*K_pad + NR_LEAVES*SEED_LENGTH_BYTES + 1)
#define SPECK_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + 2*(T-NR_LEAVES)*K_pad + NR_LEAVES*SEED_LENGTH_BYTES + 1)
#endif
