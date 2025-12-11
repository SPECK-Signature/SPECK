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
#define Q (127)
#define Qm1 (Q-1)
#define FQ_ELEM uint8_t
#define FQ_DOUBLEPREC uint16_t
#define POSITION_T uint8_t


/********************************* Category 1 *********************************/
//#elif CATEGORY == 252
#define N (252)
#define K (126)
#define NUM_KEYPAIRS (2)

#define SEED_LENGTH_BYTES (16)
#define SIGN_PIVOT_REUSE_LIMIT (25) // Ensures probability of non-CT operation is < 2^-64


#if TARGET==133
#define T (133)
#define W (60)
#define TREE_OFFSETS {0, 0, 0, 2, 2, 10, 10, 10, 10}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 6, 12, 16, 32, 64, 128}
#define TREE_LEAVES_PER_LEVEL {0, 0, 1, 0, 4, 0, 0, 0, 128}
#define TREE_SUBROOTS 3
#define TREE_LEAVES_START_INDICES {137, 21, 6}
#define TREE_CONSECUTIVE_LEAVES {128, 4, 1}
#define TREE_NODES_TO_STORE 60
#define MAX_PUBLISHED_SEEDS 70


#elif TARGET==256
#define T (256)
#define W (30)
#define TREE_OFFSETS {0, 0, 0, 0, 0, 0, 0, 0, 0}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 16, 32, 64, 128, 256}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 0, 0, 0, 0, 0, 256}
#define TREE_SUBROOTS 1
#define TREE_LEAVES_START_INDICES {255}
#define TREE_CONSECUTIVE_LEAVES {256}
#define TREE_NODES_TO_STORE 30
#define MAX_PUBLISHED_SEEDS 92


#elif TARGET==512
#define T (512)
#define W (23)
#define TREE_OFFSETS {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
#define TREE_SUBROOTS 1
#define TREE_LEAVES_START_INDICES {511}
#define TREE_CONSECUTIVE_LEAVES {512}
#define TREE_NODES_TO_STORE 23
#define MAX_PUBLISHED_SEEDS 102

#elif TARGET==768
#define T (768)
#define W (20)
#define TREE_OFFSETS {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 512}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 0, 0, 0, 0, 0, 0, 256, 512}
#define TREE_SUBROOTS 2
#define TREE_LEAVES_START_INDICES {1023, 767}
#define TREE_CONSECUTIVE_LEAVES {512, 256}
#define TREE_NODES_TO_STORE 20
#define MAX_PUBLISHED_SEEDS 106


#elif TARGET==4096
#define T (4096)
#define W (14)
#define TREE_OFFSETS {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4096}
#define TREE_SUBROOTS 1
#define TREE_LEAVES_START_INDICES {4095}
#define TREE_CONSECUTIVE_LEAVES {4096}
#define TREE_NODES_TO_STORE 14
#define MAX_PUBLISHED_SEEDS 114

#else
#error define optimization corner in parameters.h
#endif

#define VERIFY_PIVOT_REUSE_LIMIT K

/* number of bytes needed to store K or N bits */
#define K8 ((K+7u)/8u)
#define N8 ((N+7u)/8u)

/// rounds x to the next multiple of n
#define NEXT_MULTIPLE(x,n) ((((x)+((n)-1u))/(n))*(n))

#if defined(USE_AVX2) || defined(USE_NEON)
/// In case of the optimized implementation, we need that all vectors
/// are of a length, which is a multiple of 32
#define N_K_pad NEXT_MULTIPLE(N-K, 32)
#define N_pad   NEXT_MULTIPLE(N, 32)
#define K_pad   NEXT_MULTIPLE(K, 32)
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
#define SPECK_C1S_PACKEDBYTES ((BITS_TO_REPRESENT(Q)*(N-K)*W + 7)/8)

#define SEED_TREE_MAX_PUBLISHED_BYTES (MAX_PUBLISHED_SEEDS*SEED_LENGTH_BYTES + 1)

//#define SPECK_RESAMPLE_G // <- Resample G0 in Sign and Verify
#define SPECK_FULL_G // <- Compress/Expand G0 in Keygen/Sign and Verify 
//#define SPECK_COMPRESS_G // <- Compress/Expand G0 in Keygen/Sign and Verify 

#define SPECK_COMPRESS_GP 

#define SPECK_COMPRESS_C1S

#ifdef SPECK_COMPRESS_C1S
#define SPECK_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + SPECK_C1S_PACKEDBYTES + NR_LEAVES*SEED_LENGTH_BYTES + 1)
#else
#define SPECK_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + Q*W + NR_LEAVES*SEED_LENGTH_BYTES + 1)
#endif

// Things
#define CSPRNG_DOMAIN_SEP_CONST ((uint16_t)0)
#define HASH_DOMAIN_SEP_CONST ((uint16_t)32768)
