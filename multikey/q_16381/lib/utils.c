/**
 *
 * Reference ISO-C11 Implementation of LESS.
 *
 * @version 1.1 (March 2023)
 *
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 *
 * This code is hereby placed in the public domain.
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

#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <djbsort.h>


/// swaps a and b if
void cswap(uintptr_t *a,
           uintptr_t *b,
           const uintptr_t mask) {
    *a ^= (mask & *b);
    *b ^= (mask & *a);
    *a ^= (mask & *b);
}

#ifdef USE_AVX2
#include <immintrin.h>

/// taken from kyber
/// Description: Compare two arrays for equality in constant time.
/// Arguments:   const uint8_t *a: pointer to first byte array
///              const uint8_t *b: pointer to second byte array
///              size_t len: length of the byte arrays
///
/// Returns 0 if the byte arrays are equal, 1 otherwise
int verify(const uint8_t *a,
           const uint8_t *b,
           size_t len) {
    size_t i;
    uint64_t r;
    __m256i f, g, h;

    h = _mm256_setzero_si256();
    for(i=0;i<len/32;i++) {
        f = _mm256_loadu_si256((__m256i *)&a[32*i]);
        g = _mm256_loadu_si256((__m256i *)&b[32*i]);
        f = _mm256_xor_si256(f,g);
        h = _mm256_or_si256(h,f);
    }
    r = 1u - (uint32_t)_mm256_testz_si256(h,h);

    a += 32*i;
    b += 32*i;
    len -= 32*i;

    for(i=0;i<len;i++) {
        r |= a[i] ^ b[i];
    }

    r = (-r) >> 63;
    return r;
}
#else

/// taken from the kyber impl.
/// Description: Compare two arrays for equality in constant time.
///
/// Arguments:   const uint8_t *a: pointer to first byte array
///              const uint8_t *b: pointer to second byte array
///              size_t len:       length of the byte arrays
///
/// Returns 0 if the byte arrays are equal, 1 otherwise
int verify(const uint8_t *a,
           const uint8_t *b,
           const size_t len) {
    uint8_t r = 0;

    for(size_t i=0;i<len;i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

#endif

#define MAX_KEYPAIR_INDEX (NUM_KEYPAIRS-1)
#define KEYPAIR_INDEX_MASK ( ((uint16_t)1 << BITS_TO_REPRESENT(MAX_KEYPAIR_INDEX)) -1 )
/* bitmask for rejection sampling of the position */
#define  POSITION_MASK (( (uint16_t)1 << BITS_TO_REPRESENT(T-1))-1)

/* Expands a digest expanding it into a fixed weight string with elements in
 * Z_{NUM_KEYPAIRS}. */
void SampleChallenge(uint8_t fixed_weight_string[T],
                     const uint8_t digest[HASH_DIGEST_LENGTH]) {
    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state,
                      (const unsigned char *) digest,
                      HASH_DIGEST_LENGTH);

    uint64_t rnd_buf;
    uint32_t c = 0;
    for (uint32_t i = 0; i < T-W; i++) {
        fixed_weight_string[i] = 0;
    }

    if (NUM_KEYPAIRS != 2) {
        for (uint32_t i = T-W; i < T; i++) {
            uint8_t value;
            do {
                if (c == 0) {
                    csprng_randombytes((unsigned char *) &rnd_buf,
                                     sizeof(uint64_t),
                                     &shake_state);
                    c = 64u / BITS_TO_REPRESENT(MAX_KEYPAIR_INDEX);
                }

                value = rnd_buf & (KEYPAIR_INDEX_MASK);
                rnd_buf >>= BITS_TO_REPRESENT(MAX_KEYPAIR_INDEX);
                c -= 1;
            } while (value >= (NUM_KEYPAIRS-1));
            fixed_weight_string[i] = value + 1;
        }
    } else {
        for (uint32_t i = T-W; i < T; i++) {
            fixed_weight_string[i] = 1;
        }
    }

    for (uint32_t p = T - W; p < T; p++) {
        POSITION_T pos;
        do {
            if (c == 0) {
                csprng_randombytes((unsigned char *) &rnd_buf,
                                   sizeof(uint64_t),
                                   &shake_state);
                c = 64u / BITS_TO_REPRESENT(T-1);
            }
            pos = rnd_buf & (POSITION_MASK);
            rnd_buf >>= BITS_TO_REPRESENT(T-1);
            c -= 1;
        } while (pos > p);
        const uint8_t tmp = fixed_weight_string[p];
        fixed_weight_string[p] = fixed_weight_string[pos];
        fixed_weight_string[pos] = tmp;
    }
}

void sort_ct(uint16_t* out, const uint16_t* vec){
    uint32_t ordered[512];
    memset(ordered,0x8fff,sizeof(uint32_t)*512);

    for(int i=0; i<N; i++){
        ordered[i] = (uint32_t)vec[i];
    }
    
    uint32_sort(ordered,512);

    for(int i=0; i<N; i++){
        out[i] = (uint16_t)ordered[i];
    }
}

void sort_ct_double(uint16_t* out, const uint16_t* vec1, const uint16_t* vec2, uint16_t size1, uint16_t size2){
    uint32_t ordered[512];
    memset(ordered,0x8fff,sizeof(uint32_t)*512);

    for(int i=0; i<size1; i++){
        ordered[i] = (uint32_t)vec1[i];
    }
    for(int i=0; i<size2; i++){
        ordered[size1 + i] = (uint32_t)vec2[i];
    }
    
    uint32_sort(ordered,512);

    for(int i=0; i<size1+size2; i++){
        out[i] = (uint16_t)ordered[i];
    }
}

void sort_fast(uint16_t* out, const uint16_t* vec){
    uint32_t ordered[512];
    memset(ordered,0x8fff,sizeof(uint32_t)*512);

    for(int i=0; i<N; i++){
        ordered[i] = (uint32_t)vec[i];
    }
    
    uint32_sort(ordered,512);

    for(int i=0; i<N; i++){
        out[i] = (uint16_t)ordered[i];
    }
}

void sort_fast_double(uint16_t* out, const uint16_t* vec1, const uint16_t* vec2, uint16_t size1, uint16_t size2){
    uint32_t ordered[512];
    memset(ordered,0x8fff,sizeof(uint32_t)*512);

    for(int i=0; i<size1; i++){
        ordered[i] = (uint32_t)vec1[i];
    }
    for(int i=0; i<size2; i++){
        ordered[size1 + i] = (uint32_t)vec2[i];
    }
    
    uint32_sort(ordered,512);

    for(int i=0; i<N; i++){
        out[i] = (uint16_t)ordered[i];
    }
}

void histogram(FQ_ELEM *mset,
                const FQ_ELEM *to_order) {

    memset(mset,0,sizeof(uint16_t)*Q);
	for (uint16_t i = 0 ; i < N ; i++) {
		mset[to_order[i]]++;
	}
}

void histogram_c1_c2(FQ_ELEM *mset,
                const FQ_ELEM *c1,
                const FQ_ELEM *c2,
                const uint32_t size1,
                const uint32_t size2) {

    memset(mset,0,sizeof(uint16_t)*Q);
	for (uint16_t i = 0 ; i < size1 ; i++) {
		mset[c1[i]]++;
	}
	for (uint16_t i = 0 ; i < size2; i++) {
		mset[c2[i]]++;
	}
}

uint8_t check_repetition(uint16_t* ordered){
    for(int i=1; i<N; i++){
        if(ordered[i-1] == ordered[i]) return 1;
    }
    return 0;
}
uint8_t check_repetition_smol(uint16_t* ordered){
    for(int i=1; i<K; i++){
        if(ordered[i-1] == ordered[i]) return 1;
    }
    return 0;
}

uint8_t gen_ord_from_hist(uint16_t* ordering,uint16_t* histogram){

    uint16_t index = 0;
	for (uint16_t i = 0 ; i < Q ; i++) {
        if(histogram[i] == 1){
		    ordering[index] = i;
            index += 1;
        }else if(histogram[i] > 1){
            return histogram[i];
        }
    }
    return 0;
}

uint8_t histogram_c1_c2_counting(FQ_ELEM *mset,
                const FQ_ELEM *c1,
                const FQ_ELEM *c2,
                const uint32_t size1,
                const uint32_t size2) {

    memset(mset,0,sizeof(uint16_t)*Q);

	for (uint16_t i = 0 ; i < size1 ; i++) {
		if(mset[c1[i]]>0){
            return 1;
        }
		mset[c1[i]]++;
	}

	for (uint16_t i = 0 ; i < size2; i++) {
		if(mset[c2[i]]>0){
            return 1;
        }
		mset[c2[i]]++;
	}

    return 0;
}


/* Expands a digest expanding it into a fixed weight string with elements in
 * Z_{NUM_KEYPAIRS}. */
void SampleChallengeUniform(uint8_t challenge_string[T],
                     const uint8_t digest[HASH_DIGEST_LENGTH]) {
    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state,
                      (const unsigned char *) digest,
                      HASH_DIGEST_LENGTH);
    rand_range_chal_state_elements(&shake_state,challenge_string,T);
}
