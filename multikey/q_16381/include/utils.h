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

#include "parameters.h"
#include "codes.h"
#include <stddef.h>

#define SWAP(a, b) { (a)^=(b); (b)^=(a); (a)^=(b); }
#define MASKED_SWAP(a,b,m) { a^=(m&b); b^=(m&a); a^=(m&b); }

void cswap(uintptr_t *a,
           uintptr_t *b,
           uintptr_t mask);

void SampleChallenge(uint8_t fixed_weight_string[T],
                     const uint8_t digest[HASH_DIGEST_LENGTH]);

void SampleChallengeUniform(uint8_t challenge_string[T],
                     const uint8_t digest[HASH_DIGEST_LENGTH]);

void SampleSeeds(uint8_t challenge_string[T][SEED_LENGTH_BYTES],
                const uint8_t digest[HASH_DIGEST_LENGTH],
                const uint8_t salt[HASH_DIGEST_LENGTH]);


int verify(const uint8_t *a,
           const uint8_t *b,
           const size_t len);

void sort_ct(uint16_t* out, const uint16_t* vec);
void sort_ct_double(uint16_t* out, const uint16_t* vec1, const uint16_t* vec2, uint16_t size1, uint16_t size2);
void sort_fast(uint16_t* out, const uint16_t* vec);
void sort_fast_double(uint16_t* out, const uint16_t* vec1, const uint16_t* vec2, uint16_t size1, uint16_t size2);

void histogram(FQ_ELEM *mset,const FQ_ELEM *to_order);

void histogram_c1_c2(FQ_ELEM *mset,
                const FQ_ELEM *c1,
                const FQ_ELEM *c2,
                const uint32_t size1,
                const uint32_t size2);

uint8_t histogram_c1_c2_counting(FQ_ELEM *mset,
                const FQ_ELEM *c1,
                const FQ_ELEM *c2,
                const uint32_t size1,
                const uint32_t size2);

uint8_t check_repetition(uint16_t* ordered);
uint8_t check_repetition_smol(uint16_t* ordered);

uint8_t gen_ord_from_hist(uint16_t* ordering,uint16_t* histogram);
