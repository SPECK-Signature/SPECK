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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parameters.h"
#include "utils.h"
#include "fq_arith.h"
#include "codes.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/// NOTE: specialised counting sort for Fq. Thus,
/// this implementation assumes that every input element
/// is reduced mod 127
/// \param arr[in/out] input array
/// \param size[in] length of the input array
void counting_sort_u8(FQ_ELEM *arr,
                      const uint32_t size) {
	/// NOTE: the type `uint32_t` is not completly arbitrary choosen.
	/// Floyd did a quick benchmark between `uint16_t`, `uint32_t`, `uint64_t`
	/// and `uint32_t` seemed to be the fastest. But thats only true
	/// on a Ryzen7600X. On your machine thats maybe different.
	/// NOTE: `uint8_t` is not possible as there could be 256 times
	/// the same field element. Unlikely but possible.
	uint32_t cnt[128] __attribute__((aligned(32))) = { 0 };

    /// compute the histogram
	for (uint32_t i = 0 ; i < size ; ++i) {
		cnt[arr[i]]++;
	}

    /// compute the prefixsum
	uint32_t i = 0;
	for (size_t a = 0 ; a < Q; ++a) {
		while (cnt[a]--) {
			arr[i++] = a;
		}
	}
}

/// NOTE: only needed for `compute_canonical_form_type4_sub`
/// \input row1[in]:
/// \input row2[in]:
/// \return: 0 if multiset(row1) == multiset(row2)
///          x if row1 > row2
///         -x if row1 < row2
int compare_rows(const FQ_ELEM *row1,
                 const FQ_ELEM *row2) {
    uint32_t i=0;
    while((i < (Q-1)) && (row1[i] == row2[i])) {
        i += 1;
    }
    return (((int)(row2[i]))-((int)(row1[i])));
}

/// NOTE: specialised counting sort for Fq. Thus,
/// this implementation assumes that every input element
/// is reduced mod 127
/// \param arr[in/out] input array
/// \param size[in] length of the input array
void counting_sort_perm(FQ_ELEM *arr,
                      const FQ_ELEM *to_order,
                      const uint32_t size,
                      permutation_t *perm) {
	/// NOTE: the type `uint32_t` is not completly arbitrary choosen.
	/// Floyd did a quick benchmark between `uint16_t`, `uint32_t`, `uint64_t`
	/// and `uint32_t` seemed to be the fastest. But thats only true
	/// on a Ryzen7600X. On your machine thats maybe different.
	/// NOTE: `uint8_t` is not possible as there could be 256 times
	/// the same field element. Unlikely but possible.
	uint32_t cnt[128] __attribute__((aligned(32))) = { 0 };
	uint32_t cnt2[128][N] __attribute__((aligned(32))) = { 0 };

    /// compute the histogram
	for (uint32_t i = 0 ; i < size ; ++i) {
		cnt2[to_order[i]][cnt[to_order[i]]] = i;
		cnt[to_order[i]]++;
	}

    /// compute the prefixsum
	uint32_t i = 0;
	for (size_t a = 0 ; a < Q; ++a) {
		while (cnt[a]--) {
            perm->values[i] = cnt2[a][cnt[a]];
			arr[i++] = a;
		}
	}
}

/// NOTE: specialised counting sort for Fq. Thus,
/// this implementation assumes that every input element
/// is reduced mod 127
/// \param arr[in/out] input array
/// \param size[in] length of the input array
void counting_sort(FQ_ELEM *arr,
                      const FQ_ELEM *to_order,
                      const uint32_t size) {
	/// NOTE: the type `uint32_t` is not completly arbitrary choosen.
	/// Floyd did a quick benchmark between `uint16_t`, `uint32_t`, `uint64_t`
	/// and `uint32_t` seemed to be the fastest. But thats only true
	/// on a Ryzen7600X. On your machine thats maybe different.
	/// NOTE: `uint8_t` is not possible as there could be 256 times
	/// the same field element. Unlikely but possible.
	uint32_t cnt[128] __attribute__((aligned(32))) = { 0 };

    /// compute the histogram
	for (uint32_t i = 0 ; i < size ; ++i) {
		cnt[to_order[i]]++;
	}

    /// compute the prefixsum
	uint32_t i = 0;
	for (size_t a = 0 ; a < Q; ++a) {
		while (cnt[a]--) {
			arr[i++] = a;
		}
	}
}

void histogram(FQ_ELEM *mset,
                const FQ_ELEM *to_order,
                const uint32_t size) {

    memset(mset,0,sizeof(uint8_t)*Q);
	for (uint8_t i = 0 ; i < size ; ++i) {
		mset[to_order[i]]++;
	}
}

void histogram_c1_c2(FQ_ELEM *mset,
                const FQ_ELEM *c1,
                const FQ_ELEM *c2,
                const uint32_t size) {

    memset(mset,0,sizeof(uint8_t)*Q);
	for (uint8_t i = 0 ; i < size ; ++i) {
		mset[c1[i]]++;
		mset[c2[i]]++;
	}
}
