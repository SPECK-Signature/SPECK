#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sort.h"
#include "fq_arith.h"
#include "permutation.h"
#include "codes.h"

#include "test_helpers.c"
#define TESTS 100

int test_counting_sort(void) {
    const size_t s = K;
    FQ_ELEM *d1 = (FQ_ELEM *)malloc(sizeof(FQ_ELEM) * s);
    for (size_t i = 0; i < s; i++) { d1[i] = s-1-i; }

    counting_sort_u8(d1, s);
    for (size_t i = 1; i < s; i++) {
        if (d1[i-1] > d1[i]) {
            printf("error counting sort\n");
            return 1;
        }
    }

    free(d1);
}

int main(void) {
    if (test_counting_sort()) return 1;

    printf("Done, all worked\n");
    return 0;
}
