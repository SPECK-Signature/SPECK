#define _POSIX_C_SOURCE 199309L

#include <time.h>

#include <math.h>
#include <stdio.h>
#include <wchar.h>

#include "cycles.h"
#include "api.h"
#include "parameters.h"
#include "rng.h"

/// Convert seconds to milliseconds
#define SEC_TO_MS(sec) ((sec)*1000)
/// Convert seconds to microseconds
#define SEC_TO_US(sec) ((sec)*1000000)
/// Convert seconds to nanoseconds
#define SEC_TO_NS(sec) ((sec)*1000000000)

/// Convert nanoseconds to seconds
#define NS_TO_SEC(ns)   ((ns)/1000000000)
/// Convert nanoseconds to milliseconds
#define NS_TO_MS(ns)    ((ns)/1000000)
/// Convert nanoseconds to microseconds
#define NS_TO_US(ns)    ((ns)/1000)
/// Helpful for regex 
#define NS_TO_NS(ns)    ((ns))

#define NUM_RUNS 128


typedef struct {
    long double mean;
    long double M2;
    long count;
} welford_t;

static inline
void welford_init(welford_t *state) {
    state->mean = 0.0;
    state->M2 = 0.0;
    state->count = 0;
    return;
}

static inline
void welford_update(welford_t *state, long double sample) {
    long double delta, delta2;
    state->count = state->count + 1;
    delta = sample - state->mean;
    state->mean += delta / (long double)(state->count);
    delta2 = sample - state->mean;
    state->M2 += delta * delta2;
}

static inline
void welford_print(const welford_t state) {
    printf("%.2Lf kCycles (AVG), %.2Lf kCycles (STDDEV)",
           state.mean,
           sqrtl(state.M2/(long double)(state.count-1)));
}


void PERK_sign_verify_speed(void){
    fprintf(stderr,"Computing number of clock cycles as the average of %d runs\n", NUM_RUNS);
    welford_t timer;
    uint64_t cycles;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[8] = "Signme!";
    unsigned long mlen = 8;


    unsigned long siglens = 0;

    unsigned long smlen;
    unsigned char sm[sizeof(m) + CRYPTO_BYTES];


    struct timespec ts;
    uint64_t ms_start;
    uint64_t ms_end;
    uint64_t ms_sum;


    printf("Timings (kcycles):\n");

    ms_sum = 0;

    welford_init(&timer);
    for(size_t i = 0; i <NUM_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_start = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        cycles = read_cycle_counter();
        crypto_sign_keypair(pk, sk);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_end = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        ms_sum += ms_end-ms_start;
    }
    printf("Keygen kCycles (avg,stddev): ");
    welford_print(timer);
    printf("\n");
    printf("Keygen milliseconds (avg): %0.2Lf \n",(long double)ms_sum/NUM_RUNS);

    ms_sum = 0;

    welford_init(&timer);
    for(int i = 0; i <NUM_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_start = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        cycles = read_cycle_counter();
        crypto_sign(sm, &smlen, m, sizeof(m), sk);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_end = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        ms_sum += ms_end-ms_start;
        siglens += (smlen - mlen);

    }
    printf("Signing kCycles (avg,stddev): ");
    welford_print(timer);
    printf("\n");
    printf("Signing milliseconds (avg): %0.2Lf \n",(long double)ms_sum/NUM_RUNS);
    printf("Signature size (Bytes): %0.2Lf \n",(long double)siglens/NUM_RUNS);


    ms_sum = 0;

    int is_signature_ok = 1;
    welford_init(&timer);
    for(int i = 0; i <NUM_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_start = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        cycles = read_cycle_counter();
        is_signature_ok = crypto_sign_open(m, &mlen, sm, smlen, pk);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_end = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        ms_sum += ms_end-ms_start;
    }
    printf("Verification kCycles (avg,stddev):");
    welford_print(timer);
    printf("\n");
    printf("Verification milliseconds (avg): %0.2Lf \n",(long double)ms_sum/NUM_RUNS);
    fprintf(stderr,"Keygen-Sign-Verify: %s", is_signature_ok == 0 ? "functional\n": "not functional\n" );
}


int main(int argc, char* argv[]){
    (void)argc;
    (void)argv;
    PERK_sign_verify_speed();
}
