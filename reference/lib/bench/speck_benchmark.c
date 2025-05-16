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

#define _POSIX_C_SOURCE 199309L
#include <time.h>

#include <math.h>
#include <stdio.h>
#include <wchar.h>

#include "SPECK.h"
#include "codes.h"
#include "cycles.h"
#include "rng.h"
#include "permutation.h"
//#include "test_helpers.h"
#include "api.h"

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
    printf("%.2Lf,%.2Lf",
           state.mean,
           sqrtl(state.M2/(long double)(state.count-1)));
}

#if defined(CATEGORY_5)
#define NUM_RUNS 128
#elif defined(CATEGORY_3)
#define NUM_RUNS 128
#else
#define NUM_RUNS 128
#endif

#define NUM_AVG_RUNS (1u << 10u)

#ifdef N_pad
#define NN N_pad
#else
#define NN N
#endif


/* samples a random generator matrix */
void generator_rnd(generator_mat_t *res) {
   for(uint32_t i = 0; i < K; i++) {
      rand_range_q_elements(res->values[i], N);
   }
} /* end generator_rnd */


void microbench(void){
    welford_t timer;
    welford_init(&timer);

    generator_mat_t G;
    generator_rnd(&G);
    uint8_t is_pivot_column[NN];

    uint64_t cycles;
    for(int i = 0; i <NUM_RUNS; i++) {
        cycles = read_cycle_counter();
        generator_RREF(&G,is_pivot_column);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
    }
    fprintf(stderr,"Gaussian elimination kCycles (avg,stddev):");
    welford_print(timer);
    printf("\n");

}

void info(void){
    fprintf(stderr,"Code parameters: n= %d, k= %d, q=%d\n", N,K,Q);
    fprintf(stderr,"num. keypairs = %d\n",NUM_KEYPAIRS);
    fprintf(stderr,"Fixed weight challenge vector: %d rounds, weight %d \n",T,W);
    fprintf(stderr,"SPECK Private key: %luB\n", sizeof(speck_prikey_t));
    fprintf(stderr,"Public key %luB\n", sizeof(speck_pubkey_t));
    fprintf(stderr,"Signature: %luB, %f\n", sizeof(speck_sign_t), ((float) sizeof(speck_sign_t))/1024);
}

void bench_sample_antiorthogonal(void){
    fprintf(stderr,"Computing number of clock cycles as the average of %d runs\n", NUM_RUNS);
    welford_t timer;
    uint64_t cycles;
    info();

    unsigned char compressed_sk[PRIVATE_KEY_SEED_LENGTH_BYTES];
    randombytes(compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    unsigned char G_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    FQ_ELEM A[K][K];

    printf("Timings (kcycles):\n");
    welford_init(&timer);
    for(size_t i = 0; i <NUM_RUNS; i++) {
        cycles = read_cycle_counter();
        antiorthogonal_sample(A,G_seed);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
    }
    printf("Antiorthogonal Sampling kCycles (avg,stddev): ");
    welford_print(timer);
    printf("\n");
}

void SPECK_sign_verify_speed(void){
    fprintf(stderr,"Computing number of clock cycles as the average of %d runs\n", NUM_RUNS);
    welford_t timer;
    uint64_t cycles;
    speck_pubkey_t pk;
    speck_prikey_t sk;
    speck_sign_t signature;
    char message[8] = "Signme!";
    info();

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
        SPECK_keygen(&sk,&pk);
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
        SPECK_sign(&sk,&pk,message,8,&signature);
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_end = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        ms_sum += ms_end-ms_start;
    }
    printf("Signature kCycles (avg,stddev): ");
    welford_print(timer);
    printf("\n");
    printf("Signature milliseconds (avg): %0.2Lf \n",(long double)ms_sum/NUM_RUNS);

    ms_sum = 0;

    int is_signature_ok = 1;
    welford_init(&timer);
    for(int i = 0; i <NUM_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_start = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        cycles = read_cycle_counter();
        is_signature_ok = SPECK_verify(&pk,message,8,&signature); // Message never changes
        welford_update(&timer,(read_cycle_counter()-cycles)/1000.0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        ms_end = SEC_TO_MS((uint64_t)ts.tv_sec) + NS_TO_MS((uint64_t)ts.tv_nsec);
        ms_sum += ms_end-ms_start;
    }
    printf("Verification kCycles (avg,stddev):");
    welford_print(timer);
    printf("\n");
    printf("Verification milliseconds (avg): %0.2Lf \n",(long double)ms_sum/NUM_RUNS);
    fprintf(stderr,"Keygen-Sign-Verify: %s", is_signature_ok == 1 ? "functional\n": "not functional\n" );
}

int main(int argc, char* argv[]){
    (void)argc;
    (void)argv;
    setup_cycle_counter();
    initialize_csprng(&platform_csprng_state,
                      (const unsigned char *)"0123456789012345",16);
    fprintf(stderr,"SPECK implementation benchmarking tool\n");
    SPECK_sign_verify_speed();
    return 0;
}
