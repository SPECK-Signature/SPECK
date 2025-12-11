/**
 *
 * Reference ISO-C11 Implementation of CROSS.
 *
 * @version 2.0 (February 2025)
 *
 * Authors listed in alphabetical order:
 * 
 * @author: Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author: Marco Gianvecchio <marco.gianvecchio@mail.polimi.it>
 * @author: Patrick Karl <patrick.karl@tum.de>
 * @author: Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author: Jonas Schupp <jonas.schupp@tum.de>
 * 
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

#pragma once

// %%%%%%%%%%%%%%%%%% Self-contained SHAKE x1 Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%

#include "fips202.h"
#include "parameters.h"
/* standalone FIPS-202 implementation has 
 * different states for SHAKE depending on security level*/
#define SHAKE_STATE_STRUCT shake128incctx

static inline
void xof_shake_init(SHAKE_STATE_STRUCT *state, int val)
{
   shake128_inc_init(state);
   /* avoid -Werror=unused-parameter */
   (void)val;
}

static inline
void xof_shake_update(SHAKE_STATE_STRUCT *state,
                      const unsigned char *input,
                      unsigned int inputByteLen)
{
   shake128_inc_absorb(state,
                       (const uint8_t *)input,
                       inputByteLen);
}

static inline
void xof_shake_final(SHAKE_STATE_STRUCT *state)
{
   shake128_inc_finalize(state);
}

static inline
void xof_shake_extract(SHAKE_STATE_STRUCT *state,
                       unsigned char *output,
                       unsigned int outputByteLen){
   shake128_inc_squeeze(output, outputByteLen, state);
}

// %%%%%%%%%%%%%%%%%% Self-contained SHAKE x4 Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%

#include "fips202x4.h"
#define SHAKE_X4_STATE_STRUCT par_keccak_context

static inline void xof_shake_x4_init(SHAKE_X4_STATE_STRUCT *states) {
   keccak_x4_init(states);
}
static inline void xof_shake_x4_update(SHAKE_X4_STATE_STRUCT *states,
                      const unsigned char *in1,
                      const unsigned char *in2,
                      const unsigned char *in3,
                      const unsigned char *in4,
                      uint32_t singleInputByteLen) {
   keccak_x4_absorb(states, in1, in2, in3, in4, singleInputByteLen);
}
static inline void xof_shake_x4_final(SHAKE_X4_STATE_STRUCT *states) {
   keccak_x4_finalize(states);
}
static inline void xof_shake_x4_extract(SHAKE_X4_STATE_STRUCT *states,
                       unsigned char *out1,
                       unsigned char *out2,
                       unsigned char *out3,
                       unsigned char *out4,
                       uint32_t singleOutputByteLen){
   keccak_x4_squeeze(states, out1, out2, out3, out4, singleOutputByteLen);
}

// %%%%%%%%%%%%%%%%%% Self-contained SHAKE x2 Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%

/* SHAKE_x2 just calls SHAKE_x1 twice. If a suitable SHAKE_x2 implementation becomes
 * available, it should be used instead */

typedef struct {
   SHAKE_STATE_STRUCT state1;
   SHAKE_STATE_STRUCT state2;
} shake_x2_ctx;
#define SHAKE_X2_STATE_STRUCT shake_x2_ctx
static inline void xof_shake_x2_init(SHAKE_X2_STATE_STRUCT *states, int val) {
   xof_shake_init(&(states->state1), val);
   xof_shake_init(&(states->state2), val);
}
static inline void xof_shake_x2_update(SHAKE_X2_STATE_STRUCT *states,
                      const unsigned char *in1,
                      const unsigned char *in2,
                      uint32_t singleInputByteLen) {
   xof_shake_update(&(states->state1), (const uint8_t *)in1, singleInputByteLen);
   xof_shake_update(&(states->state2), (const uint8_t *)in2, singleInputByteLen);
}
static inline void xof_shake_x2_final(SHAKE_X2_STATE_STRUCT *states) {
   xof_shake_final(&(states->state1));
   xof_shake_final(&(states->state2));
}
static inline void xof_shake_x2_extract(SHAKE_X2_STATE_STRUCT *states,
                       unsigned char *out1,
                       unsigned char *out2,
                       uint32_t singleOutputByteLen){
   xof_shake_extract(&(states->state1), out1, singleOutputByteLen);
   xof_shake_extract(&(states->state2), out2, singleOutputByteLen);
}

// %%%%%%%%%%%%%%%%%%%% Parallel SHAKE State Struct %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

typedef struct {
   SHAKE_STATE_STRUCT state1;
   SHAKE_X2_STATE_STRUCT state2;
   SHAKE_X4_STATE_STRUCT state4;
} par_shake_ctx;

// %%%%%%%%%%%%%%%%%%%% SHA METHODS %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#define LESS_SHA3_INC_CTX                     sha3_256incctx
#define LESS_SHA3_INC_INIT(state)             sha3_256_inc_init(state)
#define LESS_SHA3_INC_ABSORB(state, ptr, len) sha3_256_inc_absorb(state, ptr, len)
#define LESS_SHA3_INC_FINALIZE(output, state) sha3_256_inc_finalize(output, state)
