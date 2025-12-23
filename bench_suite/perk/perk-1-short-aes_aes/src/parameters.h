
/**
 * @file parameters.h
 * @brief Parameters of the PERK scheme
 */

#ifndef SIG_PERK_PARAMETER_H
#define SIG_PERK_PARAMETER_H

#include "config.h"

#define PERK_ALGNAME         PERK_CONFIG_ALGNAME
#define PERK_SECURITY_BYTES  PERK_CONFIG_SECURITY_BYTES
#define PERK_SECURITY_BITS   (8 * PERK_SECURITY_BYTES)
#define PERK_TOWER_FIELD_EXT PERK_CONFIG_TOWER_FIELD_EXT
#define PERK_PARAM_TAU1      PERK_CONFIG_PARAM_TAU1
#define PERK_PARAM_TAU2      PERK_CONFIG_PARAM_TAU2
#define PERK_PARAM_N         PERK_CONFIG_PARAM_N
#define PERK_PARAM_M         PERK_CONFIG_PARAM_M
#define PERK_PARAM_KAPPA1    PERK_CONFIG_PARAM_KAPPA1
#define PERK_PARAM_KAPPA2    PERK_CONFIG_PARAM_KAPPA2
#define PERK_PARAM_MU1       PERK_CONFIG_PARAM_MU1
#define PERK_PARAM_MU2       PERK_CONFIG_PARAM_MU2
#define PERK_PARAM_TAU_PRIME PERK_CONFIG_PARAM_TAU_PRIME
#define PERK_PARAM_C         PERK_CONFIG_PARAM_C
#define PERK_PARAM_W         PERK_CONFIG_PARAM_W  // proof of work bits
#define PERK_PARAM_T_OPEN    PERK_CONFIG_PARAM_T_OPEN
#define PERK_PARAM_D         PERK_CONFIG_SHARE_DEGREE

#define PERK_PARAM_TAU   (PERK_PARAM_TAU1 + PERK_PARAM_TAU2)
#define PERK_PARAM_Q     11
#define PERK_PARAM_BASIS 4
#define PERK_PARAM_L_ROW (PERK_PARAM_D + 6)

#define PERK_PARAM_MAX_OPEN_RETRIES 0xFFFFFFFFFFFFFFFF

#define PERK_PARAM_RHO (PERK_PARAM_Q * PERK_TOWER_FIELD_EXT)
#if (PERK_PARAM_RHO != \
     ((PERK_PARAM_MU1 * PERK_PARAM_TAU_PRIME) + (PERK_PARAM_MU2 * (PERK_PARAM_TAU - PERK_PARAM_TAU_PRIME))))
#error "TOWER_FIELD_DEG must be equal to ((μ1 * τ') + (μ2 * (τ - τ')))"
#endif

#define PERK_PARAM_B       16
#define PERK_PARAM_L       (PERK_PARAM_N * PERK_PARAM_L_ROW)
#define PERK_PARAM_L_BAR   ((PERK_PARAM_D - 1) * PERK_PARAM_RHO)
#define PERK_PARAM_L_VHM   (PERK_SECURITY_BITS + PERK_PARAM_B)  // Vole hash mask
#define PERK_PARAM_L_PRIME (PERK_PARAM_L + PERK_PARAM_L_VHM)
#define PERK_PARAM_L_HAT   (PERK_PARAM_L_BAR + PERK_PARAM_L_PRIME)

#define PERK_SEED_BYTES       PERK_SECURITY_BYTES          /**< Seed size used in the scheme */
#define PERK_SALT_BYTES       (2 * PERK_SECURITY_BYTES)    /**< Salt size used in the scheme */
#define PERK_HASH_BYTES       (2 * PERK_SECURITY_BYTES)    /**< Hash size used in the scheme */
#define PERK_COMMITMENT_BYTES PERK_HASH_BYTES              /**< Commitment size used in the scheme */
#define PERK_VOLE_DATA_BYTES  ((PERK_PARAM_L_HAT + 7) / 8) /**< Bytes size of VOLE data used in the scheme */
#define PERK_VOLE_HASH_BYTES  PERK_SECURITY_BYTES + (PERK_PARAM_B / 8) /**< Bytes size of output of VOLEHash */
#define PERK_CHALL_3_BITS                                                        \
    (PERK_PARAM_KAPPA1 * PERK_PARAM_TAU1 + PERK_PARAM_KAPPA2 * PERK_PARAM_TAU2 + \
     PERK_PARAM_W)                                       /**< Bit size of challenge 3 */
#define PERK_CHALL_3_BYTES ((PERK_CHALL_3_BITS + 7) / 8) /**< Bytes size of challenge 3 */

#define PERK_PUBLIC_KEY_BYTES  (PERK_SEED_BYTES + ((PERK_PARAM_Q * PERK_PARAM_N + 7) / 8))
#define PERK_PRIVATE_KEY_BYTES (PERK_SEED_BYTES + PERK_PUBLIC_KEY_BYTES)

#define PERK_SIGNATURE_BITS                                                                                          \
    ((PERK_VOLE_DATA_BYTES * (PERK_PARAM_TAU - 1) + (PERK_VOLE_HASH_BYTES) + (PERK_SEED_BYTES * PERK_PARAM_T_OPEN) + \
      (PERK_COMMITMENT_BYTES * PERK_PARAM_TAU) + 8 + (PERK_SALT_BYTES)) *                                            \
         8 +                                                                                                         \
     ((11 * PERK_TOWER_FIELD_EXT * (PERK_PARAM_D)) + ((PERK_PARAM_L_ROW) * PERK_PARAM_N) +                           \
      (PERK_CHALL_3_BITS - PERK_PARAM_W)))
#define PERK_SIGNATURE_BYTES ((PERK_SIGNATURE_BITS + 7) / 8)

#define PERK_FAILURE 1 /**< Exit code in case of failure */
#define PERK_SUCCESS 0 /**< Exit code in case of success */

// domains for hash and prg
#define H0_0   0x00
#define H0_1   0x10
#define H0_2   0x20
#define H1     0x01
#define H2_1   0x12
#define H2_2   0x22
#define H2_3   0x32
#define H3     0x03
#define H4     0x04
#define PRG1   0x05
#define PRG2   0x06
#define Com1   0x07
#define Com2_0 0x08
#define Com2_1 0x18

#endif  // SIG_PERK_PARAMETER_H
