#ifndef SIG_PERK_CONFIG_H
#define SIG_PERK_CONFIG_H

#define PERK_CONFIG_ALGNAME         "perk-1-short"
#define PERK_CONFIG_SECURITY_BYTES  16
#define PERK_CONFIG_TOWER_FIELD_EXT 12
#define PERK_CONFIG_PARAM_N         64
#define PERK_CONFIG_PARAM_M         27
#define PERK_CONFIG_PARAM_TAU1      11
#define PERK_CONFIG_PARAM_KAPPA1    11
#define PERK_CONFIG_PARAM_TAU2      0
#define PERK_CONFIG_PARAM_KAPPA2    0
#define PERK_CONFIG_PARAM_MU1       12
#define PERK_CONFIG_PARAM_MU2       0
#define PERK_CONFIG_PARAM_TAU_PRIME 11
#define PERK_CONFIG_SHARE_DEGREE    3
#define PERK_CONFIG_PARAM_C         6
#define PERK_CONFIG_PARAM_W         9
#define PERK_CONFIG_PARAM_T_OPEN    106

#define PERK_USE_AVX2 1

#define xkcp4x                1
#define xkcp1x                2
#define FINAL_COMMITMENT_MODE xkcp4x

#define xkcp 1
#define aes  2
#define PRG_LEAF_COMMIT_IMPL xkcp
#define PRG_EXPAND_SEED_IMPL aes

#define PERK_CONFIG_PARAM_SEC_LEVEL 1
#endif  // SIG_PERK_CONFIG_H
