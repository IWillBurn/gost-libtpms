#ifndef TPMTOGOSTSUPPORT_FP_H
#define TPMTOGOSTSUPPORT_FP_H

#include <gost-engine/gost89.h>
#include <gost-engine/gost_grasshopper_core.h>

// [GOST-PATCH] fix incorrect definition of static functions in gost_grasshopper_core.h
// https://github.com/gost-engine/engine/issues/488
inline void grasshopper_l(grasshopper_w128_t* w) { }
inline void grasshopper_l_inv(grasshopper_w128_t* w) { }
//

void Magma_set_encrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    gost_ctx *keySchedule
);

void Magma_set_decrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    gost_ctx *keySchedule
);

void Magma_encrypt(
    const BYTE *in,
    BYTE *out,
    gost_ctx *ks
);

void Magma_decrypt(
    const BYTE *in,
    BYTE *out,
    gost_ctx *ks
);

void Grasshopper_set_encrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    grasshopper_round_keys_t *keySchedule
);

void Grasshopper_set_decrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    grasshopper_round_keys_t *keySchedule
);

void Grasshopper_encrypt(
    const BYTE *in,
    BYTE *out,
    grasshopper_round_keys_t *ks
);

void Grasshopper_decrypt(
    const BYTE *in,
    BYTE *out,
    grasshopper_round_keys_t *ks
);

#if USE_OPENSSL_FUNCTIONS_RSA
const EVP_CIPHER *magma_ctr_evp(void);
const EVP_CIPHER *magma_cbc_evp(void);
const EVP_CIPHER *magma_ecb_evp(void);
const EVP_CIPHER *grasshopper_ctr_evp(void);
const EVP_CIPHER *grasshopper_ofb_evp(void);
const EVP_CIPHER *grasshopper_cbc_evp(void);
const EVP_CIPHER *grasshopper_cfb_evp(void);
const EVP_CIPHER *grasshopper_ecb_evp(void);
#endif

#endif /* TPMTOGOSTSUPPORT_FP_H */