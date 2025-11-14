#include "Tpm.h"
#include <gost-engine/gost_grasshopper_core.h>
#include <gost-engine/gost89.h>

void Magma_set_encrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    gost_ctx *keySchedule)
{
    magma_key(keySchedule, key);
}

void Magma_set_decrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    gost_ctx *keySchedule)
{
    magma_key(keySchedule, key);
}

void Magma_encrypt(
    const BYTE *in,
    BYTE *out,
    gost_ctx *ks)
{
    magmacrypt(ks, in, out);
}

void Magma_decrypt(
    const BYTE *in,
    BYTE *out,
    gost_ctx *ks)
{
    magmadecrypt(ks, in, out);
}

void Grasshopper_set_encrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    grasshopper_round_keys_t *keySchedule)
{
    grasshopper_key_t grasshopper_key;
    memcpy(grasshopper_key.k.b, key, keySizeInBits / 8);
    grasshopper_set_encrypt_key(keySchedule, &grasshopper_key);
}

void Grasshopper_set_decrypt_key(
    const BYTE *key,
    UINT16 keySizeInBits,
    grasshopper_round_keys_t *keySchedule)
{
    grasshopper_key_t grasshopper_key;
    memcpy(grasshopper_key.k.b, key, keySizeInBits / 8);
    grasshopper_set_decrypt_key(keySchedule, &grasshopper_key);
}

void Grasshopper_encrypt(
    const BYTE *in,
    BYTE *out,
    grasshopper_round_keys_t *ks)
{
    grasshopper_w128_t source, target, buffer;
    
    memcpy(source.b, in, 16);
    grasshopper_encrypt_block(ks, &source, &target, &buffer);
    memcpy(out, target.b, 16);
}

void Grasshopper_decrypt(
    const BYTE *in,
    BYTE *out,
    grasshopper_round_keys_t *ks)
{
    grasshopper_w128_t source, target, buffer;
    
    memcpy(source.b, in, 16);
    grasshopper_decrypt_block(ks, &source, &target, &buffer);
    memcpy(out, target.b, 16);
}

#if USE_OPENSSL_FUNCTIONS_RSA
#include <gost-engine/gost_lcl.h>

const EVP_CIPHER *magma_ctr_evp(void) {
    return GOST_init_cipher(&magma_ctr_cipher);
}

const EVP_CIPHER *magma_cbc_evp(void) {
    return GOST_init_cipher(&magma_cbc_cipher);
}

const EVP_CIPHER *magma_ecb_evp(void) {
    return GOST_init_cipher(&magma_ecb_cipher);
}

const EVP_CIPHER *grasshopper_ctr_evp(void) {
    return GOST_init_cipher(&grasshopper_ctr_cipher);
}

const EVP_CIPHER *grasshopper_ofb_evp(void) {
    return GOST_init_cipher(&grasshopper_ofb_cipher);
}

const EVP_CIPHER *grasshopper_cbc_evp(void) {
    return GOST_init_cipher(&grasshopper_cbc_cipher);
}

const EVP_CIPHER *grasshopper_cfb_evp(void) {
    return GOST_init_cipher(&grasshopper_cfb_cipher);
}

const EVP_CIPHER *grasshopper_ecb_evp(void) {
    return GOST_init_cipher(&grasshopper_ecb_cipher);
}
#endif