#include "Tpm.h"
#include "TpmEcc_Signature_GOST3410_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"
#include "BnToOsslMath_fp.h"

#ifndef USE_OPENSSL_FUNCTIONS_GOST3410
#  define USE_OPENSSL_FUNCTIONS_GOST3410 0
#endif

#if ALG_ECC && (ALG_GOST3410_256 || ALG_GOST3410_512)

#if !USE_OPENSSL_FUNCTIONS_GOST3410
// =============================================================================
// Pure TPM math implementation (no gost-engine)
// =============================================================================

static void ReverseCopy(BYTE* dst, const BYTE* src, size_t n)
{
    size_t i;
    for(i = 0; i < n; i++)
        dst[i] = src[n - 1 - i];
}

/*
 * Implements gost-engine digest handling semantics:
 *   md = le2bn(dgst)
 *   e = md mod q
 *   if e == 0 => e = 1
 */
static Crypt_Int* TpmEcc_AdjustGost3410Digest(Crypt_Int*          bnE,
                                             const TPM2B_DIGEST* digest,
                                             const Crypt_Int*    order)
{
    int bitsInOrder = ExtMath_SizeInBits(order);

    if(digest == NULL || digest->t.size == 0)
    {
        ExtMath_SetWord(bnE, 0);
    }
    else
    {
        NUMBYTES n = (NUMBYTES)MIN(digest->t.size, BITS_TO_BYTES(bitsInOrder));
        BYTE     tmp[MAX_DIGEST_SIZE];

        ReverseCopy(tmp, digest->t.buffer, n);
        ExtMath_IntFromBytes(bnE, tmp, n);
    }

    // e = md mod q (in-place)
    ExtMath_Mod(bnE, order);

    // if e==0 => e=1
    if(ExtMath_IsZero(bnE))
        ExtMath_SetWord(bnE, 1);

    return bnE;
}

#endif // !USE_OPENSSL_FUNCTIONS_GOST3410

#endif // common

// =============================================================================
// 256-bit
// =============================================================================
#if ALG_ECC && ALG_GOST3410_256

#if !USE_OPENSSL_FUNCTIONS_GOST3410

TPM_RC
TpmEcc_SignGost3410256(Crypt_Int*            bnR,
                       Crypt_Int*            bnS,
                       const Crypt_EccCurve* E,
                       Crypt_Int*            bnD,
                       const TPM2B_DIGEST*   digest,
                       RAND_STATE*           rand)
{
    CRYPT_ECC_NUM(bnK);
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecC);
    CRYPT_ECC_NUM(bnX);
    CRYPT_ECC_NUM(bnTmp1);
    CRYPT_ECC_NUM(bnTmp2);

    const Crypt_Int* order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    INT32            tries = 10;

    pAssert(digest != NULL);

    // e = H mod q, little-endian interpretation; if 0 => 1
    TpmEcc_AdjustGost3410Digest(bnE, digest, order);

    for(;;)
    {
        BOOL ok = FALSE;

        // Find non-zero r with fresh ephemeral k
        for(; tries > 0; tries--)
        {
            // Generate ephemeral scalar k and point C = [k]G
            if(!TpmEcc_GenerateKeyPair(bnK, ecC, E, rand))
                continue;

            // r = x(C) mod q, r != 0
            ExtMath_Copy(bnX, ExtEcc_PointX(ecC));
            ExtMath_Mod(bnX, order);
            if(ExtMath_IsZero(bnX))
                continue;

            ExtMath_Copy(bnR, bnX);
            ok = TRUE;
            break;
        }
        if(!ok)
            return TPM_RC_FAILURE;

        // s = (r*d + k*e) mod q
        ExtMath_ModMult(bnTmp1, bnR, bnD, order);  // tmp1 = r*d mod q
        ExtMath_ModMult(bnTmp2, bnK, bnE, order);  // tmp2 = k*e mod q
        ExtMath_Add(bnS, bnTmp1, bnTmp2);          // s = tmp1 + tmp2
        ExtMath_Mod(bnS, order);                   // s mod q

        if(!ExtMath_IsZero(bnS))
            break;

        // if s==0 repeat with a new k (reset tries budget)
        tries = 10;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
TpmEcc_ValidateSignatureGost3410256(Crypt_Int*            bnR,
                                    Crypt_Int*            bnS,
                                    const Crypt_EccCurve* E,
                                    const Crypt_Point*    ecQ,
                                    const TPM2B_DIGEST*   digest)
{
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_ECC_NUM(bnV);
    CRYPT_ECC_NUM(bnZ1);
    CRYPT_ECC_NUM(bnZ2);
    CRYPT_ECC_NUM(bnTmp);
    CRYPT_POINT_VAR(ecC);
    CRYPT_ECC_NUM(bnX);
    CRYPT_ECC_NUM(bnRcalc);

    const Crypt_Int* order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    // Basic range checks: 0 < r,s < q
    if(ExtMath_IsZero(bnR) || ExtMath_IsZero(bnS))
        return TPM_RC_SIGNATURE;
    if(ExtMath_UnsignedCmp(bnR, order) >= 0 || ExtMath_UnsignedCmp(bnS, order) >= 0)
        return TPM_RC_SIGNATURE;

    // e = H mod q, little-endian interpretation; if 0 => 1
    TpmEcc_AdjustGost3410Digest(bnE, digest, order);

    // v = e^{-1} mod q
    if(!ExtMath_ModInverse(bnV, bnE, order))
        return TPM_RC_SIGNATURE;

    // z1 = s*v mod q
    ExtMath_ModMult(bnZ1, bnS, bnV, order);

    // z2 = (q - r)*v mod q
    ExtMath_Subtract(bnTmp, order, bnR);  // tmp = q - r
    ExtMath_ModMult(bnZ2, bnTmp, bnV, order);

    // C = z1*G + z2*Q
    if(TpmEcc_PointMult(ecC,
                        ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)),
                        bnZ1,
                        ecQ,
                        bnZ2,
                        E)
       != TPM_RC_SUCCESS)
        return TPM_RC_SIGNATURE;

    // R' = x(C) mod q
    ExtMath_Copy(bnX, ExtEcc_PointX(ecC));
    ExtMath_Copy(bnRcalc, bnX);
    ExtMath_Mod(bnRcalc, order);

    if(ExtMath_UnsignedCmp(bnRcalc, bnR) != 0)
        return TPM_RC_SIGNATURE;

    return TPM_RC_SUCCESS;
}

#else // USE_OPENSSL_FUNCTIONS_GOST3410
// =============================================================================
// gost-engine implementation
// =============================================================================
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <gost-engine/gost_lcl.h>

static int TpmEcc_GostCurveNidFromCurve(const Crypt_EccCurve* E)
{
    // Prefer curve name if present
    int nid = EC_GROUP_get_curve_name(E->G);
    if(nid != NID_undef)
        return nid;

    // Otherwise map from TPM curveId
    switch(ExtEcc_CurveGetCurveId(E))
    {
#ifdef TPM_ECC_TC26_GOST3410_256_PARAM_SET_A
    case TPM_ECC_TC26_GOST3410_256_PARAM_SET_A:
        return NID_id_tc26_gost_3410_2012_256_paramSetA;
#endif
#ifdef TPM_ECC_TC26_GOST3410_512_PARAM_SET_A
    case TPM_ECC_TC26_GOST3410_512_PARAM_SET_A:
        return NID_id_tc26_gost_3410_2012_512_paramSetA;
#endif
    default:
        return NID_undef;
    }
}

TPM_RC
TpmEcc_SignGost3410256(Crypt_Int*            bnR,
                       Crypt_Int*            bnS,
                       const Crypt_EccCurve* E,
                       Crypt_Int*            bnD,
                       const TPM2B_DIGEST*   digest,
                       RAND_STATE*           rand LIBTPMS_ATTR_UNUSED)
{
    TPM_RC       retVal = TPM_RC_FAILURE;
    EC_KEY*      eckey  = NULL;
    ECDSA_SIG*   sig    = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    BIGNUM*      d      = BN_new();
    int          nid;

    if(!d)
        return TPM_RC_MEMORY;

    d = BigInitialized(d, (bigConst)bnD);
    eckey = EC_KEY_new();
    if(d == NULL || eckey == NULL)
        goto Exit;

    nid = TpmEcc_GostCurveNidFromCurve(E);
    if(nid == NID_undef)
        goto Exit;

    if(fill_GOST_EC_params(eckey, nid) != 1)
        goto Exit;

    if(EC_KEY_set_private_key(eckey, d) != 1)
        goto Exit;

    sig = gost_ec_sign(digest->b.buffer, digest->b.size, eckey);
    if(sig == NULL)
        goto Exit;

    ECDSA_SIG_get0(sig, &r, &s);
    if(r == NULL || s == NULL)
        goto Exit;

    OsslToTpmBn((bigNum)bnR, r);
    OsslToTpmBn((bigNum)bnS, s);

    retVal = TPM_RC_SUCCESS;

Exit:
    BN_clear_free(d);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    return retVal;
}

TPM_RC
TpmEcc_ValidateSignatureGost3410256(Crypt_Int*            bnR,
                                    Crypt_Int*            bnS,
                                    const Crypt_EccCurve* E,
                                    const Crypt_Point*    ecQ,
                                    const TPM2B_DIGEST*   digest)
{
    TPM_RC     retVal = TPM_RC_FAILURE;
    int        rc;
    ECDSA_SIG* sig  = NULL;
    EC_KEY*    eckey = NULL;
    BIGNUM*    r = BN_new();
    BIGNUM*    s = BN_new();
    EC_POINT*  q = NULL;
    int        nid;

    if(!r || !s)
        goto Exit;

    r = BigInitialized(r, (bigConst)bnR);
    s = BigInitialized(s, (bigConst)bnS);
    q = EcPointInitialized((bn_point_t*)ecQ, E);

    sig  = ECDSA_SIG_new();
    eckey = EC_KEY_new();

    if(r == NULL || s == NULL || q == NULL || sig == NULL || eckey == NULL)
        goto Exit;

    nid = TpmEcc_GostCurveNidFromCurve(E);
    if(nid == NID_undef)
        goto Exit;

    if(fill_GOST_EC_params(eckey, nid) != 1)
        goto Exit;

    if(EC_KEY_set_public_key(eckey, q) != 1)
        goto Exit;

    if(ECDSA_SIG_set0(sig, r, s) != 1)
        goto Exit;

    // sig now owns r and s
    r = NULL;
    s = NULL;

    rc = gost_ec_verify(digest->b.buffer, digest->b.size, sig, eckey);
    if(rc == 1)
        retVal = TPM_RC_SUCCESS;
    else
        retVal = TPM_RC_SIGNATURE;

Exit:
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    EC_POINT_clear_free(q);
    BN_clear_free(r);
    BN_clear_free(s);
    return retVal;
}

#endif // !USE_OPENSSL_FUNCTIONS_GOST3410

#endif // ALG_ECC && ALG_GOST3410_256

// =============================================================================
// 512-bit
// =============================================================================
#if ALG_ECC && ALG_GOST3410_512

#if !USE_OPENSSL_FUNCTIONS_GOST3410

TPM_RC
TpmEcc_SignGost3410512(Crypt_Int*            bnR,
                       Crypt_Int*            bnS,
                       const Crypt_EccCurve* E,
                       Crypt_Int*            bnD,
                       const TPM2B_DIGEST*   digest,
                       RAND_STATE*           rand)
{
    CRYPT_ECC_NUM(bnK);
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecC);
    CRYPT_ECC_NUM(bnX);
    CRYPT_ECC_NUM(bnTmp1);
    CRYPT_ECC_NUM(bnTmp2);

    const Crypt_Int* order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    INT32            tries = 10;

    pAssert(digest != NULL);

    TpmEcc_AdjustGost3410Digest(bnE, digest, order);

    for(;;)
    {
        BOOL ok = FALSE;

        for(; tries > 0; tries--)
        {
            if(!TpmEcc_GenerateKeyPair(bnK, ecC, E, rand))
                continue;

            ExtMath_Copy(bnX, ExtEcc_PointX(ecC));
            ExtMath_Mod(bnX, order);
            if(ExtMath_IsZero(bnX))
                continue;

            ExtMath_Copy(bnR, bnX);
            ok = TRUE;
            break;
        }
        if(!ok)
            return TPM_RC_FAILURE;

        ExtMath_ModMult(bnTmp1, bnR, bnD, order);
        ExtMath_ModMult(bnTmp2, bnK, bnE, order);
        ExtMath_Add(bnS, bnTmp1, bnTmp2);
        ExtMath_Mod(bnS, order);

        if(!ExtMath_IsZero(bnS))
            break;

        tries = 10;
    }

    return TPM_RC_SUCCESS;
}

TPM_RC
TpmEcc_ValidateSignatureGost3410512(Crypt_Int*            bnR,
                                    Crypt_Int*            bnS,
                                    const Crypt_EccCurve* E,
                                    const Crypt_Point*    ecQ,
                                    const TPM2B_DIGEST*   digest)
{
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_ECC_NUM(bnV);
    CRYPT_ECC_NUM(bnZ1);
    CRYPT_ECC_NUM(bnZ2);
    CRYPT_ECC_NUM(bnTmp);
    CRYPT_POINT_VAR(ecC);
    CRYPT_ECC_NUM(bnX);
    CRYPT_ECC_NUM(bnRcalc);

    const Crypt_Int* order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    if(ExtMath_IsZero(bnR) || ExtMath_IsZero(bnS))
        return TPM_RC_SIGNATURE;
    if(ExtMath_UnsignedCmp(bnR, order) >= 0 || ExtMath_UnsignedCmp(bnS, order) >= 0)
        return TPM_RC_SIGNATURE;

    TpmEcc_AdjustGost3410Digest(bnE, digest, order);

    if(!ExtMath_ModInverse(bnV, bnE, order))
        return TPM_RC_SIGNATURE;

    ExtMath_ModMult(bnZ1, bnS, bnV, order);

    ExtMath_Subtract(bnTmp, order, bnR);
    ExtMath_ModMult(bnZ2, bnTmp, bnV, order);

    if(TpmEcc_PointMult(ecC,
                        ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)),
                        bnZ1,
                        ecQ,
                        bnZ2,
                        E)
       != TPM_RC_SUCCESS)
        return TPM_RC_SIGNATURE;

    ExtMath_Copy(bnX, ExtEcc_PointX(ecC));
    ExtMath_Copy(bnRcalc, bnX);
    ExtMath_Mod(bnRcalc, order);

    if(ExtMath_UnsignedCmp(bnRcalc, bnR) != 0)
        return TPM_RC_SIGNATURE;

    return TPM_RC_SUCCESS;
}

#else // USE_OPENSSL_FUNCTIONS_GOST3410
// =============================================================================
// gost-engine implementation
// =============================================================================
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <gost-engine/gost_lcl.h>

static int TpmEcc_GostCurveNidFromCurve(const Crypt_EccCurve* E);

TPM_RC
TpmEcc_SignGost3410512(Crypt_Int*            bnR,
                       Crypt_Int*            bnS,
                       const Crypt_EccCurve* E,
                       Crypt_Int*            bnD,
                       const TPM2B_DIGEST*   digest,
                       RAND_STATE*           rand LIBTPMS_ATTR_UNUSED)
{
    TPM_RC       retVal = TPM_RC_FAILURE;
    EC_KEY*      eckey  = NULL;
    ECDSA_SIG*   sig    = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    BIGNUM*      d      = BN_new();
    int          nid;

    if(!d)
        return TPM_RC_MEMORY;

    d = BigInitialized(d, (bigConst)bnD);
    eckey = EC_KEY_new();
    if(d == NULL || eckey == NULL)
        goto Exit;

    nid = TpmEcc_GostCurveNidFromCurve(E);
    if(nid == NID_undef)
        goto Exit;

    if(fill_GOST_EC_params(eckey, nid) != 1)
        goto Exit;

    if(EC_KEY_set_private_key(eckey, d) != 1)
        goto Exit;

    sig = gost_ec_sign(digest->b.buffer, digest->b.size, eckey);
    if(sig == NULL)
        goto Exit;

    ECDSA_SIG_get0(sig, &r, &s);
    if(r == NULL || s == NULL)
        goto Exit;

    OsslToTpmBn((bigNum)bnR, r);
    OsslToTpmBn((bigNum)bnS, s);

    retVal = TPM_RC_SUCCESS;

Exit:
    BN_clear_free(d);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    return retVal;
}

TPM_RC
TpmEcc_ValidateSignatureGost3410512(Crypt_Int*            bnR,
                                    Crypt_Int*            bnS,
                                    const Crypt_EccCurve* E,
                                    const Crypt_Point*    ecQ,
                                    const TPM2B_DIGEST*   digest)
{
    TPM_RC     retVal = TPM_RC_FAILURE;
    int        rc;
    ECDSA_SIG* sig  = NULL;
    EC_KEY*    eckey = NULL;
    BIGNUM*    r = BN_new();
    BIGNUM*    s = BN_new();
    EC_POINT*  q = NULL;
    int        nid;

    if(!r || !s)
        goto Exit;

    r = BigInitialized(r, (bigConst)bnR);
    s = BigInitialized(s, (bigConst)bnS);
    q = EcPointInitialized((bn_point_t*)ecQ, E);

    sig  = ECDSA_SIG_new();
    eckey = EC_KEY_new();

    if(r == NULL || s == NULL || q == NULL || sig == NULL || eckey == NULL)
        goto Exit;

    nid = TpmEcc_GostCurveNidFromCurve(E);
    if(nid == NID_undef)
        goto Exit;

    if(fill_GOST_EC_params(eckey, nid) != 1)
        goto Exit;

    if(EC_KEY_set_public_key(eckey, q) != 1)
        goto Exit;

    if(ECDSA_SIG_set0(sig, r, s) != 1)
        goto Exit;

    r = NULL;
    s = NULL;

    rc = gost_ec_verify(digest->b.buffer, digest->b.size, sig, eckey);
    if(rc == 1)
        retVal = TPM_RC_SUCCESS;
    else
        retVal = TPM_RC_SIGNATURE;

Exit:
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    EC_POINT_clear_free(q);
    BN_clear_free(r);
    BN_clear_free(s);
    return retVal;
}

#endif // !USE_OPENSSL_FUNCTIONS_GOST3410

#endif // ALG_ECC && ALG_GOST3410_512