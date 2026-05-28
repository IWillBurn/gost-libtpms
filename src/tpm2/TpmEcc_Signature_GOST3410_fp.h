#ifndef _TPMECC_SIGNATURE_GOST3410_FP_H_
#define _TPMECC_SIGNATURE_GOST3410_FP_H_

#if ALG_ECC && ALG_GOST3410

//*** TpmEcc_SignGost3410()
// This function implements the GOST3410 signing algorithm.
TPM_RC
TpmEcc_SignGost3410(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
                    Crypt_Int*            bnS,   // OUT: 's' component of the signature
                    const Crypt_EccCurve* E,     // IN: the curve used in the signature
                                                 //     process
                    Crypt_Int*          bnD,     // IN: private signing key
                    const TPM2B_DIGEST* digest,  // IN: the digest to sign
                    RAND_STATE*         rand     // IN: used in debug of signing
);

//*** TpmEcc_ValidateSignatureGost3410()
// This function validates a GOST3410 signature.
TPM_RC
TpmEcc_ValidateSignatureGost3410(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    const Crypt_Point*  ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_GOST3410
#endif  // _TPMECC_SIGNATURE_GOST3410_FP_H_
