#ifndef _TPMECC_SIGNATURE_GOST3410_FP_H_
#define _TPMECC_SIGNATURE_GOST3410_FP_H_

#if ALG_ECC && ALG_GOST3410_256

//*** TpmEcc_SignGost3410256()
// This function implements the GOST3410_256 signing algorithm.
TPM_RC
TpmEcc_SignGost3410256(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
                 Crypt_Int*            bnS,   // OUT: 's' component of the signature
                 const Crypt_EccCurve* E,     // IN: the curve used in the signature
                                              //     process
                 Crypt_Int*          bnD,     // IN: private signing key
                 const TPM2B_DIGEST* digest,  // IN: the digest to sign
                 RAND_STATE*         rand     // IN: used in debug of signing
);

//*** TpmEcc_ValidateSignatureGost3410256()
// This function validates an GOST3410_256 signature.
TPM_RC
TpmEcc_ValidateSignatureGost3410256(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    const Crypt_Point*  ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_GOST3410_256

#if ALG_ECC && ALG_GOST3410_512

//*** TpmEcc_SignGost3410512()
// This function implements the GOST3410_512 signing algorithm.
TPM_RC
TpmEcc_SignGost3410512(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
                 Crypt_Int*            bnS,   // OUT: 's' component of the signature
                 const Crypt_EccCurve* E,     // IN: the curve used in the signature
                                              //     process
                 Crypt_Int*          bnD,     // IN: private signing key
                 const TPM2B_DIGEST* digest,  // IN: the digest to sign
                 RAND_STATE*         rand     // IN: used in debug of signing
);

//*** TpmEcc_ValidateSignatureGost3410512()
// This function validates an GOST3410_512 signature.
TPM_RC
TpmEcc_ValidateSignatureGost3410512(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    const Crypt_Point*  ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_GOST3410_512
#endif  // _TPMECC_SIGNATURE_GOST3410_FP_H_