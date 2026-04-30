use bitflags::bitflags;

use pkcs11_macros::{
    AttributePodType, TryFromCkAttribute, pkcs11_mechanism_type, pkcs11_type,
};

use crate::error::{Error, Result};

use super::{CkPodType, ObjectHandle, TryFromCkAttribute, general::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorDefinedMechanism<'a> {
    pub mechanism_type: MechanismType,
    pub param: Option<&'a [u8]>,
}

// TODO: add missing mechanisms/params
pkcs11_mechanism_type!(
    /// Specifies a particular mechanism and any parameters it requires.
    #[non_exhaustive]
    Mechanism, naming = UpperCamelCase;
    [
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_RSA_9796,
        CKM_RSA_X_509,

        CKM_MD2_RSA_PKCS,
        CKM_MD5_RSA_PKCS,
        CKM_SHA1_RSA_PKCS,

        CKM_RIPEMD128_RSA_PKCS,
        CKM_RIPEMD160_RSA_PKCS,
        // CKM_RSA_PKCS_OAEP,  // CK_RSA_PKCS_OAEP_PARAMS_T

        CKM_RSA_X9_31_KEY_PAIR_GEN,
        CKM_RSA_X9_31,
        CKM_SHA1_RSA_X9_31,
        CKM_RSA_PKCS_PSS: RsaPkcsPssParams,
        CKM_SHA1_RSA_PKCS_PSS: RsaPkcsPssParams,

        CKM_DSA_KEY_PAIR_GEN,
        CKM_DSA,
        CKM_DSA_SHA1,
        CKM_DSA_SHA224,
        CKM_DSA_SHA256,
        CKM_DSA_SHA384,
        CKM_DSA_SHA512,
        // CKM_DSA_SHA3_224,  // UNDEFINED_T
        // CKM_DSA_SHA3_256,  // UNDEFINED_T
        // CKM_DSA_SHA3_384,  // UNDEFINED_T
        // CKM_DSA_SHA3_512,  // UNDEFINED_T

        CKM_DH_PKCS_KEY_PAIR_GEN,
        /// This is a mechanism for key derivation based on Diffie-Hellman
        /// key agreement, as defined in PKCS #3.
        /// This is what PKCS #3 calls "phase II".
        ///
        /// It has a parameter, which is the public value of the other party
        /// in the key agreement protocol, represented as a Cryptoki "Big integer"
        /// (i.e., a sequence of bytes, most-significant byte first).
        CKM_DH_PKCS_DERIVE: Vec<u8>,  // BIG_INTEGER_T

        CKM_X9_42_DH_KEY_PAIR_GEN,
        CKM_X9_42_DH_DERIVE: X9_42Dh1DeriveParams<'a>,  // CK_X9_42_DH1_DERIVE_PARAMS_T
        // CKM_X9_42_DH_HYBRID_DERIVE,  // CK_X9_42_DH2_DERIVE_PARAMS_T
        // CKM_X9_42_MQV_DERIVE,  // CK_X9_42_MQV_DERIVE_PARAMS_T

        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS: RsaPkcsPssParams,
        CKM_SHA384_RSA_PKCS_PSS: RsaPkcsPssParams,
        CKM_SHA512_RSA_PKCS_PSS: RsaPkcsPssParams,

        CKM_SHA224_RSA_PKCS,
        CKM_SHA224_RSA_PKCS_PSS: RsaPkcsPssParams,

        CKM_SHA512_224,
        CKM_SHA512_224_HMAC,
        CKM_SHA512_224_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        // CKM_SHA512_224_KEY_DERIVATION,  // UNDEFINED_T
        CKM_SHA512_256,  // CK_MAC_GENERAL_PARAMS
        CKM_SHA512_256_HMAC,  // CK_MAC_GENERAL_PARAMS
        CKM_SHA512_256_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        // CKM_SHA512_256_KEY_DERIVATION,  // UNDEFINED_T

        CKM_SHA512_T: Ulong,
        CKM_SHA512_T_HMAC: Ulong,
        CKM_SHA512_T_HMAC_GENERAL: Ulong,
        // CKM_SHA512_T_KEY_DERIVATION,

        // CKM_SHA3_256_RSA_PKCS,  // UNDEFINED_T
        // CKM_SHA3_384_RSA_PKCS,  // UNDEFINED_T
        // CKM_SHA3_512_RSA_PKCS,  // UNDEFINED_T
        // CKM_SHA3_256_RSA_PKCS_PSS, // UNDEFINED_T
        // CKM_SHA3_384_RSA_PKCS_PSS, // UNDEFINED_T
        // CKM_SHA3_512_RSA_PKCS_PSS, // UNDEFINED_T
        // CKM_SHA3_224_RSA_PKCS,  // UNDEFINED_T
        // CKM_SHA3_224_RSA_PKCS_PSS,  // UNDEFINED_T

        // /// Historical
        // CKM_RC2_KEY_GEN,
        /// Historical
        CKM_RC2_ECB: Ulong,  // CK_RC2_PARAMS
        // /// Historical
        // CKM_RC2_CBC,  // CK_RC2_CBC_PARAMS_T
        /// Historical
        CKM_RC2_MAC: Ulong,  // CK_RC2_PARAMS

        // /// Historical
        // CKM_RC2_MAC_GENERAL,  // CK_RC2_MAC_GENERAL_PARAMS_T
        // /// Historical
        // CKM_RC2_CBC_PAD,  // CK_RC2_CBC_PARAMS_T

        /// Historical
        CKM_RC4_KEY_GEN,
        /// Historical
        CKM_RC4,
        /// Historical
        CKM_DES_KEY_GEN,
        /// Historical
        CKM_DES_ECB,
        /// Historical
        ///
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_CBC: [u8; 8],
        /// Historical
        CKM_DES_MAC,

        /// Historical
        CKM_DES_MAC_GENERAL: Ulong,
        /// Historical
        ///
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_CBC_PAD: [u8; 8],

        CKM_DES2_KEY_GEN,
        CKM_DES3_KEY_GEN,
        CKM_DES3_ECB,
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES3_CBC: [u8; 8],
        CKM_DES3_MAC,
        CKM_DES3_MAC_GENERAL: Ulong,
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES3_CBC_PAD: [u8; 8],
        CKM_DES3_CMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_DES3_CMAC,
        // /// Historical
        // CKM_CDMF_KEY_GEN,  // UNDEFINED_T
        // /// Historical
        // CKM_CDMF_ECB,  // UNDEFINED_T
        // /// Historical
        // CKM_CDMF_CBC,  // UNDEFINED_T
        // /// Historical
        // CKM_CDMF_MAC,  // UNDEFINED_T
        // /// Historical
        // CKM_CDMF_MAC_GENERAL,  // UNDEFINED_T
        // /// Historical
        // CKM_CDMF_CBC_PAD,  // UNDEFINED_T

        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_OFB64: [u8; 8],
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_OFB8: [u8; 8],
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_CFB64: [u8; 8],
        /// It has a parameter, an initialization vector for this mode.
        CKM_DES_CFB8: [u8; 8],

        /// Historical
        CKM_MD2,

        /// Historical
        CKM_MD2_HMAC,
        /// Historical
        CKM_MD2_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS

        /// Historical
        CKM_MD5,

        /// Historical
        CKM_MD5_HMAC,
        /// Historical
        CKM_MD5_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS

        CKM_SHA_1,

        CKM_SHA_1_HMAC,
        CKM_SHA_1_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS

        /// Historical
        CKM_RIPEMD128,
        /// Historical
        CKM_RIPEMD128_HMAC,
        /// Historical
        CKM_RIPEMD128_HMAC_GENERAL: Ulong,
        /// Historical
        CKM_RIPEMD160,
        /// Historical
        CKM_RIPEMD160_HMAC,
        /// Historical
        CKM_RIPEMD160_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS

        CKM_SHA256,
        CKM_SHA256_HMAC,
        CKM_SHA256_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_SHA224,
        CKM_SHA224_HMAC,
        CKM_SHA224_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_SHA384,
        CKM_SHA384_HMAC,
        CKM_SHA384_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_SHA512,
        CKM_SHA512_HMAC,
        CKM_SHA512_HMAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_SECURID_KEY_GEN,
        // CKM_SECURID,  // CK_OTP_PARAMS_T
        CKM_HOTP_KEY_GEN,
        // CKM_HOTP,  // CK_OTP_PARAMS_T
        // CKM_ACTI,  // CK_OTP_PARAMS_T
        CKM_ACTI_KEY_GEN,

        // CKM_SHA3_256,  // UNDEFINED_T
        // CKM_SHA3_256_HMAC,  // UNDEFINED_T
        // CKM_SHA3_256_HMAC_GENERAL,  // UNDEFINED_T
        // CKM_SHA3_256_KEY_GEN,  // UNDEFINED_T
        // CKM_SHA3_224,  // UNDEFINED_T
        // CKM_SHA3_224_HMAC,  // UNDEFINED_T
        // CKM_SHA3_224_HMAC_GENERAL,  // UNDEFINED_T
        // CKM_SHA3_224_KEY_GEN,  // UNDEFINED_T
        // CKM_SHA3_384,  // UNDEFINED_T
        // CKM_SHA3_384_HMAC,  // UNDEFINED_T
        // CKM_SHA3_384_HMAC_GENERAL,  // UNDEFINED_T
        // CKM_SHA3_384_KEY_GEN,  // UNDEFINED_T
        // CKM_SHA3_512,  // UNDEFINED_T
        // CKM_SHA3_512_HMAC,  // UNDEFINED_T
        // CKM_SHA3_512_HMAC_GENERAL,  // UNDEFINED_T
        // CKM_SHA3_512_KEY_GEN,  // UNDEFINED_T

        // /// Historical
        // CKM_CAST_KEY_GEN,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST_ECB,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST_CBC,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST_MAC,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST_MAC_GENERAL,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST_CBC_PAD,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_KEY_GEN,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_ECB,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_CBC,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_MAC,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_MAC_GENERAL,  // UNDEFINED_T
        // /// Historical
        // CKM_CAST3_CBC_PAD,  // UNDEFINED_T

        // Note that CAST128 and CAST5 are the same algorithm */

        // /// Historical
        // CKM_CAST128_KEY_GEN,
        // /// Historical
        // CKM_CAST128_ECB,
        // /// Historical
        // CKM_CAST128_CBC,
        // /// Historical
        // CKM_CAST128_MAC,
        // /// Historical
        // CKM_CAST128_MAC_GENERAL,
        // /// Historical
        // CKM_CAST128_CBC_PAD,
        /// Historical
        CKM_RC5_KEY_GEN,
        // /// Historical
        // CKM_RC5_ECB,  // CK_RC5_PARAMS_T
        // /// Historical
        // CKM_RC5_CBC,  // CK_RC5_CBC_PARAMS_T
        // /// Historical
        // CKM_RC5_MAC,  // CK_RC5_PARAMS_T
        // /// Historical
        // CKM_RC5_MAC_GENERAL,  // CK_RC5_MAC_GENERAL_PARAMS_T
        // /// Historical
        // CKM_RC5_CBC_PAD,  // CK_RC5_CBC_PARAMS_T
        // /// Historical
        // CKM_IDEA_KEY_GEN,  // UNDEFINED_T
        // /// Historical
        // CKM_IDEA_ECB,  // UNDEFINED_T
        // /// Historical
        // CKM_IDEA_CBC,  // UNDEFINED_T
        // /// Historical
        // CKM_IDEA_MAC,  // UNDEFINED_T
        // /// Historical
        // CKM_IDEA_MAC_GENERAL,  // UNDEFINED_T
        // /// Historical
        // CKM_IDEA_CBC_PAD,  // UNDEFINED_T
        /// Historical
        CKM_GENERIC_SECRET_KEY_GEN,
        CKM_CONCATENATE_BASE_AND_KEY: ObjectHandle,
        // CKM_CONCATENATE_BASE_AND_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_CONCATENATE_DATA_AND_BASE,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_XOR_BASE_AND_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        CKM_EXTRACT_KEY_FROM_KEY: Ulong,  // CK_EXTRACT_PARAMS
        // CKM_SSL3_PRE_MASTER_KEY_GEN,  // CK_VERSION_T
        // CKM_SSL3_MASTER_KEY_DERIVE,  // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
        // CKM_SSL3_KEY_AND_MAC_DERIVE,  // CK_SSL3_KEY_MAT_PARAMS_T

        // CKM_SSL3_MASTER_KEY_DERIVE_DH,  // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
        // CKM_TLS_PRE_MASTER_KEY_GEN,  // UNDEFINED_T
        // CKM_TLS_MASTER_KEY_DERIVE,  // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
        // CKM_TLS_KEY_AND_MAC_DERIVE,  // CK_SSL3_KEY_MAT_PARAMS_T
        // CKM_TLS_MASTER_KEY_DERIVE_DH,  // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T

        // CKM_TLS_PRF,  // CK_TLS_MAC_PARAMS_T

        CKM_SSL3_MD5_MAC: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_SSL3_SHA1_MAC: Ulong,  // CK_MAC_GENERAL_PARAMS
        // /// Historical
        // CKM_MD5_KEY_DERIVATION,  // UNDEFINED_T
        // /// Historical
        // CKM_MD2_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA1_KEY_DERIVATION,  // UNDEFINED_T

        // CKM_SHA256_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA384_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA512_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA224_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA3_256_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA3_224_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA3_384_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHA3_512_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHAKE_128_KEY_DERIVATION,  // UNDEFINED_T
        // CKM_SHAKE_256_KEY_DERIVATION,  // UNDEFINED_T

        // /// Historical
        // CKM_PBE_MD2_DES_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_MD5_DES_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_MD5_CAST_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_MD5_CAST3_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_MD5_CAST128_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_SHA1_CAST128_CBC, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_SHA1_RC4_128, // UNDEFINED_T
        // /// Historical
        // CKM_PBE_SHA1_RC4_40, // UNDEFINED_T
        // CKM_PBE_SHA1_DES3_EDE_CBC, // CK_PBE_PARAMS_T
        // CKM_PBE_SHA1_DES2_EDE_CBC, // CK_PBE_PARAMS_T
        // CKM_PBE_SHA1_RC2_128_CBC, // UNDEFINED_T
        // CKM_PBE_SHA1_RC2_40_CBC, // UNDEFINED_T

        // CKM_PKCS5_PBKD2,  // CK_PKCS5_PBKD2_PARAMS_T

        // CKM_PBA_SHA1_WITH_SHA1_HMAC,  // CK_PBE_PARAMS_T

        CKM_WTLS_PRE_MASTER_KEY_GEN: u8,
        // CKM_WTLS_MASTER_KEY_DERIVE,  // UNDEFINED_T, ? CK_WTLS_MASTER_KEY_DERIVE_PARAMS or CK_WTLS_RANDOM_DATA ?
        // CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,  // CK_WTLS_MASTER_KEY_DERIVE_PARAMS
        // CKM_WTLS_PRF,  // CK_WTLS_PRF_PARAMS_T
        // CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,  // UNDEFINED_T
        // CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,  // UNDEFINED_T

        // CKM_TLS10_MAC_SERVER,  // UNDEFINED_T
        // CKM_TLS10_MAC_CLIENT,  // UNDEFINED_T
        // CKM_TLS12_MAC,  // UNDEFINED_T
        // CKM_TLS12_KDF,  // UNDEFINED_T
        // CKM_TLS12_MASTER_KEY_DERIVE,  // CK_TLS12_MASTER_KEY_DERIVE_PARAMS_T
        // CKM_TLS12_KEY_AND_MAC_DERIVE,   // CK_TLS12_KEY_MAT_PARAMS_T
        // CKM_TLS12_MASTER_KEY_DERIVE_DH,  // CK_TLS12_MASTER_KEY_DERIVE_DH_T
        // CKM_TLS12_KEY_SAFE_DERIVE,  // UNDEFINED_T
        // CKM_TLS_MAC,  // CK_TLS_MAC_PARAMS_T
        // CKM_TLS_KDF,  // CK_TLS_KDF_PARAMS_T

        // CKM_KEY_WRAP_LYNKS,  // UNDEFINED_T
        // CKM_KEY_WRAP_SET_OAEP,  // UNDEFINED_T

        // CKM_CMS_SIG,  // CK_CMS_SIG_PARAMS_T
        // CKM_KIP_DERIVE,  // CK_KIP_PARAMS_T
        // CKM_KIP_WRAP,  // CK_KIP_PARAMS_T
        // CKM_KIP_MAC,  // CK_KIP_PARAMS_T

        CKM_CAMELLIA_KEY_GEN,
        CKM_CAMELLIA_ECB,
        /// Camellia-CBC, denoted CKM_CAMELLIA_CBC, is a mechanism for single-
        /// and multiple-part encryption and decryption; key wrapping; and
        /// key unwrapping, based on Camellia and cipher-block chaining mode.
        CKM_CAMELLIA_CBC: [u8; 16],
        /// Camellia-MAC, denoted by CKM_CAMELLIA_MAC, is a special case of
        /// the general-length Camellia-MAC mechanism. Camellia-MAC always
        /// produces and verifies MACs that are half the block size in length.
        CKM_CAMELLIA_MAC,
        /// General-length Camellia-MAC, denoted CKM_CAMELLIA_MAC_GENERAL,
        /// is a mechanism for single- and multiple-part signatures and
        /// verification, based on Camellia and data authentication as
        /// defined in [`CAMELLIA`]
        ///
        /// It has a parameter, a CK_MAC_GENERAL_PARAMS structure, which
        /// specifies the output length desired from the mechanism.
        ///
        /// The output bytes from this mechanism are taken from the start
        /// of the final Camellia cipher block produced in the MACing process.
        ///
        /// [`CAMELLIA`]: http://www.ietf.org/rfc/rfc3713.txt
        CKM_CAMELLIA_MAC_GENERAL: Ulong,
        /// Camellia-CBC with PKCS padding, denoted CKM_CAMELLIA_CBC_PAD,
        /// is a mechanism for single- and multiple-part encryption and decryption;
        /// key wrapping; and key unwrapping, based on Camellia;
        /// cipher-block chaining mode; and the block cipher padding method
        /// detailed in PKCS #7.
        CKM_CAMELLIA_CBC_PAD: [u8; 16],
        // CKM_CAMELLIA_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_CAMELLIA_CBC_ENCRYPT_DATA,  // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_T
        // /// Historical
        // CKM_CAMELLIA_CTR,  // UNDEFINED_T

        CKM_ARIA_KEY_GEN,
        CKM_ARIA_ECB,
        /// ARIA-CBC, denoted CKM_ARIA_CBC, is a mechanism for single- and
        /// multiple-part encryption and decryption; key wrapping; and
        /// key unwrapping, based on ARIA and cipher-block chaining mode.
        CKM_ARIA_CBC: [u8; 16],
        CKM_ARIA_MAC,
        CKM_ARIA_MAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        /// ARIA-CBC with PKCS padding, denoted CKM_ARIA_CBC_PAD, is a mechanism
        /// for single- and multiple-part encryption and decryption; key wrapping;
        /// and key unwrapping, based on ARIA; cipher-block chaining mode;
        /// and the block cipher padding method detailed in PKCS #7.
        CKM_ARIA_CBC_PAD: [u8; 16],
        // CKM_ARIA_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_ARIA_CBC_ENCRYPT_DATA,  // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_T

        CKM_SEED_KEY_GEN,
        CKM_SEED_ECB,
        /// SEED-CBC, denoted CKM_SEED_CBC, is a mechanism for single- and
        /// multiple-part encryption and decryption; key wrapping; and
        /// key unwrapping, based on SEED and cipher-block chaining mode.
        CKM_SEED_CBC: [u8; 16],
        CKM_SEED_MAC,
        CKM_SEED_MAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        /// SEED-CBC with PKCS padding, denoted CKM_SEED_CBC_PAD, is a mechanism
        /// for single- and multiple-part encryption and decryption; key wrapping;
        /// and key unwrapping, based on SEED; cipher-block chaining mode;
        /// and the block cipher padding method detailed in PKCS #7.
        CKM_SEED_CBC_PAD: [u8; 16],
        // CKM_SEED_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_SEED_CBC_ENCRYPT_DATA,  // CK_CBC_ENCRYPT_DATA_PARAMS_T

        /// Historical
        CKM_SKIPJACK_KEY_GEN,
        /// Historical
        ///
        /// SKIPJACK-ECB64, denoted CKM_SKIPJACK_ECB64, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 64-bit electronic codebook mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_ECB64: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-CBC64, denoted CKM_SKIPJACK_CBC64, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 64-bit cipher-block chaining mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_CBC64: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-OFB64, denoted CKM_SKIPJACK_OFB64, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 64-bit output feedback mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_OFB64: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-CFB64, denoted CKM_SKIPJACK_CFB64, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 64-bit cipher feedback mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_CFB64: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-CFB32, denoted CKM_SKIPJACK_CFB32, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 32-bit cipher feedback mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_CFB32: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-CFB16, denoted CKM_SKIPJACK_CFB16, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 16-bit cipher feedback mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_CFB16: [u8; 24],
        /// Historical
        ///
        /// SKIPJACK-CFB8, denoted CKM_SKIPJACK_CFB8, is a mechanism
        /// for single- and multiple-part encryption and decryption with SKIPJACK
        /// in 8-bit cipher feedback mode as defined in FIPS PUB 185.
        CKM_SKIPJACK_CFB8: [u8; 24],
        /// Historical
        CKM_SKIPJACK_WRAP,
        // /// Historical
        // CKM_SKIPJACK_PRIVATE_WRAP,  // CK_SKIPJACK_PRIVATE_WRAP_PARAMS_T
        // /// Historical
        // CKM_SKIPJACK_RELAYX,  // CK_SKIPJACK_RELAYX_PARAMS_T
        /// Historical
        CKM_KEA_KEY_PAIR_GEN,
        // /// Historical
        // CKM_KEA_KEY_DERIVE,  // UNDEFINED_T
        // /// Historical
        // CKM_KEA_DERIVE,  // CK_KEA_DERIVE_PARAMS_T
        /// Historical
        CKM_FORTEZZA_TIMESTAMP,
        /// Historical
        CKM_BATON_KEY_GEN,
        /// Historical
        ///
        /// BATON-ECB128, denoted CKM_BATON_ECB128, is a mechanism
        /// for single- and multiple-part encryption and decryption with BATON
        /// in 128-bit electronic codebook mode.
        CKM_BATON_ECB128: [u8; 24],
        /// Historical
        ///
        /// BATON-ECB96, denoted CKM_BATON_ECB96, is a mechanism
        /// for single- and multiple-part encryption and decryption with BATON
        /// in 96-bit electronic codebook mode.
        CKM_BATON_ECB96: [u8; 24],
        /// Historical
        ///
        /// BATON-CBC128, denoted CKM_BATON_CBC128, is a mechanism
        /// for single- and multiple-part encryption and decryption with BATON
        /// in 128-bit cipher-block chaining mode.
        CKM_BATON_CBC128: [u8; 24],
        /// Historical
        ///
        /// BATON-COUNTER, denoted CKM_BATON_COUNTER, is a mechanism
        /// for single- and multiple-part encryption and decryption with BATON
        /// in counter mode.
        CKM_BATON_COUNTER: [u8; 24],
        /// BATON-SHUFFLE, denoted CKM_BATON_SHUFFLE, is a mechanism
        /// for single- and multiple-part encryption and decryption with BATON
        /// in shuffle mode.
        CKM_BATON_SHUFFLE: [u8; 24],
        /// Historical
        CKM_BATON_WRAP,

        CKM_EC_KEY_PAIR_GEN,

        CKM_ECDSA,
        CKM_ECDSA_SHA1,
        // CKM_ECDSA_SHA224, // UNDEFINED_T
        // CKM_ECDSA_SHA256, // UNDEFINED_T
        // CKM_ECDSA_SHA384, // UNDEFINED_T
        // CKM_ECDSA_SHA512, // UNDEFINED_T
        // CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,

        CKM_ECDH1_DERIVE: Ecdh1DeriveParams<'a>,
        CKM_ECDH1_COFACTOR_DERIVE: Ecdh1DeriveParams<'a>,
        // CKM_ECMQV_DERIVE,  // CK_ECMQV_DERIVE_PARAMS_T

        // CKM_ECDH_AES_KEY_WRAP,  // CK_ECDH_AES_KEY_WRAP_PARAMS_T
        // CKM_RSA_AES_KEY_WRAP,  // CK_RSA_AES_KEY_WRAP_PARAMS_T

        /// Historical
        CKM_JUNIPER_KEY_GEN,
        /// Historical
        ///
        /// JUNIPER-ECB128, denoted CKM_JUNIPER_ECB128, is a mechanism
        /// for single- and multiple-part encryption and decryption with JUNIPER
        /// in 128-bit electronic codebook mode.
        ///
        /// It has a parameter, a 24-byte initialization vector.
        /// During an encryption operation, this IV is set to some value generated
        /// by the token"in other words, the application cannot specify
        /// a particular IV when encrypting. It can, of course, specify
        /// a particular IV when decrypting.
        CKM_JUNIPER_ECB128: [u8; 24],
        /// Historical
        ///
        /// JUNIPER-CBC128, denoted CKM_JUNIPER_CBC128, is a mechanism
        /// for single- and multiple-part encryption and decryption with JUNIPER
        /// in 128-bit cipher-block chaining mode.
        ///
        /// It has a parameter, a 24-byte initialization vector.
        /// During an encryption operation, this IV is set to some value generated
        /// by the token"in other words, the application cannot specify
        /// a particular IV when encrypting. It can, of course, specify
        /// a particular IV when decrypting.
        CKM_JUNIPER_CBC128: [u8; 24],
        /// Historical
        ///
        /// JUNIPER COUNTER, denoted CKM_JUNIPER_COUNTER, is a mechanism
        /// for single- and multiple-part encryption and decryption with JUNIPER
        /// in counter mode.
        ///
        /// It has a parameter, a 24-byte initialization vector.
        /// During an encryption operation, this IV is set to some value generated
        /// by the token"in other words, the application cannot specify
        /// a particular IV when encrypting. It can, of course, specify
        /// a particular IV when decrypting.
        CKM_JUNIPER_COUNTER: [u8; 24],
        /// Historical
        ///
        /// JUNIPER-SHUFFLE, denoted CKM_JUNIPER_SHUFFLE, is a mechanism
        /// for single- and multiple-part encryption and decryption with JUNIPER
        /// in shuffle mode.
        ///
        /// It has a parameter, a 24-byte initialization vector.
        /// During an encryption operation, this IV is set to some value generated
        /// by the token"in other words, the application cannot specify
        /// a particular IV when encrypting. It can, of course, specify
        /// a particular IV when decrypting.
        CKM_JUNIPER_SHUFFLE: [u8; 24],
        /// Historical
        CKM_JUNIPER_WRAP,
        CKM_FASTHASH,

        // CKM_AES_XTS,
        // CKM_AES_XTS_KEY_GEN,
        CKM_AES_KEY_GEN,
        CKM_AES_ECB,
        /// AES-CBC, denoted CKM_AES_CBC, is a mechanism for single- and
        /// multiple-part encryption and decryption; key wrapping; and
        /// key unwrapping, based on NIST's Advanced Encryption Standard and
        /// cipher-block chaining mode.
        ///
        /// It has a parameter, a 16-byte initialization vector.
        CKM_AES_CBC: [u8; 16],
        CKM_AES_MAC,
        CKM_AES_MAC_GENERAL: Ulong,  // CK_MAC_GENERAL_PARAMS
        /// AES-CBC with PKCS padding, denoted CKM_AES_CBC_PAD, is a mechanism
        /// for single- and multiple-part encryption and decryption; key wrapping;
        /// and key unwrapping, based on NIST's Advanced Encryption Standard;
        /// cipher-block chaining mode; and the block cipher padding method
        /// detailed in PKCS#7.
        ///
        /// It has a parameter, a 16-byte initialization vector.
        CKM_AES_CBC_PAD: [u8; 16],
        // CKM_AES_CTR,  // CK_AES_CTR_PARAMS_T
        // CKM_AES_GCM,  // CK_GCM_PARAMS_T
        // CKM_AES_CCM,  // CK_CCM_PARAMS_T
        CKM_AES_CTS: [u8; 16],
        CKM_AES_CMAC: Ulong,  // CK_MAC_GENERAL_PARAMS
        CKM_AES_CMAC_GENERAL,

        CKM_AES_XCBC_MAC,
        CKM_AES_XCBC_MAC_96,
        /// AES-GMAC, denoted CKM_AES_GMAC, is a mechanism for single and
        /// multiple-part signatures and verification. It is described in
        /// NIST Special Publication 800-38D \[GMAC\]. GMAC is a special case of GCM
        /// that authenticates only the Additional Authenticated Data (AAD)
        /// part of the GCM mechanism parameters. When HMAC is used
        /// with C_Sign or C_Verify, pData points to the AAD.
        /// HMAC does not use plaintext or ciphertext.
        ///
        /// The signature produced by HMAC, also referred to as a Tag,
        /// is 16 bytes long.
        /// Its single mechanism parameter is a 12 byte initialization vector (IV).
        CKM_AES_GMAC: [u8; 12],

        CKM_BLOWFISH_KEY_GEN,
        /// Blowfish-CBC, denoted CKM_BLOWFISH_CBC, is a mechanism
        /// for single- and multiple-part encryption and decryption;
        /// key wrapping; and key unwrapping.
        CKM_BLOWFISH_CBC: [u8; 8],
        CKM_TWOFISH_KEY_GEN,
        /// Twofish-CBC, denoted CKM_TWOFISH_CBC, is a mechanism
        /// for single- and multiple-part encryption and decryption;
        /// key wrapping; and key unwrapping.
        CKM_TWOFISH_CBC: [u8; 16],
        /// Blowfish-CBC, denoted CKM_BLOWFISH_CBC, is a mechanism
        /// for single- and multiple-part encryption and decryption;
        /// key wrapping; and key unwrapping.
        CKM_BLOWFISH_CBC_PAD: [u8; 8],
        /// Twofish-CBC-PAD, denoted CKM_TWOFISH_CBC_PAD, is a mechanism
        /// for single- and multiple-part encryption and decryption,
        /// key wrapping and key unwrapping, cipher-block chaining mode
        /// and the block cipher padding method detailed in PKCS #7.
        CKM_TWOFISH_CBC_PAD: [u8; 16],

        // CKM_DES_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_DES_CBC_ENCRYPT_DATA,  // CK_DES_CBC_ENCRYPT_DATA_PARAMS_T
        // CKM_DES3_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_DES3_CBC_ENCRYPT_DATA,  // CK_DES_CBC_ENCRYPT_DATA_PARAMS_T
        // CKM_AES_ECB_ENCRYPT_DATA,  // CK_KEY_DERIVATION_STRING_DATA_T
        // CKM_AES_CBC_ENCRYPT_DATA,  // CK_AES_CBC_ENCRYPT_DATA_PARAMS_T

        CKM_GOSTR3410_KEY_PAIR_GEN,
        CKM_GOSTR3410,
        CKM_GOSTR3410_WITH_GOSTR3411: Vec<u8>,  // DER-encoding of the object identifier
        // CKM_GOSTR3410_KEY_WRAP,  // CK_GOSTR3410_KEY_WRAP_PARAMS_T
        // CKM_GOSTR3410_DERIVE,  // CK_GOSTR3410_DERIVE_PARAMS_T
        CKM_GOSTR3411: Vec<u8>,  // DER-encoding of the object identifier
        CKM_GOSTR3411_HMAC: Vec<u8>,  // DER-encoding of the object identifier
        CKM_GOST28147_KEY_GEN,  /* CKM_GOST28147_KEY_GEN INTERNATIONAL */
        CKM_GOST28147_ECB,  /* CKM_GOST28147_ECB INTERNATIONAL */
        /// GOST 28147-89 encryption mode except ECB, denoted CKM_GOST28147,
        /// is a mechanism for single and multiple-part encryption and decryption;
        /// key wrapping; and key unwrapping, based on [GOST 28147-89] and CFB,
        /// counter mode, and additional CBC mode defined in [RFC 4357] section 2.
        /// Encryption's parameters are specified in object identifier of
        /// attribute CKA_GOST28147_PARAMS.
        ///
        /// It has a parameter, which is an 8-byte initialization vector.
        /// This parameter may be omitted then a zero initialization vector is used.
        CKM_GOST28147: [u8; 8],
        /// GOST 28147-89-MAC, denoted CKM_GOST28147_MAC, is a mechanism
        /// for data integrity and authentication based on GOST 28147-89
        /// and key meshing algorithms [RFC 4357] section 2.3.
        ///
        /// MACing parameters are specified in object identifier
        /// of attribute CKA_GOST28147_PARAMS.
        ///
        /// The output bytes from this mechanism are taken from the start of
        /// the final GOST 28147-89 cipher block produced in the MACing process.
        ///
        /// It has a parameter, which is an 8-byte MAC initialization vector.
        /// This parameter may be omitted then a zero initialization vector is used.
        CKM_GOST28147_MAC: [u8; 8],
        /// GOST 28147-89 keys as a KEK (key encryption keys) for encryption
        /// GOST 28147-89 keys, denoted by CKM_GOST28147_KEY_WRAP, is a mechanism
        /// for key wrapping; and key unwrapping, based on GOST 28147-89.
        /// Its purpose is to encrypt and decrypt keys have been generated by
        /// key generation mechanism for GOST 28147-89.
        ///
        /// It has a parameter, which is an 8-byte MAC initialization vector.
        /// This parameter may be omitted then a zero initialization vector is used.
        CKM_GOST28147_KEY_WRAP: [u8; 8],
        // CKM_CHACHA20_KEY_GEN,
        // CKM_CHACHA20,
        // CKM_POLY1305_KEY_GEN,
        // CKM_POLY1305,
        CKM_DSA_PARAMETER_GEN,
        CKM_DH_PKCS_PARAMETER_GEN,
        CKM_X9_42_DH_PARAMETER_GEN,
        // CKM_DSA_PROBABILISTIC_PARAMETER_GEN,  // CK_DSA_PARAMETER_GEN_PARAM_T
        // CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,  // CK_DSA_PARAMETER_GEN_PARAM_T
        // CKM_DSA_FIPS_G_GEN,

        CKM_AES_OFB: [u8; 16],
        CKM_AES_CFB64: [u8; 16],
        CKM_AES_CFB8: [u8; 16],
        CKM_AES_CFB128: [u8; 16],

        // CKM_AES_CFB1,  // UNDEFINED_T
        // // WAS: 0x00001090
        // CKM_AES_KEY_WRAP,  // UNDEFINED_T, [u8; 8] or None
        // // WAS: 0x00001091
        // CKM_AES_KEY_WRAP_PAD,  // UNDEFINED_T, [u8; 8] or None
        // CKM_AES_KEY_WRAP_KWP,
        // CKM_AES_KEY_WRAP_PKCS7,

        CKM_RSA_PKCS_TPM_1_1,
        CKM_RSA_PKCS_OAEP_TPM_1_1,

        // CKM_SHA_1_KEY_GEN,
        // CKM_SHA224_KEY_GEN,
        // CKM_SHA256_KEY_GEN,
        // CKM_SHA384_KEY_GEN,
        // CKM_SHA512_KEY_GEN,
        // CKM_SHA512_224_KEY_GEN,
        // CKM_SHA512_256_KEY_GEN,
        // CKM_SHA512_T_KEY_GEN,
        // CKM_NULL,
        // CKM_BLAKE2B_160,
        // CKM_BLAKE2B_160_HMAC,
        // CKM_BLAKE2B_160_HMAC_GENERAL,
        // CKM_BLAKE2B_160_KEY_DERIVE,
        // CKM_BLAKE2B_160_KEY_GEN,
        // CKM_BLAKE2B_256,
        // CKM_BLAKE2B_256_HMAC,
        // CKM_BLAKE2B_256_HMAC_GENERAL,
        // CKM_BLAKE2B_256_KEY_DERIVE,
        // CKM_BLAKE2B_256_KEY_GEN,
        // CKM_BLAKE2B_384,
        // CKM_BLAKE2B_384_HMAC,
        // CKM_BLAKE2B_384_HMAC_GENERAL,
        // CKM_BLAKE2B_384_KEY_DERIVE,
        // CKM_BLAKE2B_384_KEY_GEN,
        // CKM_BLAKE2B_512,
        // CKM_BLAKE2B_512_HMAC,
        // CKM_BLAKE2B_512_HMAC_GENERAL,
        // CKM_BLAKE2B_512_KEY_DERIVE,
        // CKM_BLAKE2B_512_KEY_GEN,
        // CKM_SALSA20,
        // CKM_CHACHA20_POLY1305,
        // CKM_SALSA20_POLY1305,
        // CKM_X3DH_INITIALIZE,
        // CKM_X3DH_RESPOND,
        // CKM_X2RATCHET_INITIALIZE,
        // CKM_X2RATCHET_RESPOND,
        // CKM_X2RATCHET_ENCRYPT,
        // CKM_X2RATCHET_DECRYPT,
        // CKM_XEDDSA,
        // CKM_HKDF_DERIVE,
        // CKM_HKDF_DATA,
        // CKM_HKDF_KEY_GEN,
        // CKM_SALSA20_KEY_GEN,

        // CKM_ECDSA_SHA3_224,  // UNDEFINED_T
        // CKM_ECDSA_SHA3_256,  // UNDEFINED_T
        // CKM_ECDSA_SHA3_384,  // UNDEFINED_T
        // CKM_ECDSA_SHA3_512,  // UNDEFINED_T
        // CKM_EC_EDWARDS_KEY_PAIR_GEN,
        // CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        // CKM_EDDSA,
        // CKM_SP800_108_COUNTER_KDF,
        // CKM_SP800_108_FEEDBACK_KDF,
        // CKM_SP800_108_DOUBLE_PIPELINE_KDF,

        // CKM_IKE2_PRF_PLUS_DERIVE,
        // CKM_IKE_PRF_DERIVE,
        // CKM_IKE1_PRF_DERIVE,
        // CKM_IKE1_EXTENDED_DERIVE,
        // CKM_HSS_KEY_PAIR_GEN,
        // CKM_HSS,

        // CKM_XMSS_KEY_PAIR_GEN,
        // CKM_XMSSMT_KEY_PAIR_GEN,
        // CKM_XMSS,
        // CKM_XMSSMT,

        // CKM_ECDH_X_AES_KEY_WRAP,
        // CKM_ECDH_COF_AES_KEY_WRAP,
        // CKM_PUB_KEY_FROM_PRIV_KEY,

        // CKM_ML_KEM_KEY_PAIR_GEN,
        // CKM_ML_KEM,

        // CKM_ML_DSA_KEY_PAIR_GEN,
        // CKM_ML_DSA,
        // CKM_HASH_ML_DSA,
        // CKM_HASH_ML_DSA_SHA224,
        // CKM_HASH_ML_DSA_SHA256,
        // CKM_HASH_ML_DSA_SHA384,
        // CKM_HASH_ML_DSA_SHA512,
        // CKM_HASH_ML_DSA_SHA3_224,
        // CKM_HASH_ML_DSA_SHA3_256,
        // CKM_HASH_ML_DSA_SHA3_384,
        // CKM_HASH_ML_DSA_SHA3_512,
        // CKM_HASH_ML_DSA_SHAKE128,
        // CKM_HASH_ML_DSA_SHAKE256,

        // CKM_SLH_DSA_KEY_PAIR_GEN,
        // CKM_SLH_DSA,
        // CKM_HASH_SLH_DSA,
        // CKM_HASH_SLH_DSA_SHA224,
        // CKM_HASH_SLH_DSA_SHA256,
        // CKM_HASH_SLH_DSA_SHA384,
        // CKM_HASH_SLH_DSA_SHA512,
        // CKM_HASH_SLH_DSA_SHA3_224,
        // CKM_HASH_SLH_DSA_SHA3_256,
        // CKM_HASH_SLH_DSA_SHA3_384,
        // CKM_HASH_SLH_DSA_SHA3_512,
        // CKM_HASH_SLH_DSA_SHAKE128,
        // CKM_HASH_SLH_DSA_SHAKE256,

        // CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        // CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,

        CKM_VENDOR_DEFINED,
    ]
);

// CK_MECHANISM_INFO

bitflags! {
    /// Flags specifying mechanism capabilities for [`CK_MECHANISM_INFO`].
    #[derive(Debug, Clone)]
    struct MechanismInfoFlags: CK_FLAGS {
        const HW = CKF_HW;
        const ENCRYPT = CKF_ENCRYPT;
        const DECRYPT = CKF_DECRYPT;
        const DIGEST = CKF_DIGEST;
        const SIGN = CKF_SIGN;
        const SIGN_RECOVER = CKF_SIGN_RECOVER;
        const VERIFY = CKF_VERIFY;
        const VERIFY_RECOVER = CKF_VERIFY_RECOVER;
        const GENERATE = CKF_GENERATE;
        const GENERATE_KEY_PAIR = CKF_GENERATE_KEY_PAIR;
        const WRAP = CKF_WRAP;
        const UNWRAP = CKF_UNWRAP;
        const DERIVE = CKF_DERIVE;
        const EXTENSION = CKF_EXTENSION;
        const EC_F_P = CKF_EC_F_P;
        const EC_F_2M = CKF_EC_F_2M;
        const EC_ECPARAMETERS = CKF_EC_ECPARAMETERS;
        const EC_NAMEDCURVE = CKF_EC_NAMEDCURVE;
        const EC_UNCOMPRESS = CKF_EC_UNCOMPRESS;
        const EC_COMPRESS = CKF_EC_COMPRESS;
    }
}

/// Information about a particular mechanism
#[derive(Debug, Clone)]
pub struct MechanismInfo {
    min_key_size: usize,
    max_key_size: usize,
    /// Flags specifying mechanism capabilities.
    flags: MechanismInfoFlags,
}

impl MechanismInfo {
    /// The minimum size of the key for the mechanism (whether this is
    /// measured in bits or in bytes is mechanism-dependent).
    /// For some mechanisms has meaningless values.
    pub fn min_key_size(&self) -> usize {
        self.min_key_size
    }

    /// The maximum size of the key for the mechanism (whether this is
    /// measured in bits or in bytes is mechanism-dependent).
    /// For some mechanisms has meaningless values.
    pub fn max_key_size(&self) -> usize {
        self.max_key_size
    }

    /// True if the mechanism is performed by the device;
    /// false if the mechanism is performed in software.
    pub fn hardware(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::HW)
    }

    /// True if the mechanism can be used with
    /// [`Session::encrypt_init`](crate::module::session::Session::encrypt_init) or
    /// [`Session::encrypt`](crate::module::session::Session::encrypt).
    pub fn encrypt(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::ENCRYPT)
    }

    /// True if the mechanism can be used with
    /// [`Session::decrypt_init`](crate::module::session::Session::decrypt_init) or
    /// [`Session::decrypt`](crate::module::session::Session::decrypt).
    pub fn decrypt(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::DECRYPT)
    }

    /// True if the mechanism can be used with
    /// [`Session::digest_init`](crate::module::session::Session::digest_init) or
    /// [`Session::digest`](crate::module::session::Session::digest).
    pub fn digest(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::DIGEST)
    }

    /// True if the mechanism can be used with
    /// [`Session::sign_init`](crate::module::session::Session::sign_init) or
    /// [`Session::sign`](crate::module::session::Session::sign).
    pub fn sign(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::SIGN)
    }

    /// True if the mechanism can be used with
    /// [`Session::sign_recover`](crate::module::session::Session::sign_recover).
    pub fn sign_recover(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::SIGN_RECOVER)
    }

    /// True if the mechanism can be used with
    /// [`Session::verify_init`](crate::module::session::Session::verify_init) or
    /// [`Session::verify`](crate::module::session::Session::verify).
    pub fn verify(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::VERIFY)
    }

    /// True if the mechanism can be used with
    /// [`Session::verify_recover`](crate::module::session::Session::verify_recover).
    pub fn verify_recover(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::VERIFY_RECOVER)
    }

    /// True if the mechanism can be used with
    /// [`Session::generate_key`](crate::module::session::Session::generate_key).
    pub fn generate(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::GENERATE)
    }

    /// True if the mechanism can be used with
    /// [`Session::generate_key_pair`](crate::module::session::Session::generate_key_pair).
    pub fn generate_key_pair(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::GENERATE_KEY_PAIR)
    }

    /// True if the mechanism can be used with
    /// [`Session::wrap_key`](crate::module::session::Session::wrap_key).
    pub fn wrap(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::WRAP)
    }

    /// True if the mechanism can be used with
    /// [`Session::unwrap_key`](crate::module::session::Session::unwrap_key).
    pub fn unwrap(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::UNWRAP)
    }

    /// True if the mechanism can be used with
    /// [`Session::derive_key`](crate::module::session::Session::derive_key).
    pub fn derive(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::DERIVE)
    }

    /// True if there is an extension to the flags; false if no extensions.
    /// MUST be false for PKCS#11 v2.40.
    pub fn extension(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EXTENSION)
    }

    /// True if the mechanism can be used with EC domain parameters over
    /// ***F<sub>p</sub>***.
    pub fn ec_f_p(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_F_P)
    }

    /// True if the mechanism can be used with EC domain parameters over
    /// ***F<sub>2<sup>m</sup></sub>***.
    pub fn ec_f_2m(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_F_2M)
    }

    /// True if the mechanism can be used with EC domain parameters of the
    /// choice **ecParameters**.
    pub fn ec_from_parameters(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_ECPARAMETERS)
    }

    /// True if the mechanism can be used with EC domain parameters of the
    /// choice **namedCurve**.
    pub fn ec_from_named_curve(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_NAMEDCURVE)
    }

    /// True if the mechanism can be used with elliptic curve point
    /// uncompressed.
    pub fn ec_uncompressed(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_UNCOMPRESS)
    }

    /// True if the mechanism can be used with elliptic curve point compressed.
    pub fn ec_compressed(&self) -> bool {
        self.flags.contains(MechanismInfoFlags::EC_COMPRESS)
    }
}

#[doc(hidden)]
impl From<CK_MECHANISM_INFO> for MechanismInfo {
    fn from(ck_mechanism_info: CK_MECHANISM_INFO) -> Self {
        Self {
            min_key_size: ck_mechanism_info.ulMinKeySize as usize,
            max_key_size: ck_mechanism_info.ulMaxKeySize as usize,
            flags: MechanismInfoFlags::from_bits_truncate(ck_mechanism_info.flags),
        }
    }
}

pkcs11_type!(
    /// Identifies the Key Derivation Function (KDF) applied to derive keying
    /// data from a shared secret.
    KeyDerivationFunctionType: CK_X9_42_DH_KDF_TYPE, naming = ScreamingSnakeCase;
    [
        // The following EC Key Derivation Functions are defined
        // (type: CK_EC_KDF_TYPE).

        CKD_NULL,
        CKD_SHA1_KDF,

        // The following X9.42 DH key derivation functions are defined
        // (type: CK_X9_42_DH_KDF_TYPE).

        CKD_SHA1_KDF_ASN1,
        CKD_SHA1_KDF_CONCATENATE,
        CKD_SHA224_KDF,
        CKD_SHA256_KDF,
        CKD_SHA384_KDF,
        CKD_SHA512_KDF,
        CKD_CPDIVERSIFY_KDF,
        CKD_SHA3_224_KDF,
        CKD_SHA3_256_KDF,
        CKD_SHA3_384_KDF,
        CKD_SHA3_512_KDF,
        CKD_SHA1_KDF_SP800,
        CKD_SHA224_KDF_SP800,
        CKD_SHA256_KDF_SP800,
        CKD_SHA384_KDF_SP800,
        CKD_SHA512_KDF_SP800,
        CKD_SHA3_224_KDF_SP800,
        CKD_SHA3_256_KDF_SP800,
        CKD_SHA3_384_KDF_SP800,
        CKD_SHA3_512_KDF_SP800,
        CKD_BLAKE2B_160_KDF,
        CKD_BLAKE2B_256_KDF,
        CKD_BLAKE2B_384_KDF,
        CKD_BLAKE2B_512_KDF,

        CKD_VENDOR_DEFINED
    ]
);

// Params

/// Key Derivation Function (KDF) applied to derive keying data
/// from a shared secret.
///
/// The key derivation function will be used by the EC or
/// X9.42 Diffie-Hellman key agreement schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDerivationFunction<'a> {
    kdf_type: KeyDerivationFunctionType,
    shared_data: Option<&'a [u8]>,
}

impl<'a> KeyDerivationFunction<'a> {
    /// Produces a raw shared secret value without applying any key
    /// derivation function.
    pub fn null() -> Self {
        Self {
            kdf_type: KeyDerivationFunctionType::NULL,
            shared_data: None,
        }
    }

    pub fn new(
        kdf_type: KeyDerivationFunctionType,
        shared_data: Option<&'a [u8]>,
    ) -> Result<Self> {
        let _shr_data_len = shared_data.map_or(0, <[u8]>::len);
        Ok(Self {
            kdf_type,
            shared_data,
        })
    }
}

// CK_ECDH1_DERIVE_PARAMS

/// Structure that provides the parameters for the [`Mechanism::Ecdh1Derive`]
/// and [`Mechanism::Ecdh1CofactorDerive`] key derivation mechanisms, where
/// each party contributes one key pair.
#[derive(Copy, Debug, Clone)]
#[repr(C)]
pub struct Ecdh1DeriveParams<'a> {
    /// Key derivation function used on the shared secret value.
    kdf: KeyDerivationFunctionType,
    /// The length in bytes of the shared info. [Optional]
    shared_data_len: Ulong,
    /// Pointer to some data shared between the two parties [Optional]
    shared_data: *const u8,
    /// The length in bytes of the other party's EC public key
    public_data_len: Ulong,
    /// Pointer to other party's EC public key value.
    public_data: *const u8,
    /// Phantom type
    _phantom: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Ecdh1DeriveParams<'a> {
    /// Construct ECDH derivation parameters.
    ///
    /// # Parameters
    ///
    /// * `kdf` - The key derivation function to use.
    /// * `public_data` - The other party's EC public key value. A token MUST
    ///   be able to accept this value encoded as a raw octet string (as per
    ///   section A.5.2 of [ANSI X9.62]). A token MAY, in addition, support
    ///   accepting this value as a DER-encoded
    ///   [`Attribute::EcPoint`](crate::module::types::Attribute::EcPoint)
    ///   (as per section E.6 of [ANSI X9.62]). The calling application is
    ///   responsible for converting the offered public key to the compressed
    ///   or uncompressed forms of these encodings if the token does not
    ///   support the offered form.
    pub fn new(kdf: KeyDerivationFunction<'a>, public_data: &'a [u8]) -> Result<Self> {
        Ok(Self {
            kdf: kdf.kdf_type,
            shared_data_len: kdf.shared_data.map_or(0, <[u8]>::len).try_into()?,
            shared_data: kdf.shared_data.map_or(std::ptr::null(), <[u8]>::as_ptr),
            public_data_len: public_data.len().try_into()?,
            public_data: public_data.as_ptr(),
            _phantom: std::marker::PhantomData,
        })
    }
}

// CK_X9_42_DH1_DERIVE_PARAMS

/// Structure that provides the parameters for the [`Mechanism::X942DhDerive`]
/// key derivation mechanisms, where each party contributes one key pair.
#[derive(Copy, Debug, Clone)]
#[repr(C)]
pub struct X9_42Dh1DeriveParams<'a> {
    /// Key derivation function used on the shared secret value
    kdf: KeyDerivationFunctionType,
    /// The length in bytes of the other info. [Optional]
    other_info_len: Ulong,
    /// Pointer to some data shared between the two parties [Optional]
    other_info: *const u8,
    /// The length in bytes of the other party's X9.42 Diffie-Hellman
    /// public key
    public_data_len: Ulong,
    /// Pointer to other party's X9.42 Diffie-Hellman public key value.
    public_data: *const u8,
    /// Phantom type
    _phantom: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> X9_42Dh1DeriveParams<'a> {
    /// Construct X9_42_DH derivation parameters.
    ///
    /// # Parameters
    ///
    /// * `kdf` - The key derivation function to use.
    /// * `public_data` - The other party's X9.42 Diffie-Hellman public key value.
    pub fn new(kdf: KeyDerivationFunction<'a>, public_data: &'a [u8]) -> Result<Self> {
        Ok(Self {
            kdf: kdf.kdf_type,
            other_info_len: kdf.shared_data.map_or(0, <[u8]>::len).try_into()?,
            other_info: kdf.shared_data.map_or(std::ptr::null(), <[u8]>::as_ptr),
            public_data_len: public_data.len().try_into()?,
            public_data: public_data.as_ptr(),
            _phantom: std::marker::PhantomData,
        })
    }
}

// CK_RSA_PKCS_MGF_TYPE

pkcs11_type!(
    /// Identifies the Message Generation Function (MGF) applied to a message block
    /// when formatting a message block for the PKCS #1 OAEP encryption scheme or
    /// the PKCS #1 PSS signature scheme.
    RsaPkcsMgfType: CK_RSA_PKCS_MGF_TYPE, naming = ScreamingSnakeCase;
    [
        CKG_MGF1_SHA1,
        CKG_MGF1_SHA256,
        CKG_MGF1_SHA384,
        CKG_MGF1_SHA512,
        CKG_MGF1_SHA224,
        CKG_MGF1_SHA3_224,
        CKG_MGF1_SHA3_256,
        CKG_MGF1_SHA3_384,
        CKG_MGF1_SHA3_512,
    ]
);

/// Parameters of the RsaPkcsPss mechanism
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct RsaPkcsPssParams {
    hash_alg: MechanismType,
    mgf: RsaPkcsMgfType,
    s_len: Ulong,
}

impl RsaPkcsPssParams {
    /// Construct parameters to the RsaPkcsPss mechanism.
    ///
    /// # Parameters
    ///
    /// * `hash_alg` - hash algorithm used in the PSS encoding;
    ///   if the signature mechanism does not include message hashing,
    ///   then this value must be the mechanism used by the application
    ///   to generate the message hash; if the signature mechanism includes
    ///   hashing, then this value must match the hash algorithm
    ///   indicated by the signature mechanism.
    /// * `mgf` - mask generation function to use on the encoded block.
    /// * `s_len` - length, in bytes, of the salt value
    ///   used  in the PSS encoding; typical values are
    ///   the length of the message hash and zero.
    pub fn new(hash_alg: MechanismType, mgf: RsaPkcsMgfType, s_len: Ulong) -> Self {
        Self {
            hash_alg,
            mgf,
            s_len,
        }
    }
}
