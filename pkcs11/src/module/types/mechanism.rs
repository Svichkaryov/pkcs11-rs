use bitflags::bitflags;
use std::{convert::TryFrom, ops::Deref};

use crate::error::{Error, Result};

use super::{general::*, ObjectHandle};

/// Identifies a mechanism type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
#[non_exhaustive]
pub struct MechanismType(CK_ULONG);

impl MechanismType {
    pub const RSA_PKCS_KEY_PAIR_GEN: MechanismType =
        MechanismType(CKM_RSA_PKCS_KEY_PAIR_GEN);
    pub const RSA_PKCS: MechanismType = MechanismType(CKM_RSA_PKCS);
    pub const RSA_9796: MechanismType = MechanismType(CKM_RSA_9796);
    pub const RSA_X_509: MechanismType = MechanismType(CKM_RSA_X_509);

    pub const MD2_RSA_PKCS: MechanismType = MechanismType(CKM_MD2_RSA_PKCS);
    pub const MD5_RSA_PKCS: MechanismType = MechanismType(CKM_MD5_RSA_PKCS);
    pub const SHA1_RSA_PKCS: MechanismType = MechanismType(CKM_SHA1_RSA_PKCS);

    pub const RIPEMD128_RSA_PKCS: MechanismType = MechanismType(CKM_RIPEMD128_RSA_PKCS);
    pub const RIPEMD160_RSA_PKCS: MechanismType = MechanismType(CKM_RIPEMD160_RSA_PKCS);
    pub const RSA_PKCS_OAEP: MechanismType = MechanismType(CKM_RSA_PKCS_OAEP);

    pub const RSA_X9_31_KEY_PAIR_GEN: MechanismType =
        MechanismType(CKM_RSA_X9_31_KEY_PAIR_GEN);
    pub const RSA_X9_31: MechanismType = MechanismType(CKM_RSA_X9_31);
    pub const SHA1_RSA_X9_31: MechanismType = MechanismType(CKM_SHA1_RSA_X9_31);
    pub const RSA_PKCS_PSS: MechanismType = MechanismType(CKM_RSA_PKCS_PSS);
    pub const SHA1_RSA_PKCS_PSS: MechanismType = MechanismType(CKM_SHA1_RSA_PKCS_PSS);

    pub const DSA_KEY_PAIR_GEN: MechanismType = MechanismType(CKM_DSA_KEY_PAIR_GEN);
    pub const DSA: MechanismType = MechanismType(CKM_DSA);
    pub const DSA_SHA1: MechanismType = MechanismType(CKM_DSA_SHA1);
    pub const DSA_SHA224: MechanismType = MechanismType(CKM_DSA_SHA224);
    pub const DSA_SHA256: MechanismType = MechanismType(CKM_DSA_SHA256);
    pub const DSA_SHA384: MechanismType = MechanismType(CKM_DSA_SHA384);
    pub const DSA_SHA512: MechanismType = MechanismType(CKM_DSA_SHA512);
    pub const DSA_SHA3_224: MechanismType = MechanismType(CKM_DSA_SHA3_224);
    pub const DSA_SHA3_256: MechanismType = MechanismType(CKM_DSA_SHA3_256);
    pub const DSA_SHA3_384: MechanismType = MechanismType(CKM_DSA_SHA3_384);
    pub const DSA_SHA3_512: MechanismType = MechanismType(CKM_DSA_SHA3_512);

    pub const DH_PKCS_KEY_PAIR_GEN: MechanismType =
        MechanismType(CKM_DH_PKCS_KEY_PAIR_GEN);
    pub const DH_PKCS_DERIVE: MechanismType = MechanismType(CKM_DH_PKCS_DERIVE);

    pub const X9_42_DH_KEY_PAIR_GEN: MechanismType =
        MechanismType(CKM_X9_42_DH_KEY_PAIR_GEN);
    pub const X9_42_DH_DERIVE: MechanismType = MechanismType(CKM_X9_42_DH_DERIVE);
    pub const X9_42_DH_HYBRID_DERIVE: MechanismType =
        MechanismType(CKM_X9_42_DH_HYBRID_DERIVE);
    pub const X9_42_MQV_DERIVE: MechanismType = MechanismType(CKM_X9_42_MQV_DERIVE);

    pub const SHA256_RSA_PKCS: MechanismType = MechanismType(CKM_SHA256_RSA_PKCS);
    pub const SHA384_RSA_PKCS: MechanismType = MechanismType(CKM_SHA384_RSA_PKCS);
    pub const SHA512_RSA_PKCS: MechanismType = MechanismType(CKM_SHA512_RSA_PKCS);
    pub const SHA256_RSA_PKCS_PSS: MechanismType = MechanismType(CKM_SHA256_RSA_PKCS_PSS);
    pub const SHA384_RSA_PKCS_PSS: MechanismType = MechanismType(CKM_SHA384_RSA_PKCS_PSS);
    pub const SHA512_RSA_PKCS_PSS: MechanismType = MechanismType(CKM_SHA512_RSA_PKCS_PSS);

    pub const SHA224_RSA_PKCS: MechanismType = MechanismType(CKM_SHA224_RSA_PKCS);
    pub const SHA224_RSA_PKCS_PSS: MechanismType = MechanismType(CKM_SHA224_RSA_PKCS_PSS);

    pub const SHA512_224: MechanismType = MechanismType(CKM_SHA512_224);
    pub const SHA512_224_HMAC: MechanismType = MechanismType(CKM_SHA512_224_HMAC);
    pub const SHA512_224_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA512_224_HMAC_GENERAL);
    pub const SHA512_224_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA512_224_KEY_DERIVATION);
    pub const SHA512_256: MechanismType = MechanismType(CKM_SHA512_256);
    pub const SHA512_256_HMAC: MechanismType = MechanismType(CKM_SHA512_256_HMAC);
    pub const SHA512_256_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA512_256_HMAC_GENERAL);
    pub const SHA512_256_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA512_256_KEY_DERIVATION);

    pub const SHA512_T: MechanismType = MechanismType(CKM_SHA512_T);
    pub const SHA512_T_HMAC: MechanismType = MechanismType(CKM_SHA512_T_HMAC);
    pub const SHA512_T_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA512_T_HMAC_GENERAL);
    pub const SHA512_T_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA512_T_KEY_DERIVATION);

    pub const SHA3_256_RSA_PKCS: MechanismType = MechanismType(CKM_SHA3_256_RSA_PKCS);
    pub const SHA3_384_RSA_PKCS: MechanismType = MechanismType(CKM_SHA3_384_RSA_PKCS);
    pub const SHA3_512_RSA_PKCS: MechanismType = MechanismType(CKM_SHA3_512_RSA_PKCS);
    pub const SHA3_256_RSA_PKCS_PSS: MechanismType =
        MechanismType(CKM_SHA3_256_RSA_PKCS_PSS);
    pub const SHA3_384_RSA_PKCS_PSS: MechanismType =
        MechanismType(CKM_SHA3_384_RSA_PKCS_PSS);
    pub const SHA3_512_RSA_PKCS_PSS: MechanismType =
        MechanismType(CKM_SHA3_512_RSA_PKCS_PSS);
    pub const SHA3_224_RSA_PKCS: MechanismType = MechanismType(CKM_SHA3_224_RSA_PKCS);
    pub const SHA3_224_RSA_PKCS_PSS: MechanismType =
        MechanismType(CKM_SHA3_224_RSA_PKCS_PSS);

    pub const RC2_KEY_GEN: MechanismType = MechanismType(CKM_RC2_KEY_GEN);
    pub const RC2_ECB: MechanismType = MechanismType(CKM_RC2_ECB);
    pub const RC2_CBC: MechanismType = MechanismType(CKM_RC2_CBC);
    pub const RC2_MAC: MechanismType = MechanismType(CKM_RC2_MAC);

    pub const RC2_MAC_GENERAL: MechanismType = MechanismType(CKM_RC2_MAC_GENERAL);
    pub const RC2_CBC_PAD: MechanismType = MechanismType(CKM_RC2_CBC_PAD);

    pub const RC4_KEY_GEN: MechanismType = MechanismType(CKM_RC4_KEY_GEN);
    pub const RC4: MechanismType = MechanismType(CKM_RC4);
    pub const DES_KEY_GEN: MechanismType = MechanismType(CKM_DES_KEY_GEN);
    pub const DES_ECB: MechanismType = MechanismType(CKM_DES_ECB);
    pub const DES_CBC: MechanismType = MechanismType(CKM_DES_CBC);
    pub const DES_MAC: MechanismType = MechanismType(CKM_DES_MAC);

    pub const DES_MAC_GENERAL: MechanismType = MechanismType(CKM_DES_MAC_GENERAL);
    pub const DES_CBC_PAD: MechanismType = MechanismType(CKM_DES_CBC_PAD);

    pub const DES2_KEY_GEN: MechanismType = MechanismType(CKM_DES2_KEY_GEN);
    pub const DES3_KEY_GEN: MechanismType = MechanismType(CKM_DES3_KEY_GEN);
    pub const DES3_ECB: MechanismType = MechanismType(CKM_DES3_ECB);
    pub const DES3_CBC: MechanismType = MechanismType(CKM_DES3_CBC);
    pub const DES3_MAC: MechanismType = MechanismType(CKM_DES3_MAC);

    pub const DES3_MAC_GENERAL: MechanismType = MechanismType(CKM_DES3_MAC_GENERAL);
    pub const DES3_CBC_PAD: MechanismType = MechanismType(CKM_DES3_CBC_PAD);
    pub const DES3_CMAC_GENERAL: MechanismType = MechanismType(CKM_DES3_CMAC_GENERAL);
    pub const DES3_CMAC: MechanismType = MechanismType(CKM_DES3_CMAC);
    pub const CDMF_KEY_GEN: MechanismType = MechanismType(CKM_CDMF_KEY_GEN);
    pub const CDMF_ECB: MechanismType = MechanismType(CKM_CDMF_ECB);
    pub const CDMF_CBC: MechanismType = MechanismType(CKM_CDMF_CBC);
    pub const CDMF_MAC: MechanismType = MechanismType(CKM_CDMF_MAC);
    pub const CDMF_MAC_GENERAL: MechanismType = MechanismType(CKM_CDMF_MAC_GENERAL);
    pub const CDMF_CBC_PAD: MechanismType = MechanismType(CKM_CDMF_CBC_PAD);

    pub const DES_OFB64: MechanismType = MechanismType(CKM_DES_OFB64);
    pub const DES_OFB8: MechanismType = MechanismType(CKM_DES_OFB8);
    pub const DES_CFB64: MechanismType = MechanismType(CKM_DES_CFB64);
    pub const DES_CFB8: MechanismType = MechanismType(CKM_DES_CFB8);

    pub const MD2: MechanismType = MechanismType(CKM_MD2);

    pub const MD2_HMAC: MechanismType = MechanismType(CKM_MD2_HMAC);
    pub const MD2_HMAC_GENERAL: MechanismType = MechanismType(CKM_MD2_HMAC_GENERAL);

    pub const MD5: MechanismType = MechanismType(CKM_MD5);

    pub const MD5_HMAC: MechanismType = MechanismType(CKM_MD5_HMAC);
    pub const MD5_HMAC_GENERAL: MechanismType = MechanismType(CKM_MD5_HMAC_GENERAL);

    pub const SHA_1: MechanismType = MechanismType(CKM_SHA_1);

    pub const SHA_1_HMAC: MechanismType = MechanismType(CKM_SHA_1_HMAC);
    pub const SHA_1_HMAC_GENERAL: MechanismType = MechanismType(CKM_SHA_1_HMAC_GENERAL);

    pub const RIPEMD128: MechanismType = MechanismType(CKM_RIPEMD128);
    pub const RIPEMD128_HMAC: MechanismType = MechanismType(CKM_RIPEMD128_HMAC);
    pub const RIPEMD128_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_RIPEMD128_HMAC_GENERAL);
    pub const RIPEMD160: MechanismType = MechanismType(CKM_RIPEMD160);
    pub const RIPEMD160_HMAC: MechanismType = MechanismType(CKM_RIPEMD160_HMAC);
    pub const RIPEMD160_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_RIPEMD160_HMAC_GENERAL);

    pub const SHA256: MechanismType = MechanismType(CKM_SHA256);
    pub const SHA256_HMAC: MechanismType = MechanismType(CKM_SHA256_HMAC);
    pub const SHA256_HMAC_GENERAL: MechanismType = MechanismType(CKM_SHA256_HMAC_GENERAL);
    pub const SHA224: MechanismType = MechanismType(CKM_SHA224);
    pub const SHA224_HMAC: MechanismType = MechanismType(CKM_SHA224_HMAC);
    pub const SHA224_HMAC_GENERAL: MechanismType = MechanismType(CKM_SHA224_HMAC_GENERAL);
    pub const SHA384: MechanismType = MechanismType(CKM_SHA384);
    pub const SHA384_HMAC: MechanismType = MechanismType(CKM_SHA384_HMAC);
    pub const SHA384_HMAC_GENERAL: MechanismType = MechanismType(CKM_SHA384_HMAC_GENERAL);
    pub const SHA512: MechanismType = MechanismType(CKM_SHA512);
    pub const SHA512_HMAC: MechanismType = MechanismType(CKM_SHA512_HMAC);
    pub const SHA512_HMAC_GENERAL: MechanismType = MechanismType(CKM_SHA512_HMAC_GENERAL);
    pub const SECURID_KEY_GEN: MechanismType = MechanismType(CKM_SECURID_KEY_GEN);
    pub const SECURID: MechanismType = MechanismType(CKM_SECURID);
    pub const HOTP_KEY_GEN: MechanismType = MechanismType(CKM_HOTP_KEY_GEN);
    pub const HOTP: MechanismType = MechanismType(CKM_HOTP);
    pub const ACTI: MechanismType = MechanismType(CKM_ACTI);
    pub const ACTI_KEY_GEN: MechanismType = MechanismType(CKM_ACTI_KEY_GEN);

    pub const SHA3_256: MechanismType = MechanismType(CKM_SHA3_256);
    pub const SHA3_256_HMAC: MechanismType = MechanismType(CKM_SHA3_256_HMAC);
    pub const SHA3_256_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA3_256_HMAC_GENERAL);
    pub const SHA3_256_KEY_GEN: MechanismType = MechanismType(CKM_SHA3_256_KEY_GEN);
    pub const SHA3_224: MechanismType = MechanismType(CKM_SHA3_224);
    pub const SHA3_224_HMAC: MechanismType = MechanismType(CKM_SHA3_224_HMAC);
    pub const SHA3_224_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA3_224_HMAC_GENERAL);
    pub const SHA3_224_KEY_GEN: MechanismType = MechanismType(CKM_SHA3_224_KEY_GEN);
    pub const SHA3_384: MechanismType = MechanismType(CKM_SHA3_384);
    pub const SHA3_384_HMAC: MechanismType = MechanismType(CKM_SHA3_384_HMAC);
    pub const SHA3_384_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA3_384_HMAC_GENERAL);
    pub const SHA3_384_KEY_GEN: MechanismType = MechanismType(CKM_SHA3_384_KEY_GEN);
    pub const SHA3_512: MechanismType = MechanismType(CKM_SHA3_512);
    pub const SHA3_512_HMAC: MechanismType = MechanismType(CKM_SHA3_512_HMAC);
    pub const SHA3_512_HMAC_GENERAL: MechanismType =
        MechanismType(CKM_SHA3_512_HMAC_GENERAL);
    pub const SHA3_512_KEY_GEN: MechanismType = MechanismType(CKM_SHA3_512_KEY_GEN);

    pub const CAST_KEY_GEN: MechanismType = MechanismType(CKM_CAST_KEY_GEN);
    pub const CAST_ECB: MechanismType = MechanismType(CKM_CAST_ECB);
    pub const CAST_CBC: MechanismType = MechanismType(CKM_CAST_CBC);
    pub const CAST_MAC: MechanismType = MechanismType(CKM_CAST_MAC);
    pub const CAST_MAC_GENERAL: MechanismType = MechanismType(CKM_CAST_MAC_GENERAL);
    pub const CAST_CBC_PAD: MechanismType = MechanismType(CKM_CAST_CBC_PAD);
    pub const CAST3_KEY_GEN: MechanismType = MechanismType(CKM_CAST3_KEY_GEN);
    pub const CAST3_ECB: MechanismType = MechanismType(CKM_CAST3_ECB);
    pub const CAST3_CBC: MechanismType = MechanismType(CKM_CAST3_CBC);
    pub const CAST3_MAC: MechanismType = MechanismType(CKM_CAST3_MAC);
    pub const CAST3_MAC_GENERAL: MechanismType = MechanismType(CKM_CAST3_MAC_GENERAL);
    pub const CAST3_CBC_PAD: MechanismType = MechanismType(CKM_CAST3_CBC_PAD);
    pub const CAST128_KEY_GEN: MechanismType = MechanismType(CKM_CAST128_KEY_GEN);
    pub const CAST128_ECB: MechanismType = MechanismType(CKM_CAST128_ECB);
    pub const CAST128_CBC: MechanismType = MechanismType(CKM_CAST128_CBC);
    pub const CAST128_MAC: MechanismType = MechanismType(CKM_CAST128_MAC);
    pub const CAST128_MAC_GENERAL: MechanismType = MechanismType(CKM_CAST128_MAC_GENERAL);
    pub const CAST128_CBC_PAD: MechanismType = MechanismType(CKM_CAST128_CBC_PAD);
    pub const RC5_KEY_GEN: MechanismType = MechanismType(CKM_RC5_KEY_GEN);
    pub const RC5_ECB: MechanismType = MechanismType(CKM_RC5_ECB);
    pub const RC5_CBC: MechanismType = MechanismType(CKM_RC5_CBC);
    pub const RC5_MAC: MechanismType = MechanismType(CKM_RC5_MAC);
    pub const RC5_MAC_GENERAL: MechanismType = MechanismType(CKM_RC5_MAC_GENERAL);
    pub const RC5_CBC_PAD: MechanismType = MechanismType(CKM_RC5_CBC_PAD);
    pub const IDEA_KEY_GEN: MechanismType = MechanismType(CKM_IDEA_KEY_GEN);
    pub const IDEA_ECB: MechanismType = MechanismType(CKM_IDEA_ECB);
    pub const IDEA_CBC: MechanismType = MechanismType(CKM_IDEA_CBC);
    pub const IDEA_MAC: MechanismType = MechanismType(CKM_IDEA_MAC);
    pub const IDEA_MAC_GENERAL: MechanismType = MechanismType(CKM_IDEA_MAC_GENERAL);
    pub const IDEA_CBC_PAD: MechanismType = MechanismType(CKM_IDEA_CBC_PAD);
    pub const GENERIC_SECRET_KEY_GEN: MechanismType =
        MechanismType(CKM_GENERIC_SECRET_KEY_GEN);
    pub const CONCATENATE_BASE_AND_KEY: MechanismType =
        MechanismType(CKM_CONCATENATE_BASE_AND_KEY);
    pub const CONCATENATE_BASE_AND_DATA: MechanismType =
        MechanismType(CKM_CONCATENATE_BASE_AND_DATA);
    pub const CONCATENATE_DATA_AND_BASE: MechanismType =
        MechanismType(CKM_CONCATENATE_DATA_AND_BASE);
    pub const XOR_BASE_AND_DATA: MechanismType = MechanismType(CKM_XOR_BASE_AND_DATA);
    pub const EXTRACT_KEY_FROM_KEY: MechanismType =
        MechanismType(CKM_EXTRACT_KEY_FROM_KEY);
    pub const SSL3_PRE_MASTER_KEY_GEN: MechanismType =
        MechanismType(CKM_SSL3_PRE_MASTER_KEY_GEN);
    pub const SSL3_MASTER_KEY_DERIVE: MechanismType =
        MechanismType(CKM_SSL3_MASTER_KEY_DERIVE);
    pub const SSL3_KEY_AND_MAC_DERIVE: MechanismType =
        MechanismType(CKM_SSL3_KEY_AND_MAC_DERIVE);

    pub const SSL3_MASTER_KEY_DERIVE_DH: MechanismType =
        MechanismType(CKM_SSL3_MASTER_KEY_DERIVE_DH);
    pub const TLS_PRE_MASTER_KEY_GEN: MechanismType =
        MechanismType(CKM_TLS_PRE_MASTER_KEY_GEN);
    pub const TLS_MASTER_KEY_DERIVE: MechanismType =
        MechanismType(CKM_TLS_MASTER_KEY_DERIVE);
    pub const TLS_KEY_AND_MAC_DERIVE: MechanismType =
        MechanismType(CKM_TLS_KEY_AND_MAC_DERIVE);
    pub const TLS_MASTER_KEY_DERIVE_DH: MechanismType =
        MechanismType(CKM_TLS_MASTER_KEY_DERIVE_DH);

    pub const TLS_PRF: MechanismType = MechanismType(CKM_TLS_PRF);

    pub const SSL3_MD5_MAC: MechanismType = MechanismType(CKM_SSL3_MD5_MAC);
    pub const SSL3_SHA1_MAC: MechanismType = MechanismType(CKM_SSL3_SHA1_MAC);
    pub const MD5_KEY_DERIVATION: MechanismType = MechanismType(CKM_MD5_KEY_DERIVATION);
    pub const MD2_KEY_DERIVATION: MechanismType = MechanismType(CKM_MD2_KEY_DERIVATION);
    pub const SHA1_KEY_DERIVATION: MechanismType = MechanismType(CKM_SHA1_KEY_DERIVATION);

    pub const SHA256_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA256_KEY_DERIVATION);
    pub const SHA384_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA384_KEY_DERIVATION);
    pub const SHA512_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA512_KEY_DERIVATION);
    pub const SHA224_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA224_KEY_DERIVATION);
    pub const SHA3_256_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA3_256_KEY_DERIVATION);
    pub const SHA3_224_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA3_224_KEY_DERIVATION);
    pub const SHA3_384_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA3_384_KEY_DERIVATION);
    pub const SHA3_512_KEY_DERIVATION: MechanismType =
        MechanismType(CKM_SHA3_512_KEY_DERIVATION);

    pub const PBE_MD2_DES_CBC: MechanismType = MechanismType(CKM_PBE_MD2_DES_CBC);
    pub const PBE_MD5_DES_CBC: MechanismType = MechanismType(CKM_PBE_MD5_DES_CBC);
    pub const PBE_MD5_CAST_CBC: MechanismType = MechanismType(CKM_PBE_MD5_CAST_CBC);
    pub const PBE_MD5_CAST3_CBC: MechanismType = MechanismType(CKM_PBE_MD5_CAST3_CBC);
    pub const PBE_MD5_CAST128_CBC: MechanismType = MechanismType(CKM_PBE_MD5_CAST128_CBC);
    pub const PBE_SHA1_CAST128_CBC: MechanismType =
        MechanismType(CKM_PBE_SHA1_CAST128_CBC);
    pub const PBE_SHA1_RC4_128: MechanismType = MechanismType(CKM_PBE_SHA1_RC4_128);
    pub const PBE_SHA1_RC4_40: MechanismType = MechanismType(CKM_PBE_SHA1_RC4_40);
    pub const PBE_SHA1_DES3_EDE_CBC: MechanismType =
        MechanismType(CKM_PBE_SHA1_DES3_EDE_CBC);
    pub const PBE_SHA1_DES2_EDE_CBC: MechanismType =
        MechanismType(CKM_PBE_SHA1_DES2_EDE_CBC);
    pub const PBE_SHA1_RC2_128_CBC: MechanismType =
        MechanismType(CKM_PBE_SHA1_RC2_128_CBC);
    pub const PBE_SHA1_RC2_40_CBC: MechanismType = MechanismType(CKM_PBE_SHA1_RC2_40_CBC);

    pub const PKCS5_PBKD2: MechanismType = MechanismType(CKM_PKCS5_PBKD2);

    pub const PBA_SHA1_WITH_SHA1_HMAC: MechanismType =
        MechanismType(CKM_PBA_SHA1_WITH_SHA1_HMAC);

    pub const WTLS_PRE_MASTER_KEY_GEN: MechanismType =
        MechanismType(CKM_WTLS_PRE_MASTER_KEY_GEN);
    pub const WTLS_MASTER_KEY_DERIVE: MechanismType =
        MechanismType(CKM_WTLS_MASTER_KEY_DERIVE);
    pub const WTLS_MASTER_KEY_DERIVE_DH_ECC: MechanismType =
        MechanismType(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC);
    pub const WTLS_PRF: MechanismType = MechanismType(CKM_WTLS_PRF);
    pub const WTLS_SERVER_KEY_AND_MAC_DERIVE: MechanismType =
        MechanismType(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE);
    pub const WTLS_CLIENT_KEY_AND_MAC_DERIVE: MechanismType =
        MechanismType(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE);

    pub const TLS10_MAC_SERVER: MechanismType = MechanismType(CKM_TLS10_MAC_SERVER);
    pub const TLS10_MAC_CLIENT: MechanismType = MechanismType(CKM_TLS10_MAC_CLIENT);
    pub const TLS12_MAC: MechanismType = MechanismType(CKM_TLS12_MAC);
    pub const TLS12_KDF: MechanismType = MechanismType(CKM_TLS12_KDF);
    pub const TLS12_MASTER_KEY_DERIVE: MechanismType =
        MechanismType(CKM_TLS12_MASTER_KEY_DERIVE);
    pub const TLS12_KEY_AND_MAC_DERIVE: MechanismType =
        MechanismType(CKM_TLS12_KEY_AND_MAC_DERIVE);
    pub const TLS12_MASTER_KEY_DERIVE_DH: MechanismType =
        MechanismType(CKM_TLS12_MASTER_KEY_DERIVE_DH);
    pub const TLS12_KEY_SAFE_DERIVE: MechanismType =
        MechanismType(CKM_TLS12_KEY_SAFE_DERIVE);
    pub const TLS_MAC: MechanismType = MechanismType(CKM_TLS_MAC);
    pub const TLS_KDF: MechanismType = MechanismType(CKM_TLS_KDF);

    pub const KEY_WRAP_LYNKS: MechanismType = MechanismType(CKM_KEY_WRAP_LYNKS);
    pub const KEY_WRAP_SET_OAEP: MechanismType = MechanismType(CKM_KEY_WRAP_SET_OAEP);

    pub const CMS_SIG: MechanismType = MechanismType(CKM_CMS_SIG);
    pub const KIP_DERIVE: MechanismType = MechanismType(CKM_KIP_DERIVE);
    pub const KIP_WRAP: MechanismType = MechanismType(CKM_KIP_WRAP);
    pub const KIP_MAC: MechanismType = MechanismType(CKM_KIP_MAC);

    pub const CAMELLIA_KEY_GEN: MechanismType = MechanismType(CKM_CAMELLIA_KEY_GEN);
    pub const CAMELLIA_ECB: MechanismType = MechanismType(CKM_CAMELLIA_ECB);
    pub const CAMELLIA_CBC: MechanismType = MechanismType(CKM_CAMELLIA_CBC);
    pub const CAMELLIA_MAC: MechanismType = MechanismType(CKM_CAMELLIA_MAC);
    pub const CAMELLIA_MAC_GENERAL: MechanismType =
        MechanismType(CKM_CAMELLIA_MAC_GENERAL);
    pub const CAMELLIA_CBC_PAD: MechanismType = MechanismType(CKM_CAMELLIA_CBC_PAD);
    pub const CAMELLIA_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_CAMELLIA_ECB_ENCRYPT_DATA);
    pub const CAMELLIA_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_CAMELLIA_CBC_ENCRYPT_DATA);
    pub const CAMELLIA_CTR: MechanismType = MechanismType(CKM_CAMELLIA_CTR);

    pub const ARIA_KEY_GEN: MechanismType = MechanismType(CKM_ARIA_KEY_GEN);
    pub const ARIA_ECB: MechanismType = MechanismType(CKM_ARIA_ECB);
    pub const ARIA_CBC: MechanismType = MechanismType(CKM_ARIA_CBC);
    pub const ARIA_MAC: MechanismType = MechanismType(CKM_ARIA_MAC);
    pub const ARIA_MAC_GENERAL: MechanismType = MechanismType(CKM_ARIA_MAC_GENERAL);
    pub const ARIA_CBC_PAD: MechanismType = MechanismType(CKM_ARIA_CBC_PAD);
    pub const ARIA_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_ARIA_ECB_ENCRYPT_DATA);
    pub const ARIA_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_ARIA_CBC_ENCRYPT_DATA);

    pub const SEED_KEY_GEN: MechanismType = MechanismType(CKM_SEED_KEY_GEN);
    pub const SEED_ECB: MechanismType = MechanismType(CKM_SEED_ECB);
    pub const SEED_CBC: MechanismType = MechanismType(CKM_SEED_CBC);
    pub const SEED_MAC: MechanismType = MechanismType(CKM_SEED_MAC);
    pub const SEED_MAC_GENERAL: MechanismType = MechanismType(CKM_SEED_MAC_GENERAL);
    pub const SEED_CBC_PAD: MechanismType = MechanismType(CKM_SEED_CBC_PAD);
    pub const SEED_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_SEED_ECB_ENCRYPT_DATA);
    pub const SEED_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_SEED_CBC_ENCRYPT_DATA);

    pub const SKIPJACK_KEY_GEN: MechanismType = MechanismType(CKM_SKIPJACK_KEY_GEN);
    pub const SKIPJACK_ECB64: MechanismType = MechanismType(CKM_SKIPJACK_ECB64);
    pub const SKIPJACK_CBC64: MechanismType = MechanismType(CKM_SKIPJACK_CBC64);
    pub const SKIPJACK_OFB64: MechanismType = MechanismType(CKM_SKIPJACK_OFB64);
    pub const SKIPJACK_CFB64: MechanismType = MechanismType(CKM_SKIPJACK_CFB64);
    pub const SKIPJACK_CFB32: MechanismType = MechanismType(CKM_SKIPJACK_CFB32);
    pub const SKIPJACK_CFB16: MechanismType = MechanismType(CKM_SKIPJACK_CFB16);
    pub const SKIPJACK_CFB8: MechanismType = MechanismType(CKM_SKIPJACK_CFB8);
    pub const SKIPJACK_WRAP: MechanismType = MechanismType(CKM_SKIPJACK_WRAP);
    pub const SKIPJACK_PRIVATE_WRAP: MechanismType =
        MechanismType(CKM_SKIPJACK_PRIVATE_WRAP);
    pub const SKIPJACK_RELAYX: MechanismType = MechanismType(CKM_SKIPJACK_RELAYX);
    pub const KEA_KEY_PAIR_GEN: MechanismType = MechanismType(CKM_KEA_KEY_PAIR_GEN);
    pub const KEA_KEY_DERIVE: MechanismType = MechanismType(CKM_KEA_KEY_DERIVE);
    pub const KEA_DERIVE: MechanismType = MechanismType(CKM_KEA_DERIVE);
    pub const FORTEZZA_TIMESTAMP: MechanismType = MechanismType(CKM_FORTEZZA_TIMESTAMP);
    pub const BATON_KEY_GEN: MechanismType = MechanismType(CKM_BATON_KEY_GEN);
    pub const BATON_ECB128: MechanismType = MechanismType(CKM_BATON_ECB128);
    pub const BATON_ECB96: MechanismType = MechanismType(CKM_BATON_ECB96);
    pub const BATON_CBC128: MechanismType = MechanismType(CKM_BATON_CBC128);
    pub const BATON_COUNTER: MechanismType = MechanismType(CKM_BATON_COUNTER);
    pub const BATON_SHUFFLE: MechanismType = MechanismType(CKM_BATON_SHUFFLE);
    pub const BATON_WRAP: MechanismType = MechanismType(CKM_BATON_WRAP);

    pub const EC_KEY_PAIR_GEN: MechanismType = MechanismType(CKM_EC_KEY_PAIR_GEN);

    pub const ECDSA: MechanismType = MechanismType(CKM_ECDSA);
    pub const ECDSA_SHA1: MechanismType = MechanismType(CKM_ECDSA_SHA1);
    pub const ECDSA_SHA224: MechanismType = MechanismType(CKM_ECDSA_SHA224);
    pub const ECDSA_SHA256: MechanismType = MechanismType(CKM_ECDSA_SHA256);
    pub const ECDSA_SHA384: MechanismType = MechanismType(CKM_ECDSA_SHA384);
    pub const ECDSA_SHA512: MechanismType = MechanismType(CKM_ECDSA_SHA512);

    pub const ECDSA_SHA3_224: MechanismType = MechanismType(CKM_ECDSA_SHA3_224);
    pub const ECDSA_SHA3_256: MechanismType = MechanismType(CKM_ECDSA_SHA3_256);
    pub const ECDSA_SHA3_384: MechanismType = MechanismType(CKM_ECDSA_SHA3_384);
    pub const ECDSA_SHA3_512: MechanismType = MechanismType(CKM_ECDSA_SHA3_512);

    pub const ECDH1_DERIVE: MechanismType = MechanismType(CKM_ECDH1_DERIVE);
    pub const ECDH1_COFACTOR_DERIVE: MechanismType =
        MechanismType(CKM_ECDH1_COFACTOR_DERIVE);
    pub const ECMQV_DERIVE: MechanismType = MechanismType(CKM_ECMQV_DERIVE);

    pub const ECDH_AES_KEY_WRAP: MechanismType = MechanismType(CKM_ECDH_AES_KEY_WRAP);
    pub const RSA_AES_KEY_WRAP: MechanismType = MechanismType(CKM_RSA_AES_KEY_WRAP);

    pub const JUNIPER_KEY_GEN: MechanismType = MechanismType(CKM_JUNIPER_KEY_GEN);
    pub const JUNIPER_ECB128: MechanismType = MechanismType(CKM_JUNIPER_ECB128);
    pub const JUNIPER_CBC128: MechanismType = MechanismType(CKM_JUNIPER_CBC128);
    pub const JUNIPER_COUNTER: MechanismType = MechanismType(CKM_JUNIPER_COUNTER);
    pub const JUNIPER_SHUFFLE: MechanismType = MechanismType(CKM_JUNIPER_SHUFFLE);
    pub const JUNIPER_WRAP: MechanismType = MechanismType(CKM_JUNIPER_WRAP);
    pub const FASTHASH: MechanismType = MechanismType(CKM_FASTHASH);

    pub const AES_KEY_GEN: MechanismType = MechanismType(CKM_AES_KEY_GEN);
    pub const AES_ECB: MechanismType = MechanismType(CKM_AES_ECB);
    pub const AES_CBC: MechanismType = MechanismType(CKM_AES_CBC);
    pub const AES_MAC: MechanismType = MechanismType(CKM_AES_MAC);
    pub const AES_MAC_GENERAL: MechanismType = MechanismType(CKM_AES_MAC_GENERAL);
    pub const AES_CBC_PAD: MechanismType = MechanismType(CKM_AES_CBC_PAD);
    pub const AES_CTR: MechanismType = MechanismType(CKM_AES_CTR);
    pub const AES_GCM: MechanismType = MechanismType(CKM_AES_GCM);
    pub const AES_CCM: MechanismType = MechanismType(CKM_AES_CCM);
    pub const AES_CTS: MechanismType = MechanismType(CKM_AES_CTS);
    pub const AES_CMAC: MechanismType = MechanismType(CKM_AES_CMAC);
    pub const AES_CMAC_GENERAL: MechanismType = MechanismType(CKM_AES_CMAC_GENERAL);

    pub const AES_XCBC_MAC: MechanismType = MechanismType(CKM_AES_XCBC_MAC);
    pub const AES_XCBC_MAC_96: MechanismType = MechanismType(CKM_AES_XCBC_MAC_96);
    pub const AES_GMAC: MechanismType = MechanismType(CKM_AES_GMAC);

    pub const BLOWFISH_KEY_GEN: MechanismType = MechanismType(CKM_BLOWFISH_KEY_GEN);
    pub const BLOWFISH_CBC: MechanismType = MechanismType(CKM_BLOWFISH_CBC);
    pub const TWOFISH_KEY_GEN: MechanismType = MechanismType(CKM_TWOFISH_KEY_GEN);
    pub const TWOFISH_CBC: MechanismType = MechanismType(CKM_TWOFISH_CBC);
    pub const BLOWFISH_CBC_PAD: MechanismType = MechanismType(CKM_BLOWFISH_CBC_PAD);
    pub const TWOFISH_CBC_PAD: MechanismType = MechanismType(CKM_TWOFISH_CBC_PAD);

    pub const DES_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_DES_ECB_ENCRYPT_DATA);
    pub const DES_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_DES_CBC_ENCRYPT_DATA);
    pub const DES3_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_DES3_ECB_ENCRYPT_DATA);
    pub const DES3_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_DES3_CBC_ENCRYPT_DATA);
    pub const AES_ECB_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_AES_ECB_ENCRYPT_DATA);
    pub const AES_CBC_ENCRYPT_DATA: MechanismType =
        MechanismType(CKM_AES_CBC_ENCRYPT_DATA);

    pub const GOSTR3410_KEY_PAIR_GEN: MechanismType =
        MechanismType(CKM_GOSTR3410_KEY_PAIR_GEN);
    pub const GOSTR3410: MechanismType = MechanismType(CKM_GOSTR3410);
    pub const GOSTR3410_WITH_GOSTR3411: MechanismType =
        MechanismType(CKM_GOSTR3410_WITH_GOSTR3411);
    pub const GOSTR3410_KEY_WRAP: MechanismType = MechanismType(CKM_GOSTR3410_KEY_WRAP);
    pub const GOSTR3410_DERIVE: MechanismType = MechanismType(CKM_GOSTR3410_DERIVE);
    pub const GOSTR3411: MechanismType = MechanismType(CKM_GOSTR3411);
    pub const GOSTR3411_HMAC: MechanismType = MechanismType(CKM_GOSTR3411_HMAC);
    pub const GOST28147_KEY_GEN: MechanismType = MechanismType(CKM_GOST28147_KEY_GEN);
    pub const GOST28147_ECB: MechanismType = MechanismType(CKM_GOST28147_ECB);
    pub const GOST28147: MechanismType = MechanismType(CKM_GOST28147);
    pub const GOST28147_MAC: MechanismType = MechanismType(CKM_GOST28147_MAC);
    pub const GOST28147_KEY_WRAP: MechanismType = MechanismType(CKM_GOST28147_KEY_WRAP);

    pub const DSA_PARAMETER_GEN: MechanismType = MechanismType(CKM_DSA_PARAMETER_GEN);
    pub const DH_PKCS_PARAMETER_GEN: MechanismType =
        MechanismType(CKM_DH_PKCS_PARAMETER_GEN);
    pub const X9_42_DH_PARAMETER_GEN: MechanismType =
        MechanismType(CKM_X9_42_DH_PARAMETER_GEN);
    pub const DSA_PROBABLISTIC_PARAMETER_GEN: MechanismType =
        MechanismType(CKM_DSA_PROBABLISTIC_PARAMETER_GEN);
    pub const DSA_SHAWE_TAYLOR_PARAMETER_GEN: MechanismType =
        MechanismType(CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN);

    pub const AES_OFB: MechanismType = MechanismType(CKM_AES_OFB);
    pub const AES_CFB64: MechanismType = MechanismType(CKM_AES_CFB64);
    pub const AES_CFB8: MechanismType = MechanismType(CKM_AES_CFB8);
    pub const AES_CFB128: MechanismType = MechanismType(CKM_AES_CFB128);

    pub const AES_CFB1: MechanismType = MechanismType(CKM_AES_CFB1);
    /// WAS: 0x00001090
    pub const AES_KEY_WRAP: MechanismType = MechanismType(CKM_AES_KEY_WRAP);
    /// WAS: 0x00001091
    pub const AES_KEY_WRAP_PAD: MechanismType = MechanismType(CKM_AES_KEY_WRAP_PAD);

    pub const RSA_PKCS_TPM_1_1: MechanismType = MechanismType(CKM_RSA_PKCS_TPM_1_1);
    pub const RSA_PKCS_OAEP_TPM_1_1: MechanismType =
        MechanismType(CKM_RSA_PKCS_OAEP_TPM_1_1);
}

impl MechanismType {
    pub fn new_vendor_defined(value: CK_ULONG) -> Result<MechanismType> {
        if value >= CKM_VENDOR_DEFINED {
            Ok(MechanismType(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKM_VENDOR_DEFINED
    }
}

impl Deref for MechanismType {
    type Target = CK_MECHANISM_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<MechanismType> for CK_MECHANISM_TYPE {
    fn from(mechanism_type: MechanismType) -> Self {
        *mechanism_type
    }
}

impl std::fmt::Display for MechanismType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            MechanismType::RSA_PKCS_KEY_PAIR_GEN => {
                write!(f, "CKM_RSA_PKCS_KEY_PAIR_GEN")
            }
            MechanismType::RSA_PKCS => write!(f, "CKM_RSA_PKCS"),
            MechanismType::RSA_9796 => write!(f, "CKM_RSA_9796"),
            MechanismType::RSA_X_509 => write!(f, "CKM_RSA_X_509"),

            MechanismType::MD2_RSA_PKCS => write!(f, "CKM_MD2_RSA_PKCS"),
            MechanismType::MD5_RSA_PKCS => write!(f, "CKM_MD5_RSA_PKCS"),
            MechanismType::SHA1_RSA_PKCS => write!(f, "CKM_SHA1_RSA_PKCS"),

            MechanismType::RIPEMD128_RSA_PKCS => write!(f, "CKM_RIPEMD128_RSA_PKCS"),
            MechanismType::RIPEMD160_RSA_PKCS => write!(f, "CKM_RIPEMD160_RSA_PKCS"),
            MechanismType::RSA_PKCS_OAEP => write!(f, "CKM_RSA_PKCS_OAEP"),

            MechanismType::RSA_X9_31_KEY_PAIR_GEN => {
                write!(f, "CKM_RSA_X9_31_KEY_PAIR_GEN")
            }
            MechanismType::RSA_X9_31 => write!(f, "CKM_RSA_X9_31"),
            MechanismType::SHA1_RSA_X9_31 => write!(f, "CKM_SHA1_RSA_X9_31"),
            MechanismType::RSA_PKCS_PSS => write!(f, "CKM_RSA_PKCS_PSS"),
            MechanismType::SHA1_RSA_PKCS_PSS => write!(f, "CKM_SHA1_RSA_PKCS_PSS"),

            MechanismType::DSA_KEY_PAIR_GEN => write!(f, "CKM_DSA_KEY_PAIR_GEN"),
            MechanismType::DSA => write!(f, "CKM_DSA"),
            MechanismType::DSA_SHA1 => write!(f, "CKM_DSA_SHA1"),
            MechanismType::DSA_SHA224 => write!(f, "CKM_DSA_SHA224"),
            MechanismType::DSA_SHA256 => write!(f, "CKM_DSA_SHA256"),
            MechanismType::DSA_SHA384 => write!(f, "CKM_DSA_SHA384"),
            MechanismType::DSA_SHA512 => write!(f, "CKM_DSA_SHA512"),
            MechanismType::DSA_SHA3_224 => write!(f, "CKM_DSA_SHA3_224"),
            MechanismType::DSA_SHA3_256 => write!(f, "CKM_DSA_SHA3_256"),
            MechanismType::DSA_SHA3_384 => write!(f, "CKM_DSA_SHA3_384"),
            MechanismType::DSA_SHA3_512 => write!(f, "CKM_DSA_SHA3_512"),

            MechanismType::DH_PKCS_KEY_PAIR_GEN => write!(f, "CKM_DH_PKCS_KEY_PAIR_GEN"),
            MechanismType::DH_PKCS_DERIVE => write!(f, "CKM_DH_PKCS_DERIVE"),

            MechanismType::X9_42_DH_KEY_PAIR_GEN => {
                write!(f, "CKM_X9_42_DH_KEY_PAIR_GEN")
            }
            MechanismType::X9_42_DH_DERIVE => write!(f, "CKM_X9_42_DH_DERIVE"),
            MechanismType::X9_42_DH_HYBRID_DERIVE => {
                write!(f, "CKM_X9_42_DH_HYBRID_DERIVE")
            }
            MechanismType::X9_42_MQV_DERIVE => write!(f, "CKM_X9_42_MQV_DERIVE"),

            MechanismType::SHA256_RSA_PKCS => write!(f, "CKM_SHA256_RSA_PKCS"),
            MechanismType::SHA384_RSA_PKCS => write!(f, "CKM_SHA384_RSA_PKCS"),
            MechanismType::SHA512_RSA_PKCS => write!(f, "CKM_SHA512_RSA_PKCS"),
            MechanismType::SHA256_RSA_PKCS_PSS => write!(f, "CKM_SHA256_RSA_PKCS_PSS"),
            MechanismType::SHA384_RSA_PKCS_PSS => write!(f, "CKM_SHA384_RSA_PKCS_PSS"),
            MechanismType::SHA512_RSA_PKCS_PSS => write!(f, "CKM_SHA512_RSA_PKCS_PSS"),

            MechanismType::SHA224_RSA_PKCS => write!(f, "CKM_SHA224_RSA_PKCS"),
            MechanismType::SHA224_RSA_PKCS_PSS => write!(f, "CKM_SHA224_RSA_PKCS_PSS"),

            MechanismType::SHA512_224 => write!(f, "CKM_SHA512_224"),
            MechanismType::SHA512_224_HMAC => write!(f, "CKM_SHA512_224_HMAC"),
            MechanismType::SHA512_224_HMAC_GENERAL => {
                write!(f, "CKM_SHA512_224_HMAC_GENERAL")
            }
            MechanismType::SHA512_224_KEY_DERIVATION => {
                write!(f, "CKM_SHA512_224_KEY_DERIVATION")
            }
            MechanismType::SHA512_256 => write!(f, "CKM_SHA512_256"),
            MechanismType::SHA512_256_HMAC => write!(f, "CKM_SHA512_256_HMAC"),
            MechanismType::SHA512_256_HMAC_GENERAL => {
                write!(f, "CKM_SHA512_256_HMAC_GENERAL")
            }
            MechanismType::SHA512_256_KEY_DERIVATION => {
                write!(f, "CKM_SHA512_256_KEY_DERIVATION")
            }

            MechanismType::SHA512_T => write!(f, "CKM_SHA512_T"),
            MechanismType::SHA512_T_HMAC => write!(f, "CKM_SHA512_T_HMAC"),
            MechanismType::SHA512_T_HMAC_GENERAL => {
                write!(f, "CKM_SHA512_T_HMAC_GENERAL")
            }
            MechanismType::SHA512_T_KEY_DERIVATION => {
                write!(f, "CKM_SHA512_T_KEY_DERIVATION")
            }

            MechanismType::SHA3_256_RSA_PKCS => write!(f, "CKM_SHA3_256_RSA_PKCS"),
            MechanismType::SHA3_384_RSA_PKCS => write!(f, "CKM_SHA3_384_RSA_PKCS"),
            MechanismType::SHA3_512_RSA_PKCS => write!(f, "CKM_SHA3_512_RSA_PKCS"),
            MechanismType::SHA3_256_RSA_PKCS_PSS => {
                write!(f, "CKM_SHA3_256_RSA_PKCS_PSS")
            }
            MechanismType::SHA3_384_RSA_PKCS_PSS => {
                write!(f, "CKM_SHA3_384_RSA_PKCS_PSS")
            }
            MechanismType::SHA3_512_RSA_PKCS_PSS => {
                write!(f, "CKM_SHA3_512_RSA_PKCS_PSS")
            }
            MechanismType::SHA3_224_RSA_PKCS => write!(f, "CKM_SHA3_224_RSA_PKCS"),
            MechanismType::SHA3_224_RSA_PKCS_PSS => {
                write!(f, "CKM_SHA3_224_RSA_PKCS_PSS")
            }

            MechanismType::RC2_KEY_GEN => write!(f, "CKM_RC2_KEY_GEN"),
            MechanismType::RC2_ECB => write!(f, "CKM_RC2_ECB"),
            MechanismType::RC2_CBC => write!(f, "CKM_RC2_CBC"),
            MechanismType::RC2_MAC => write!(f, "CKM_RC2_MAC"),

            MechanismType::RC2_MAC_GENERAL => write!(f, "CKM_RC2_MAC_GENERAL"),
            MechanismType::RC2_CBC_PAD => write!(f, "CKM_RC2_CBC_PAD"),

            MechanismType::RC4_KEY_GEN => write!(f, "CKM_RC4_KEY_GEN"),
            MechanismType::RC4 => write!(f, "CKM_RC4"),
            MechanismType::DES_KEY_GEN => write!(f, "CKM_DES_KEY_GEN"),
            MechanismType::DES_ECB => write!(f, "CKM_DES_ECB"),
            MechanismType::DES_CBC => write!(f, "CKM_DES_CBC"),
            MechanismType::DES_MAC => write!(f, "CKM_DES_MAC"),

            MechanismType::DES_MAC_GENERAL => write!(f, "CKM_DES_MAC_GENERAL"),
            MechanismType::DES_CBC_PAD => write!(f, "CKM_DES_CBC_PAD"),

            MechanismType::DES2_KEY_GEN => write!(f, "CKM_DES2_KEY_GEN"),
            MechanismType::DES3_KEY_GEN => write!(f, "CKM_DES3_KEY_GEN"),
            MechanismType::DES3_ECB => write!(f, "CKM_DES3_ECB"),
            MechanismType::DES3_CBC => write!(f, "CKM_DES3_CBC"),
            MechanismType::DES3_MAC => write!(f, "CKM_DES3_MAC"),

            MechanismType::DES3_MAC_GENERAL => write!(f, "CKM_DES3_MAC_GENERAL"),
            MechanismType::DES3_CBC_PAD => write!(f, "CKM_DES3_CBC_PAD"),
            MechanismType::DES3_CMAC_GENERAL => write!(f, "CKM_DES3_CMAC_GENERAL"),
            MechanismType::DES3_CMAC => write!(f, "CKM_DES3_CMAC"),
            MechanismType::CDMF_KEY_GEN => write!(f, "CKM_CDMF_KEY_GEN"),
            MechanismType::CDMF_ECB => write!(f, "CKM_CDMF_ECB"),
            MechanismType::CDMF_CBC => write!(f, "CKM_CDMF_CBC"),
            MechanismType::CDMF_MAC => write!(f, "CKM_CDMF_MAC"),
            MechanismType::CDMF_MAC_GENERAL => write!(f, "CKM_CDMF_MAC_GENERAL"),
            MechanismType::CDMF_CBC_PAD => write!(f, "CKM_CDMF_CBC_PAD"),

            MechanismType::DES_OFB64 => write!(f, "CKM_DES_OFB64"),
            MechanismType::DES_OFB8 => write!(f, "CKM_DES_OFB8"),
            MechanismType::DES_CFB64 => write!(f, "CKM_DES_CFB64"),
            MechanismType::DES_CFB8 => write!(f, "CKM_DES_CFB8"),

            MechanismType::MD2 => write!(f, "CKM_MD2"),

            MechanismType::MD2_HMAC => write!(f, "CKM_MD2_HMAC"),
            MechanismType::MD2_HMAC_GENERAL => write!(f, "CKM_MD2_HMAC_GENERAL"),

            MechanismType::MD5 => write!(f, "CKM_MD5"),

            MechanismType::MD5_HMAC => write!(f, "CKM_MD5_HMAC"),
            MechanismType::MD5_HMAC_GENERAL => write!(f, "CKM_MD5_HMAC_GENERAL"),

            MechanismType::SHA_1 => write!(f, "CKM_SHA_1"),

            MechanismType::SHA_1_HMAC => write!(f, "CKM_SHA_1_HMAC"),
            MechanismType::SHA_1_HMAC_GENERAL => write!(f, "CKM_SHA_1_HMAC_GENERAL"),

            MechanismType::RIPEMD128 => write!(f, "CKM_RIPEMD128"),
            MechanismType::RIPEMD128_HMAC => write!(f, "CKM_RIPEMD128_HMAC"),
            MechanismType::RIPEMD128_HMAC_GENERAL => {
                write!(f, "CKM_RIPEMD128_HMAC_GENERAL")
            }
            MechanismType::RIPEMD160 => write!(f, "CKM_RIPEMD160"),
            MechanismType::RIPEMD160_HMAC => write!(f, "CKM_RIPEMD160_HMAC"),
            MechanismType::RIPEMD160_HMAC_GENERAL => {
                write!(f, "CKM_RIPEMD160_HMAC_GENERAL")
            }

            MechanismType::SHA256 => write!(f, "CKM_SHA256"),
            MechanismType::SHA256_HMAC => write!(f, "CKM_SHA256_HMAC"),
            MechanismType::SHA256_HMAC_GENERAL => write!(f, "CKM_SHA256_HMAC_GENERAL"),
            MechanismType::SHA224 => write!(f, "CKM_SHA224"),
            MechanismType::SHA224_HMAC => write!(f, "CKM_SHA224_HMAC"),
            MechanismType::SHA224_HMAC_GENERAL => write!(f, "CKM_SHA224_HMAC_GENERAL"),
            MechanismType::SHA384 => write!(f, "CKM_SHA384"),
            MechanismType::SHA384_HMAC => write!(f, "CKM_SHA384_HMAC"),
            MechanismType::SHA384_HMAC_GENERAL => write!(f, "CKM_SHA384_HMAC_GENERAL"),
            MechanismType::SHA512 => write!(f, "CKM_SHA512"),
            MechanismType::SHA512_HMAC => write!(f, "CKM_SHA512_HMAC"),
            MechanismType::SHA512_HMAC_GENERAL => write!(f, "CKM_SHA512_HMAC_GENERAL"),
            MechanismType::SECURID_KEY_GEN => write!(f, "CKM_SECURID_KEY_GEN"),
            MechanismType::SECURID => write!(f, "CKM_SECURID"),
            MechanismType::HOTP_KEY_GEN => write!(f, "CKM_HOTP_KEY_GEN"),
            MechanismType::HOTP => write!(f, "CKM_HOTP"),
            MechanismType::ACTI => write!(f, "CKM_ACTI"),
            MechanismType::ACTI_KEY_GEN => write!(f, "CKM_ACTI_KEY_GEN"),

            MechanismType::SHA3_256 => write!(f, "CKM_SHA3_256"),
            MechanismType::SHA3_256_HMAC => write!(f, "CKM_SHA3_256_HMAC"),
            MechanismType::SHA3_256_HMAC_GENERAL => {
                write!(f, "CKM_SHA3_256_HMAC_GENERAL")
            }
            MechanismType::SHA3_256_KEY_GEN => write!(f, "CKM_SHA3_256_KEY_GEN"),
            MechanismType::SHA3_224 => write!(f, "CKM_SHA3_224"),
            MechanismType::SHA3_224_HMAC => write!(f, "CKM_SHA3_224_HMAC"),
            MechanismType::SHA3_224_HMAC_GENERAL => {
                write!(f, "CKM_SHA3_224_HMAC_GENERAL")
            }
            MechanismType::SHA3_224_KEY_GEN => write!(f, "CKM_SHA3_224_KEY_GEN"),
            MechanismType::SHA3_384 => write!(f, "CKM_SHA3_384"),
            MechanismType::SHA3_384_HMAC => write!(f, "CKM_SHA3_384_HMAC"),
            MechanismType::SHA3_384_HMAC_GENERAL => {
                write!(f, "CKM_SHA3_384_HMAC_GENERAL")
            }
            MechanismType::SHA3_384_KEY_GEN => write!(f, "CKM_SHA3_384_KEY_GEN"),
            MechanismType::SHA3_512 => write!(f, "CKM_SHA3_512"),
            MechanismType::SHA3_512_HMAC => write!(f, "CKM_SHA3_512_HMAC"),
            MechanismType::SHA3_512_HMAC_GENERAL => {
                write!(f, "CKM_SHA3_512_HMAC_GENERAL")
            }
            MechanismType::SHA3_512_KEY_GEN => write!(f, "CKM_SHA3_512_KEY_GEN"),

            MechanismType::CAST_KEY_GEN => write!(f, "CKM_CAST_KEY_GEN"),
            MechanismType::CAST_ECB => write!(f, "CKM_CAST_ECB"),
            MechanismType::CAST_CBC => write!(f, "CKM_CAST_CBC"),
            MechanismType::CAST_MAC => write!(f, "CKM_CAST_MAC"),
            MechanismType::CAST_MAC_GENERAL => write!(f, "CKM_CAST_MAC_GENERAL"),
            MechanismType::CAST_CBC_PAD => write!(f, "CKM_CAST_CBC_PAD"),
            MechanismType::CAST3_KEY_GEN => write!(f, "CKM_CAST3_KEY_GEN"),
            MechanismType::CAST3_ECB => write!(f, "CKM_CAST3_ECB"),
            MechanismType::CAST3_CBC => write!(f, "CKM_CAST3_CBC"),
            MechanismType::CAST3_MAC => write!(f, "CKM_CAST3_MAC"),
            MechanismType::CAST3_MAC_GENERAL => write!(f, "CKM_CAST3_MAC_GENERAL"),
            MechanismType::CAST3_CBC_PAD => write!(f, "CKM_CAST3_CBC_PAD"),
            MechanismType::CAST128_KEY_GEN => write!(f, "CKM_CAST128_KEY_GEN"),
            MechanismType::CAST128_ECB => write!(f, "CKM_CAST128_ECB"),
            MechanismType::CAST128_CBC => write!(f, "CKM_CAST128_CBC"),
            MechanismType::CAST128_MAC => write!(f, "CKM_CAST128_MAC"),
            MechanismType::CAST128_MAC_GENERAL => write!(f, "CKM_CAST128_MAC_GENERAL"),
            MechanismType::CAST128_CBC_PAD => write!(f, "CKM_CAST128_CBC_PAD"),
            MechanismType::RC5_KEY_GEN => write!(f, "CKM_RC5_KEY_GEN"),
            MechanismType::RC5_ECB => write!(f, "CKM_RC5_ECB"),
            MechanismType::RC5_CBC => write!(f, "CKM_RC5_CBC"),
            MechanismType::RC5_MAC => write!(f, "CKM_RC5_MAC"),
            MechanismType::RC5_MAC_GENERAL => write!(f, "CKM_RC5_MAC_GENERAL"),
            MechanismType::RC5_CBC_PAD => write!(f, "CKM_RC5_CBC_PAD"),
            MechanismType::IDEA_KEY_GEN => write!(f, "CKM_IDEA_KEY_GEN"),
            MechanismType::IDEA_ECB => write!(f, "CKM_IDEA_ECB"),
            MechanismType::IDEA_CBC => write!(f, "CKM_IDEA_CBC"),
            MechanismType::IDEA_MAC => write!(f, "CKM_IDEA_MAC"),
            MechanismType::IDEA_MAC_GENERAL => write!(f, "CKM_IDEA_MAC_GENERAL"),
            MechanismType::IDEA_CBC_PAD => write!(f, "CKM_IDEA_CBC_PAD"),
            MechanismType::GENERIC_SECRET_KEY_GEN => {
                write!(f, "CKM_GENERIC_SECRET_KEY_GEN")
            }
            MechanismType::CONCATENATE_BASE_AND_KEY => {
                write!(f, "CKM_CONCATENATE_BASE_AND_KEY")
            }
            MechanismType::CONCATENATE_BASE_AND_DATA => {
                write!(f, "CKM_CONCATENATE_BASE_AND_DATA")
            }
            MechanismType::CONCATENATE_DATA_AND_BASE => {
                write!(f, "CKM_CONCATENATE_DATA_AND_BASE")
            }
            MechanismType::XOR_BASE_AND_DATA => write!(f, "CKM_XOR_BASE_AND_DATA"),
            MechanismType::EXTRACT_KEY_FROM_KEY => write!(f, "CKM_EXTRACT_KEY_FROM_KEY"),
            MechanismType::SSL3_PRE_MASTER_KEY_GEN => {
                write!(f, "CKM_SSL3_PRE_MASTER_KEY_GEN")
            }
            MechanismType::SSL3_MASTER_KEY_DERIVE => {
                write!(f, "CKM_SSL3_MASTER_KEY_DERIVE")
            }
            MechanismType::SSL3_KEY_AND_MAC_DERIVE => {
                write!(f, "CKM_SSL3_KEY_AND_MAC_DERIVE")
            }

            MechanismType::SSL3_MASTER_KEY_DERIVE_DH => {
                write!(f, "CKM_SSL3_MASTER_KEY_DERIVE_DH")
            }
            MechanismType::TLS_PRE_MASTER_KEY_GEN => {
                write!(f, "CKM_TLS_PRE_MASTER_KEY_GEN")
            }
            MechanismType::TLS_MASTER_KEY_DERIVE => {
                write!(f, "CKM_TLS_MASTER_KEY_DERIVE")
            }
            MechanismType::TLS_KEY_AND_MAC_DERIVE => {
                write!(f, "CKM_TLS_KEY_AND_MAC_DERIVE")
            }
            MechanismType::TLS_MASTER_KEY_DERIVE_DH => {
                write!(f, "CKM_TLS_MASTER_KEY_DERIVE_DH")
            }

            MechanismType::TLS_PRF => write!(f, "CKM_TLS_PRF"),

            MechanismType::SSL3_MD5_MAC => write!(f, "CKM_SSL3_MD5_MAC"),
            MechanismType::SSL3_SHA1_MAC => write!(f, "CKM_SSL3_SHA1_MAC"),
            MechanismType::MD5_KEY_DERIVATION => write!(f, "CKM_MD5_KEY_DERIVATION"),
            MechanismType::MD2_KEY_DERIVATION => write!(f, "CKM_MD2_KEY_DERIVATION"),
            MechanismType::SHA1_KEY_DERIVATION => write!(f, "CKM_SHA1_KEY_DERIVATION"),

            MechanismType::SHA256_KEY_DERIVATION => {
                write!(f, "CKM_SHA256_KEY_DERIVATION")
            }
            MechanismType::SHA384_KEY_DERIVATION => {
                write!(f, "CKM_SHA384_KEY_DERIVATION")
            }
            MechanismType::SHA512_KEY_DERIVATION => {
                write!(f, "CKM_SHA512_KEY_DERIVATION")
            }
            MechanismType::SHA224_KEY_DERIVATION => {
                write!(f, "CKM_SHA224_KEY_DERIVATION")
            }
            MechanismType::SHA3_256_KEY_DERIVATION => {
                write!(f, "CKM_SHA3_256_KEY_DERIVATION")
            }
            MechanismType::SHA3_224_KEY_DERIVATION => {
                write!(f, "CKM_SHA3_224_KEY_DERIVATION")
            }
            MechanismType::SHA3_384_KEY_DERIVATION => {
                write!(f, "CKM_SHA3_384_KEY_DERIVATION")
            }
            MechanismType::SHA3_512_KEY_DERIVATION => {
                write!(f, "CKM_SHA3_512_KEY_DERIVATION")
            }

            MechanismType::PBE_MD2_DES_CBC => write!(f, "CKM_PBE_MD2_DES_CBC"),
            MechanismType::PBE_MD5_DES_CBC => write!(f, "CKM_PBE_MD5_DES_CBC"),
            MechanismType::PBE_MD5_CAST_CBC => write!(f, "CKM_PBE_MD5_CAST_CBC"),
            MechanismType::PBE_MD5_CAST3_CBC => write!(f, "CKM_PBE_MD5_CAST3_CBC"),
            MechanismType::PBE_MD5_CAST128_CBC => write!(f, "CKM_PBE_MD5_CAST128_CBC"),
            MechanismType::PBE_SHA1_CAST128_CBC => write!(f, "CKM_PBE_SHA1_CAST128_CBC"),
            MechanismType::PBE_SHA1_RC4_128 => write!(f, "CKM_PBE_SHA1_RC4_128"),
            MechanismType::PBE_SHA1_RC4_40 => write!(f, "CKM_PBE_SHA1_RC4_40"),
            MechanismType::PBE_SHA1_DES3_EDE_CBC => {
                write!(f, "CKM_PBE_SHA1_DES3_EDE_CBC")
            }
            MechanismType::PBE_SHA1_DES2_EDE_CBC => {
                write!(f, "CKM_PBE_SHA1_DES2_EDE_CBC")
            }
            MechanismType::PBE_SHA1_RC2_128_CBC => write!(f, "CKM_PBE_SHA1_RC2_128_CBC"),
            MechanismType::PBE_SHA1_RC2_40_CBC => write!(f, "CKM_PBE_SHA1_RC2_40_CBC"),

            MechanismType::PKCS5_PBKD2 => write!(f, "CKM_PKCS5_PBKD2"),

            MechanismType::PBA_SHA1_WITH_SHA1_HMAC => {
                write!(f, "CKM_PBA_SHA1_WITH_SHA1_HMAC")
            }

            MechanismType::WTLS_PRE_MASTER_KEY_GEN => {
                write!(f, "CKM_WTLS_PRE_MASTER_KEY_GEN")
            }
            MechanismType::WTLS_MASTER_KEY_DERIVE => {
                write!(f, "CKM_WTLS_MASTER_KEY_DERIVE")
            }
            MechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC => {
                write!(f, "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC")
            }
            MechanismType::WTLS_PRF => write!(f, "CKM_WTLS_PRF"),
            MechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE => {
                write!(f, "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE")
            }
            MechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE => {
                write!(f, "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE")
            }

            MechanismType::TLS10_MAC_SERVER => write!(f, "CKM_TLS10_MAC_SERVER"),
            MechanismType::TLS10_MAC_CLIENT => write!(f, "CKM_TLS10_MAC_CLIENT"),
            MechanismType::TLS12_MAC => write!(f, "CKM_TLS12_MAC"),
            MechanismType::TLS12_KDF => write!(f, "CKM_TLS12_KDF"),
            MechanismType::TLS12_MASTER_KEY_DERIVE => {
                write!(f, "CKM_TLS12_MASTER_KEY_DERIVE")
            }
            MechanismType::TLS12_KEY_AND_MAC_DERIVE => {
                write!(f, "CKM_TLS12_KEY_AND_MAC_DERIVE")
            }
            MechanismType::TLS12_MASTER_KEY_DERIVE_DH => {
                write!(f, "CKM_TLS12_MASTER_KEY_DERIVE_DH")
            }
            MechanismType::TLS12_KEY_SAFE_DERIVE => {
                write!(f, "CKM_TLS12_KEY_SAFE_DERIVE")
            }
            MechanismType::TLS_MAC => write!(f, "CKM_TLS_MAC"),
            MechanismType::TLS_KDF => write!(f, "CKM_TLS_KDF"),

            MechanismType::KEY_WRAP_LYNKS => write!(f, "CKM_KEY_WRAP_LYNKS"),
            MechanismType::KEY_WRAP_SET_OAEP => write!(f, "CKM_KEY_WRAP_SET_OAEP"),

            MechanismType::CMS_SIG => write!(f, "CKM_CMS_SIG"),
            MechanismType::KIP_DERIVE => write!(f, "CKM_KIP_DERIVE"),
            MechanismType::KIP_WRAP => write!(f, "CKM_KIP_WRAP"),
            MechanismType::KIP_MAC => write!(f, "CKM_KIP_MAC"),

            MechanismType::CAMELLIA_KEY_GEN => write!(f, "CKM_CAMELLIA_KEY_GEN"),
            MechanismType::CAMELLIA_ECB => write!(f, "CKM_CAMELLIA_ECB"),
            MechanismType::CAMELLIA_CBC => write!(f, "CKM_CAMELLIA_CBC"),
            MechanismType::CAMELLIA_MAC => write!(f, "CKM_CAMELLIA_MAC"),
            MechanismType::CAMELLIA_MAC_GENERAL => write!(f, "CKM_CAMELLIA_MAC_GENERAL"),
            MechanismType::CAMELLIA_CBC_PAD => write!(f, "CKM_CAMELLIA_CBC_PAD"),
            MechanismType::CAMELLIA_ECB_ENCRYPT_DATA => {
                write!(f, "CKM_CAMELLIA_ECB_ENCRYPT_DATA")
            }
            MechanismType::CAMELLIA_CBC_ENCRYPT_DATA => {
                write!(f, "CKM_CAMELLIA_CBC_ENCRYPT_DATA")
            }
            MechanismType::CAMELLIA_CTR => write!(f, "CKM_CAMELLIA_CTR"),

            MechanismType::ARIA_KEY_GEN => write!(f, "CKM_ARIA_KEY_GEN"),
            MechanismType::ARIA_ECB => write!(f, "CKM_ARIA_ECB"),
            MechanismType::ARIA_CBC => write!(f, "CKM_ARIA_CBC"),
            MechanismType::ARIA_MAC => write!(f, "CKM_ARIA_MAC"),
            MechanismType::ARIA_MAC_GENERAL => write!(f, "CKM_ARIA_MAC_GENERAL"),
            MechanismType::ARIA_CBC_PAD => write!(f, "CKM_ARIA_CBC_PAD"),
            MechanismType::ARIA_ECB_ENCRYPT_DATA => {
                write!(f, "CKM_ARIA_ECB_ENCRYPT_DATA")
            }
            MechanismType::ARIA_CBC_ENCRYPT_DATA => {
                write!(f, "CKM_ARIA_CBC_ENCRYPT_DATA")
            }

            MechanismType::SEED_KEY_GEN => write!(f, "CKM_SEED_KEY_GEN"),
            MechanismType::SEED_ECB => write!(f, "CKM_SEED_ECB"),
            MechanismType::SEED_CBC => write!(f, "CKM_SEED_CBC"),
            MechanismType::SEED_MAC => write!(f, "CKM_SEED_MAC"),
            MechanismType::SEED_MAC_GENERAL => write!(f, "CKM_SEED_MAC_GENERAL"),
            MechanismType::SEED_CBC_PAD => write!(f, "CKM_SEED_CBC_PAD"),
            MechanismType::SEED_ECB_ENCRYPT_DATA => {
                write!(f, "CKM_SEED_ECB_ENCRYPT_DATA")
            }
            MechanismType::SEED_CBC_ENCRYPT_DATA => {
                write!(f, "CKM_SEED_CBC_ENCRYPT_DATA")
            }

            MechanismType::SKIPJACK_KEY_GEN => write!(f, "CKM_SKIPJACK_KEY_GEN"),
            MechanismType::SKIPJACK_ECB64 => write!(f, "CKM_SKIPJACK_ECB64"),
            MechanismType::SKIPJACK_CBC64 => write!(f, "CKM_SKIPJACK_CBC64"),
            MechanismType::SKIPJACK_OFB64 => write!(f, "CKM_SKIPJACK_OFB64"),
            MechanismType::SKIPJACK_CFB64 => write!(f, "CKM_SKIPJACK_CFB64"),
            MechanismType::SKIPJACK_CFB32 => write!(f, "CKM_SKIPJACK_CFB32"),
            MechanismType::SKIPJACK_CFB16 => write!(f, "CKM_SKIPJACK_CFB16"),
            MechanismType::SKIPJACK_CFB8 => write!(f, "CKM_SKIPJACK_CFB8"),
            MechanismType::SKIPJACK_WRAP => write!(f, "CKM_SKIPJACK_WRAP"),
            MechanismType::SKIPJACK_PRIVATE_WRAP => {
                write!(f, "CKM_SKIPJACK_PRIVATE_WRAP")
            }
            MechanismType::SKIPJACK_RELAYX => write!(f, "CKM_SKIPJACK_RELAYX"),
            MechanismType::KEA_KEY_PAIR_GEN => write!(f, "CKM_KEA_KEY_PAIR_GEN"),
            MechanismType::KEA_KEY_DERIVE => write!(f, "CKM_KEA_KEY_DERIVE"),
            MechanismType::KEA_DERIVE => write!(f, "CKM_KEA_DERIVE"),
            MechanismType::FORTEZZA_TIMESTAMP => write!(f, "CKM_FORTEZZA_TIMESTAMP"),
            MechanismType::BATON_KEY_GEN => write!(f, "CKM_BATON_KEY_GEN"),
            MechanismType::BATON_ECB128 => write!(f, "CKM_BATON_ECB128"),
            MechanismType::BATON_ECB96 => write!(f, "CKM_BATON_ECB96"),
            MechanismType::BATON_CBC128 => write!(f, "CKM_BATON_CBC128"),
            MechanismType::BATON_COUNTER => write!(f, "CKM_BATON_COUNTER"),
            MechanismType::BATON_SHUFFLE => write!(f, "CKM_BATON_SHUFFLE"),
            MechanismType::BATON_WRAP => write!(f, "CKM_BATON_WRAP"),

            MechanismType::EC_KEY_PAIR_GEN => write!(f, "CKM_EC_KEY_PAIR_GEN"),

            MechanismType::ECDSA => write!(f, "CKM_ECDSA"),
            MechanismType::ECDSA_SHA1 => write!(f, "CKM_ECDSA_SHA1"),
            MechanismType::ECDSA_SHA224 => write!(f, "CKM_ECDSA_SHA224"),
            MechanismType::ECDSA_SHA256 => write!(f, "CKM_ECDSA_SHA256"),
            MechanismType::ECDSA_SHA384 => write!(f, "CKM_ECDSA_SHA384"),
            MechanismType::ECDSA_SHA512 => write!(f, "CKM_ECDSA_SHA512"),

            MechanismType::ECDSA_SHA3_224 => write!(f, "CKM_ECDSA_SHA3_224"),
            MechanismType::ECDSA_SHA3_256 => write!(f, "CKM_ECDSA_SHA3_256"),
            MechanismType::ECDSA_SHA3_384 => write!(f, "CKM_ECDSA_SHA3_384"),
            MechanismType::ECDSA_SHA3_512 => write!(f, "CKM_ECDSA_SHA3_512"),

            MechanismType::ECDH1_DERIVE => write!(f, "CKM_ECDH1_DERIVE"),
            MechanismType::ECDH1_COFACTOR_DERIVE => {
                write!(f, "CKM_ECDH1_COFACTOR_DERIVE")
            }
            MechanismType::ECMQV_DERIVE => write!(f, "CKM_ECMQV_DERIVE"),

            MechanismType::ECDH_AES_KEY_WRAP => write!(f, "CKM_ECDH_AES_KEY_WRAP"),
            MechanismType::RSA_AES_KEY_WRAP => write!(f, "CKM_RSA_AES_KEY_WRAP"),

            MechanismType::JUNIPER_KEY_GEN => write!(f, "CKM_JUNIPER_KEY_GEN"),
            MechanismType::JUNIPER_ECB128 => write!(f, "CKM_JUNIPER_ECB128"),
            MechanismType::JUNIPER_CBC128 => write!(f, "CKM_JUNIPER_CBC128"),
            MechanismType::JUNIPER_COUNTER => write!(f, "CKM_JUNIPER_COUNTER"),
            MechanismType::JUNIPER_SHUFFLE => write!(f, "CKM_JUNIPER_SHUFFLE"),
            MechanismType::JUNIPER_WRAP => write!(f, "CKM_JUNIPER_WRAP"),
            MechanismType::FASTHASH => write!(f, "CKM_FASTHASH"),

            MechanismType::AES_KEY_GEN => write!(f, "CKM_AES_KEY_GEN"),
            MechanismType::AES_ECB => write!(f, "CKM_AES_ECB"),
            MechanismType::AES_CBC => write!(f, "CKM_AES_CBC"),
            MechanismType::AES_MAC => write!(f, "CKM_AES_MAC"),
            MechanismType::AES_MAC_GENERAL => write!(f, "CKM_AES_MAC_GENERAL"),
            MechanismType::AES_CBC_PAD => write!(f, "CKM_AES_CBC_PAD"),
            MechanismType::AES_CTR => write!(f, "CKM_AES_CTR"),
            MechanismType::AES_GCM => write!(f, "CKM_AES_GCM"),
            MechanismType::AES_CCM => write!(f, "CKM_AES_CCM"),
            MechanismType::AES_CTS => write!(f, "CKM_AES_CTS"),
            MechanismType::AES_CMAC => write!(f, "CKM_AES_CMAC"),
            MechanismType::AES_CMAC_GENERAL => write!(f, "CKM_AES_CMAC_GENERAL"),

            MechanismType::AES_XCBC_MAC => write!(f, "CKM_AES_XCBC_MAC"),
            MechanismType::AES_XCBC_MAC_96 => write!(f, "CKM_AES_XCBC_MAC_96"),
            MechanismType::AES_GMAC => write!(f, "CKM_AES_GMAC"),

            MechanismType::BLOWFISH_KEY_GEN => write!(f, "CKM_BLOWFISH_KEY_GEN"),
            MechanismType::BLOWFISH_CBC => write!(f, "CKM_BLOWFISH_CBC"),
            MechanismType::TWOFISH_KEY_GEN => write!(f, "CKM_TWOFISH_KEY_GEN"),
            MechanismType::TWOFISH_CBC => write!(f, "CKM_TWOFISH_CBC"),
            MechanismType::BLOWFISH_CBC_PAD => write!(f, "CKM_BLOWFISH_CBC_PAD"),
            MechanismType::TWOFISH_CBC_PAD => write!(f, "CKM_TWOFISH_CBC_PAD"),

            MechanismType::DES_ECB_ENCRYPT_DATA => write!(f, "CKM_DES_ECB_ENCRYPT_DATA"),
            MechanismType::DES_CBC_ENCRYPT_DATA => write!(f, "CKM_DES_CBC_ENCRYPT_DATA"),
            MechanismType::DES3_ECB_ENCRYPT_DATA => {
                write!(f, "CKM_DES3_ECB_ENCRYPT_DATA")
            }
            MechanismType::DES3_CBC_ENCRYPT_DATA => {
                write!(f, "CKM_DES3_CBC_ENCRYPT_DATA")
            }
            MechanismType::AES_ECB_ENCRYPT_DATA => write!(f, "CKM_AES_ECB_ENCRYPT_DATA"),
            MechanismType::AES_CBC_ENCRYPT_DATA => write!(f, "CKM_AES_CBC_ENCRYPT_DATA"),

            MechanismType::GOSTR3410_KEY_PAIR_GEN => {
                write!(f, "CKM_GOSTR3410_KEY_PAIR_GEN")
            }
            MechanismType::GOSTR3410 => write!(f, "CKM_GOSTR3410"),
            MechanismType::GOSTR3410_WITH_GOSTR3411 => {
                write!(f, "CKM_GOSTR3410_WITH_GOSTR3411")
            }
            MechanismType::GOSTR3410_KEY_WRAP => write!(f, "CKM_GOSTR3410_KEY_WRAP"),
            MechanismType::GOSTR3410_DERIVE => write!(f, "CKM_GOSTR3410_DERIVE"),
            MechanismType::GOSTR3411 => write!(f, "CKM_GOSTR3411"),
            MechanismType::GOSTR3411_HMAC => write!(f, "CKM_GOSTR3411_HMAC"),
            MechanismType::GOST28147_KEY_GEN => write!(f, "CKM_GOST28147_KEY_GEN"),
            MechanismType::GOST28147_ECB => write!(f, "CKM_GOST28147_ECB"),
            MechanismType::GOST28147 => write!(f, "CKM_GOST28147"),
            MechanismType::GOST28147_MAC => write!(f, "CKM_GOST28147_MAC"),
            MechanismType::GOST28147_KEY_WRAP => write!(f, "CKM_GOST28147_KEY_WRAP"),

            MechanismType::DSA_PARAMETER_GEN => write!(f, "CKM_DSA_PARAMETER_GEN"),
            MechanismType::DH_PKCS_PARAMETER_GEN => {
                write!(f, "CKM_DH_PKCS_PARAMETER_GEN")
            }
            MechanismType::X9_42_DH_PARAMETER_GEN => {
                write!(f, "CKM_X9_42_DH_PARAMETER_GEN")
            }
            MechanismType::DSA_PROBABLISTIC_PARAMETER_GEN => {
                write!(f, "CKM_DSA_PROBABLISTIC_PARAMETER_GEN")
            }
            MechanismType::DSA_SHAWE_TAYLOR_PARAMETER_GEN => {
                write!(f, "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN")
            }

            MechanismType::AES_OFB => write!(f, "CKM_AES_OFB"),
            MechanismType::AES_CFB64 => write!(f, "CKM_AES_CFB64"),
            MechanismType::AES_CFB8 => write!(f, "CKM_AES_CFB8"),
            MechanismType::AES_CFB128 => write!(f, "CKM_AES_CFB128"),

            MechanismType::AES_CFB1 => write!(f, "CKM_AES_CFB1"),
            // WAS: 0x00001090
            MechanismType::AES_KEY_WRAP => write!(f, "CKM_AES_KEY_WRAP"),
            // WAS: 0x00001091
            MechanismType::AES_KEY_WRAP_PAD => write!(f, "CKM_AES_KEY_WRAP_PAD"),

            MechanismType::RSA_PKCS_TPM_1_1 => write!(f, "CKM_RSA_PKCS_TPM_1_1"),
            MechanismType::RSA_PKCS_OAEP_TPM_1_1 => {
                write!(f, "CKM_RSA_PKCS_OAEP_TPM_1_1")
            }

            _ if self.is_vendor_defined() => {
                write!(f, "CKM_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown mechanism type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_MECHANISM_TYPE> for MechanismType {
    type Error = Error;

    fn try_from(mechanism_type: CK_MECHANISM_TYPE) -> Result<Self> {
        match mechanism_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => Ok(MechanismType::RSA_PKCS_KEY_PAIR_GEN),
            CKM_RSA_PKCS => Ok(MechanismType::RSA_PKCS),
            CKM_RSA_9796 => Ok(MechanismType::RSA_9796),
            CKM_RSA_X_509 => Ok(MechanismType::RSA_X_509),

            CKM_MD2_RSA_PKCS => Ok(MechanismType::MD2_RSA_PKCS),
            CKM_MD5_RSA_PKCS => Ok(MechanismType::MD5_RSA_PKCS),
            CKM_SHA1_RSA_PKCS => Ok(MechanismType::SHA1_RSA_PKCS),

            CKM_RIPEMD128_RSA_PKCS => Ok(MechanismType::RIPEMD128_RSA_PKCS),
            CKM_RIPEMD160_RSA_PKCS => Ok(MechanismType::RIPEMD160_RSA_PKCS),
            CKM_RSA_PKCS_OAEP => Ok(MechanismType::RSA_PKCS_OAEP),

            CKM_RSA_X9_31_KEY_PAIR_GEN => Ok(MechanismType::RSA_X9_31_KEY_PAIR_GEN),
            CKM_RSA_X9_31 => Ok(MechanismType::RSA_X9_31),
            CKM_SHA1_RSA_X9_31 => Ok(MechanismType::SHA1_RSA_X9_31),
            CKM_RSA_PKCS_PSS => Ok(MechanismType::RSA_PKCS_PSS),
            CKM_SHA1_RSA_PKCS_PSS => Ok(MechanismType::SHA1_RSA_PKCS_PSS),

            CKM_DSA_KEY_PAIR_GEN => Ok(MechanismType::DSA_KEY_PAIR_GEN),
            CKM_DSA => Ok(MechanismType::DSA),
            CKM_DSA_SHA1 => Ok(MechanismType::DSA_SHA1),
            CKM_DSA_SHA224 => Ok(MechanismType::DSA_SHA224),
            CKM_DSA_SHA256 => Ok(MechanismType::DSA_SHA256),
            CKM_DSA_SHA384 => Ok(MechanismType::DSA_SHA384),
            CKM_DSA_SHA512 => Ok(MechanismType::DSA_SHA512),
            CKM_DSA_SHA3_224 => Ok(MechanismType::DSA_SHA3_224),
            CKM_DSA_SHA3_256 => Ok(MechanismType::DSA_SHA3_256),
            CKM_DSA_SHA3_384 => Ok(MechanismType::DSA_SHA3_384),
            CKM_DSA_SHA3_512 => Ok(MechanismType::DSA_SHA3_512),

            CKM_DH_PKCS_KEY_PAIR_GEN => Ok(MechanismType::DH_PKCS_KEY_PAIR_GEN),
            CKM_DH_PKCS_DERIVE => Ok(MechanismType::DH_PKCS_DERIVE),

            CKM_X9_42_DH_KEY_PAIR_GEN => Ok(MechanismType::X9_42_DH_KEY_PAIR_GEN),
            CKM_X9_42_DH_DERIVE => Ok(MechanismType::X9_42_DH_DERIVE),
            CKM_X9_42_DH_HYBRID_DERIVE => Ok(MechanismType::X9_42_DH_HYBRID_DERIVE),
            CKM_X9_42_MQV_DERIVE => Ok(MechanismType::X9_42_MQV_DERIVE),

            CKM_SHA256_RSA_PKCS => Ok(MechanismType::SHA256_RSA_PKCS),
            CKM_SHA384_RSA_PKCS => Ok(MechanismType::SHA384_RSA_PKCS),
            CKM_SHA512_RSA_PKCS => Ok(MechanismType::SHA512_RSA_PKCS),
            CKM_SHA256_RSA_PKCS_PSS => Ok(MechanismType::SHA256_RSA_PKCS_PSS),
            CKM_SHA384_RSA_PKCS_PSS => Ok(MechanismType::SHA384_RSA_PKCS_PSS),
            CKM_SHA512_RSA_PKCS_PSS => Ok(MechanismType::SHA512_RSA_PKCS_PSS),

            CKM_SHA224_RSA_PKCS => Ok(MechanismType::SHA224_RSA_PKCS),
            CKM_SHA224_RSA_PKCS_PSS => Ok(MechanismType::SHA224_RSA_PKCS_PSS),

            CKM_SHA512_224 => Ok(MechanismType::SHA512_224),
            CKM_SHA512_224_HMAC => Ok(MechanismType::SHA512_224_HMAC),
            CKM_SHA512_224_HMAC_GENERAL => Ok(MechanismType::SHA512_224_HMAC_GENERAL),
            CKM_SHA512_224_KEY_DERIVATION => Ok(MechanismType::SHA512_224_KEY_DERIVATION),
            CKM_SHA512_256 => Ok(MechanismType::SHA512_256),
            CKM_SHA512_256_HMAC => Ok(MechanismType::SHA512_256_HMAC),
            CKM_SHA512_256_HMAC_GENERAL => Ok(MechanismType::SHA512_256_HMAC_GENERAL),
            CKM_SHA512_256_KEY_DERIVATION => Ok(MechanismType::SHA512_256_KEY_DERIVATION),

            CKM_SHA512_T => Ok(MechanismType::SHA512_T),
            CKM_SHA512_T_HMAC => Ok(MechanismType::SHA512_T_HMAC),
            CKM_SHA512_T_HMAC_GENERAL => Ok(MechanismType::SHA512_T_HMAC_GENERAL),
            CKM_SHA512_T_KEY_DERIVATION => Ok(MechanismType::SHA512_T_KEY_DERIVATION),

            CKM_SHA3_256_RSA_PKCS => Ok(MechanismType::SHA3_256_RSA_PKCS),
            CKM_SHA3_384_RSA_PKCS => Ok(MechanismType::SHA3_384_RSA_PKCS),
            CKM_SHA3_512_RSA_PKCS => Ok(MechanismType::SHA3_512_RSA_PKCS),
            CKM_SHA3_256_RSA_PKCS_PSS => Ok(MechanismType::SHA3_256_RSA_PKCS_PSS),
            CKM_SHA3_384_RSA_PKCS_PSS => Ok(MechanismType::SHA3_384_RSA_PKCS_PSS),
            CKM_SHA3_512_RSA_PKCS_PSS => Ok(MechanismType::SHA3_512_RSA_PKCS_PSS),
            CKM_SHA3_224_RSA_PKCS => Ok(MechanismType::SHA3_224_RSA_PKCS),
            CKM_SHA3_224_RSA_PKCS_PSS => Ok(MechanismType::SHA3_224_RSA_PKCS_PSS),

            CKM_RC2_KEY_GEN => Ok(MechanismType::RC2_KEY_GEN),
            CKM_RC2_ECB => Ok(MechanismType::RC2_ECB),
            CKM_RC2_CBC => Ok(MechanismType::RC2_CBC),
            CKM_RC2_MAC => Ok(MechanismType::RC2_MAC),

            CKM_RC2_MAC_GENERAL => Ok(MechanismType::RC2_MAC_GENERAL),
            CKM_RC2_CBC_PAD => Ok(MechanismType::RC2_CBC_PAD),

            CKM_RC4_KEY_GEN => Ok(MechanismType::RC4_KEY_GEN),
            CKM_RC4 => Ok(MechanismType::RC4),
            CKM_DES_KEY_GEN => Ok(MechanismType::DES_KEY_GEN),
            CKM_DES_ECB => Ok(MechanismType::DES_ECB),
            CKM_DES_CBC => Ok(MechanismType::DES_CBC),
            CKM_DES_MAC => Ok(MechanismType::DES_MAC),

            CKM_DES_MAC_GENERAL => Ok(MechanismType::DES_MAC_GENERAL),
            CKM_DES_CBC_PAD => Ok(MechanismType::DES_CBC_PAD),

            CKM_DES2_KEY_GEN => Ok(MechanismType::DES2_KEY_GEN),
            CKM_DES3_KEY_GEN => Ok(MechanismType::DES3_KEY_GEN),
            CKM_DES3_ECB => Ok(MechanismType::DES3_ECB),
            CKM_DES3_CBC => Ok(MechanismType::DES3_CBC),
            CKM_DES3_MAC => Ok(MechanismType::DES3_MAC),

            CKM_DES3_MAC_GENERAL => Ok(MechanismType::DES3_MAC_GENERAL),
            CKM_DES3_CBC_PAD => Ok(MechanismType::DES3_CBC_PAD),
            CKM_DES3_CMAC_GENERAL => Ok(MechanismType::DES3_CMAC_GENERAL),
            CKM_DES3_CMAC => Ok(MechanismType::DES3_CMAC),
            CKM_CDMF_KEY_GEN => Ok(MechanismType::CDMF_KEY_GEN),
            CKM_CDMF_ECB => Ok(MechanismType::CDMF_ECB),
            CKM_CDMF_CBC => Ok(MechanismType::CDMF_CBC),
            CKM_CDMF_MAC => Ok(MechanismType::CDMF_MAC),
            CKM_CDMF_MAC_GENERAL => Ok(MechanismType::CDMF_MAC_GENERAL),
            CKM_CDMF_CBC_PAD => Ok(MechanismType::CDMF_CBC_PAD),

            CKM_DES_OFB64 => Ok(MechanismType::DES_OFB64),
            CKM_DES_OFB8 => Ok(MechanismType::DES_OFB8),
            CKM_DES_CFB64 => Ok(MechanismType::DES_CFB64),
            CKM_DES_CFB8 => Ok(MechanismType::DES_CFB8),

            CKM_MD2 => Ok(MechanismType::MD2),

            CKM_MD2_HMAC => Ok(MechanismType::MD2_HMAC),
            CKM_MD2_HMAC_GENERAL => Ok(MechanismType::MD2_HMAC_GENERAL),

            CKM_MD5 => Ok(MechanismType::MD5),

            CKM_MD5_HMAC => Ok(MechanismType::MD5_HMAC),
            CKM_MD5_HMAC_GENERAL => Ok(MechanismType::MD5_HMAC_GENERAL),

            CKM_SHA_1 => Ok(MechanismType::SHA_1),

            CKM_SHA_1_HMAC => Ok(MechanismType::SHA_1_HMAC),
            CKM_SHA_1_HMAC_GENERAL => Ok(MechanismType::SHA_1_HMAC_GENERAL),

            CKM_RIPEMD128 => Ok(MechanismType::RIPEMD128),
            CKM_RIPEMD128_HMAC => Ok(MechanismType::RIPEMD128_HMAC),
            CKM_RIPEMD128_HMAC_GENERAL => Ok(MechanismType::RIPEMD128_HMAC_GENERAL),
            CKM_RIPEMD160 => Ok(MechanismType::RIPEMD160),
            CKM_RIPEMD160_HMAC => Ok(MechanismType::RIPEMD160_HMAC),
            CKM_RIPEMD160_HMAC_GENERAL => Ok(MechanismType::RIPEMD160_HMAC_GENERAL),

            CKM_SHA256 => Ok(MechanismType::SHA256),
            CKM_SHA256_HMAC => Ok(MechanismType::SHA256_HMAC),
            CKM_SHA256_HMAC_GENERAL => Ok(MechanismType::SHA256_HMAC_GENERAL),
            CKM_SHA224 => Ok(MechanismType::SHA224),
            CKM_SHA224_HMAC => Ok(MechanismType::SHA224_HMAC),
            CKM_SHA224_HMAC_GENERAL => Ok(MechanismType::SHA224_HMAC_GENERAL),
            CKM_SHA384 => Ok(MechanismType::SHA384),
            CKM_SHA384_HMAC => Ok(MechanismType::SHA384_HMAC),
            CKM_SHA384_HMAC_GENERAL => Ok(MechanismType::SHA384_HMAC_GENERAL),
            CKM_SHA512 => Ok(MechanismType::SHA512),
            CKM_SHA512_HMAC => Ok(MechanismType::SHA512_HMAC),
            CKM_SHA512_HMAC_GENERAL => Ok(MechanismType::SHA512_HMAC_GENERAL),
            CKM_SECURID_KEY_GEN => Ok(MechanismType::SECURID_KEY_GEN),
            CKM_SECURID => Ok(MechanismType::SECURID),
            CKM_HOTP_KEY_GEN => Ok(MechanismType::HOTP_KEY_GEN),
            CKM_HOTP => Ok(MechanismType::HOTP),
            CKM_ACTI => Ok(MechanismType::ACTI),
            CKM_ACTI_KEY_GEN => Ok(MechanismType::ACTI_KEY_GEN),

            CKM_SHA3_256 => Ok(MechanismType::SHA3_256),
            CKM_SHA3_256_HMAC => Ok(MechanismType::SHA3_256_HMAC),
            CKM_SHA3_256_HMAC_GENERAL => Ok(MechanismType::SHA3_256_HMAC_GENERAL),
            CKM_SHA3_256_KEY_GEN => Ok(MechanismType::SHA3_256_KEY_GEN),
            CKM_SHA3_224 => Ok(MechanismType::SHA3_224),
            CKM_SHA3_224_HMAC => Ok(MechanismType::SHA3_224_HMAC),
            CKM_SHA3_224_HMAC_GENERAL => Ok(MechanismType::SHA3_224_HMAC_GENERAL),
            CKM_SHA3_224_KEY_GEN => Ok(MechanismType::SHA3_224_KEY_GEN),
            CKM_SHA3_384 => Ok(MechanismType::SHA3_384),
            CKM_SHA3_384_HMAC => Ok(MechanismType::SHA3_384_HMAC),
            CKM_SHA3_384_HMAC_GENERAL => Ok(MechanismType::SHA3_384_HMAC_GENERAL),
            CKM_SHA3_384_KEY_GEN => Ok(MechanismType::SHA3_384_KEY_GEN),
            CKM_SHA3_512 => Ok(MechanismType::SHA3_512),
            CKM_SHA3_512_HMAC => Ok(MechanismType::SHA3_512_HMAC),
            CKM_SHA3_512_HMAC_GENERAL => Ok(MechanismType::SHA3_512_HMAC_GENERAL),
            CKM_SHA3_512_KEY_GEN => Ok(MechanismType::SHA3_512_KEY_GEN),

            CKM_CAST_KEY_GEN => Ok(MechanismType::CAST_KEY_GEN),
            CKM_CAST_ECB => Ok(MechanismType::CAST_ECB),
            CKM_CAST_CBC => Ok(MechanismType::CAST_CBC),
            CKM_CAST_MAC => Ok(MechanismType::CAST_MAC),
            CKM_CAST_MAC_GENERAL => Ok(MechanismType::CAST_MAC_GENERAL),
            CKM_CAST_CBC_PAD => Ok(MechanismType::CAST_CBC_PAD),
            CKM_CAST3_KEY_GEN => Ok(MechanismType::CAST3_KEY_GEN),
            CKM_CAST3_ECB => Ok(MechanismType::CAST3_ECB),
            CKM_CAST3_CBC => Ok(MechanismType::CAST3_CBC),
            CKM_CAST3_MAC => Ok(MechanismType::CAST3_MAC),
            CKM_CAST3_MAC_GENERAL => Ok(MechanismType::CAST3_MAC_GENERAL),
            CKM_CAST3_CBC_PAD => Ok(MechanismType::CAST3_CBC_PAD),
            CKM_CAST128_KEY_GEN => Ok(MechanismType::CAST128_KEY_GEN),
            CKM_CAST128_ECB => Ok(MechanismType::CAST128_ECB),
            CKM_CAST128_CBC => Ok(MechanismType::CAST128_CBC),
            CKM_CAST128_MAC => Ok(MechanismType::CAST128_MAC),
            CKM_CAST128_MAC_GENERAL => Ok(MechanismType::CAST128_MAC_GENERAL),
            CKM_CAST128_CBC_PAD => Ok(MechanismType::CAST128_CBC_PAD),
            CKM_RC5_KEY_GEN => Ok(MechanismType::RC5_KEY_GEN),
            CKM_RC5_ECB => Ok(MechanismType::RC5_ECB),
            CKM_RC5_CBC => Ok(MechanismType::RC5_CBC),
            CKM_RC5_MAC => Ok(MechanismType::RC5_MAC),
            CKM_RC5_MAC_GENERAL => Ok(MechanismType::RC5_MAC_GENERAL),
            CKM_RC5_CBC_PAD => Ok(MechanismType::RC5_CBC_PAD),
            CKM_IDEA_KEY_GEN => Ok(MechanismType::IDEA_KEY_GEN),
            CKM_IDEA_ECB => Ok(MechanismType::IDEA_ECB),
            CKM_IDEA_CBC => Ok(MechanismType::IDEA_CBC),
            CKM_IDEA_MAC => Ok(MechanismType::IDEA_MAC),
            CKM_IDEA_MAC_GENERAL => Ok(MechanismType::IDEA_MAC_GENERAL),
            CKM_IDEA_CBC_PAD => Ok(MechanismType::IDEA_CBC_PAD),
            CKM_GENERIC_SECRET_KEY_GEN => Ok(MechanismType::GENERIC_SECRET_KEY_GEN),
            CKM_CONCATENATE_BASE_AND_KEY => Ok(MechanismType::CONCATENATE_BASE_AND_KEY),
            CKM_CONCATENATE_BASE_AND_DATA => Ok(MechanismType::CONCATENATE_BASE_AND_DATA),
            CKM_CONCATENATE_DATA_AND_BASE => Ok(MechanismType::CONCATENATE_DATA_AND_BASE),
            CKM_XOR_BASE_AND_DATA => Ok(MechanismType::XOR_BASE_AND_DATA),
            CKM_EXTRACT_KEY_FROM_KEY => Ok(MechanismType::EXTRACT_KEY_FROM_KEY),
            CKM_SSL3_PRE_MASTER_KEY_GEN => Ok(MechanismType::SSL3_PRE_MASTER_KEY_GEN),
            CKM_SSL3_MASTER_KEY_DERIVE => Ok(MechanismType::SSL3_MASTER_KEY_DERIVE),
            CKM_SSL3_KEY_AND_MAC_DERIVE => Ok(MechanismType::SSL3_KEY_AND_MAC_DERIVE),

            CKM_SSL3_MASTER_KEY_DERIVE_DH => Ok(MechanismType::SSL3_MASTER_KEY_DERIVE_DH),
            CKM_TLS_PRE_MASTER_KEY_GEN => Ok(MechanismType::TLS_PRE_MASTER_KEY_GEN),
            CKM_TLS_MASTER_KEY_DERIVE => Ok(MechanismType::TLS_MASTER_KEY_DERIVE),
            CKM_TLS_KEY_AND_MAC_DERIVE => Ok(MechanismType::TLS_KEY_AND_MAC_DERIVE),
            CKM_TLS_MASTER_KEY_DERIVE_DH => Ok(MechanismType::TLS_MASTER_KEY_DERIVE_DH),

            CKM_TLS_PRF => Ok(MechanismType::TLS_PRF),

            CKM_SSL3_MD5_MAC => Ok(MechanismType::SSL3_MD5_MAC),
            CKM_SSL3_SHA1_MAC => Ok(MechanismType::SSL3_SHA1_MAC),
            CKM_MD5_KEY_DERIVATION => Ok(MechanismType::MD5_KEY_DERIVATION),
            CKM_MD2_KEY_DERIVATION => Ok(MechanismType::MD2_KEY_DERIVATION),
            CKM_SHA1_KEY_DERIVATION => Ok(MechanismType::SHA1_KEY_DERIVATION),

            CKM_SHA256_KEY_DERIVATION => Ok(MechanismType::SHA256_KEY_DERIVATION),
            CKM_SHA384_KEY_DERIVATION => Ok(MechanismType::SHA384_KEY_DERIVATION),
            CKM_SHA512_KEY_DERIVATION => Ok(MechanismType::SHA512_KEY_DERIVATION),
            CKM_SHA224_KEY_DERIVATION => Ok(MechanismType::SHA224_KEY_DERIVATION),
            CKM_SHA3_256_KEY_DERIVATION => Ok(MechanismType::SHA3_256_KEY_DERIVATION),
            CKM_SHA3_224_KEY_DERIVATION => Ok(MechanismType::SHA3_224_KEY_DERIVATION),
            CKM_SHA3_384_KEY_DERIVATION => Ok(MechanismType::SHA3_384_KEY_DERIVATION),
            CKM_SHA3_512_KEY_DERIVATION => Ok(MechanismType::SHA3_512_KEY_DERIVATION),

            CKM_PBE_MD2_DES_CBC => Ok(MechanismType::PBE_MD2_DES_CBC),
            CKM_PBE_MD5_DES_CBC => Ok(MechanismType::PBE_MD5_DES_CBC),
            CKM_PBE_MD5_CAST_CBC => Ok(MechanismType::PBE_MD5_CAST_CBC),
            CKM_PBE_MD5_CAST3_CBC => Ok(MechanismType::PBE_MD5_CAST3_CBC),
            CKM_PBE_MD5_CAST128_CBC => Ok(MechanismType::PBE_MD5_CAST128_CBC),
            CKM_PBE_SHA1_CAST128_CBC => Ok(MechanismType::PBE_SHA1_CAST128_CBC),
            CKM_PBE_SHA1_RC4_128 => Ok(MechanismType::PBE_SHA1_RC4_128),
            CKM_PBE_SHA1_RC4_40 => Ok(MechanismType::PBE_SHA1_RC4_40),
            CKM_PBE_SHA1_DES3_EDE_CBC => Ok(MechanismType::PBE_SHA1_DES3_EDE_CBC),
            CKM_PBE_SHA1_DES2_EDE_CBC => Ok(MechanismType::PBE_SHA1_DES2_EDE_CBC),
            CKM_PBE_SHA1_RC2_128_CBC => Ok(MechanismType::PBE_SHA1_RC2_128_CBC),
            CKM_PBE_SHA1_RC2_40_CBC => Ok(MechanismType::PBE_SHA1_RC2_40_CBC),

            CKM_PKCS5_PBKD2 => Ok(MechanismType::PKCS5_PBKD2),

            CKM_PBA_SHA1_WITH_SHA1_HMAC => Ok(MechanismType::PBA_SHA1_WITH_SHA1_HMAC),

            CKM_WTLS_PRE_MASTER_KEY_GEN => Ok(MechanismType::WTLS_PRE_MASTER_KEY_GEN),
            CKM_WTLS_MASTER_KEY_DERIVE => Ok(MechanismType::WTLS_MASTER_KEY_DERIVE),
            CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC => {
                Ok(MechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC)
            }
            CKM_WTLS_PRF => Ok(MechanismType::WTLS_PRF),
            CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE => {
                Ok(MechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE)
            }
            CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE => {
                Ok(MechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE)
            }

            CKM_TLS10_MAC_SERVER => Ok(MechanismType::TLS10_MAC_SERVER),
            CKM_TLS10_MAC_CLIENT => Ok(MechanismType::TLS10_MAC_CLIENT),
            CKM_TLS12_MAC => Ok(MechanismType::TLS12_MAC),
            CKM_TLS12_KDF => Ok(MechanismType::TLS12_KDF),
            CKM_TLS12_MASTER_KEY_DERIVE => Ok(MechanismType::TLS12_MASTER_KEY_DERIVE),
            CKM_TLS12_KEY_AND_MAC_DERIVE => Ok(MechanismType::TLS12_KEY_AND_MAC_DERIVE),
            CKM_TLS12_MASTER_KEY_DERIVE_DH => {
                Ok(MechanismType::TLS12_MASTER_KEY_DERIVE_DH)
            }
            CKM_TLS12_KEY_SAFE_DERIVE => Ok(MechanismType::TLS12_KEY_SAFE_DERIVE),
            CKM_TLS_MAC => Ok(MechanismType::TLS_MAC),
            CKM_TLS_KDF => Ok(MechanismType::TLS_KDF),

            CKM_KEY_WRAP_LYNKS => Ok(MechanismType::KEY_WRAP_LYNKS),
            CKM_KEY_WRAP_SET_OAEP => Ok(MechanismType::KEY_WRAP_SET_OAEP),

            CKM_CMS_SIG => Ok(MechanismType::CMS_SIG),
            CKM_KIP_DERIVE => Ok(MechanismType::KIP_DERIVE),
            CKM_KIP_WRAP => Ok(MechanismType::KIP_WRAP),
            CKM_KIP_MAC => Ok(MechanismType::KIP_MAC),

            CKM_CAMELLIA_KEY_GEN => Ok(MechanismType::CAMELLIA_KEY_GEN),
            CKM_CAMELLIA_ECB => Ok(MechanismType::CAMELLIA_ECB),
            CKM_CAMELLIA_CBC => Ok(MechanismType::CAMELLIA_CBC),
            CKM_CAMELLIA_MAC => Ok(MechanismType::CAMELLIA_MAC),
            CKM_CAMELLIA_MAC_GENERAL => Ok(MechanismType::CAMELLIA_MAC_GENERAL),
            CKM_CAMELLIA_CBC_PAD => Ok(MechanismType::CAMELLIA_CBC_PAD),
            CKM_CAMELLIA_ECB_ENCRYPT_DATA => Ok(MechanismType::CAMELLIA_ECB_ENCRYPT_DATA),
            CKM_CAMELLIA_CBC_ENCRYPT_DATA => Ok(MechanismType::CAMELLIA_CBC_ENCRYPT_DATA),
            CKM_CAMELLIA_CTR => Ok(MechanismType::CAMELLIA_CTR),

            CKM_ARIA_KEY_GEN => Ok(MechanismType::ARIA_KEY_GEN),
            CKM_ARIA_ECB => Ok(MechanismType::ARIA_ECB),
            CKM_ARIA_CBC => Ok(MechanismType::ARIA_CBC),
            CKM_ARIA_MAC => Ok(MechanismType::ARIA_MAC),
            CKM_ARIA_MAC_GENERAL => Ok(MechanismType::ARIA_MAC_GENERAL),
            CKM_ARIA_CBC_PAD => Ok(MechanismType::ARIA_CBC_PAD),
            CKM_ARIA_ECB_ENCRYPT_DATA => Ok(MechanismType::ARIA_ECB_ENCRYPT_DATA),
            CKM_ARIA_CBC_ENCRYPT_DATA => Ok(MechanismType::ARIA_CBC_ENCRYPT_DATA),

            CKM_SEED_KEY_GEN => Ok(MechanismType::SEED_KEY_GEN),
            CKM_SEED_ECB => Ok(MechanismType::SEED_ECB),
            CKM_SEED_CBC => Ok(MechanismType::SEED_CBC),
            CKM_SEED_MAC => Ok(MechanismType::SEED_MAC),
            CKM_SEED_MAC_GENERAL => Ok(MechanismType::SEED_MAC_GENERAL),
            CKM_SEED_CBC_PAD => Ok(MechanismType::SEED_CBC_PAD),
            CKM_SEED_ECB_ENCRYPT_DATA => Ok(MechanismType::SEED_ECB_ENCRYPT_DATA),
            CKM_SEED_CBC_ENCRYPT_DATA => Ok(MechanismType::SEED_CBC_ENCRYPT_DATA),

            CKM_SKIPJACK_KEY_GEN => Ok(MechanismType::SKIPJACK_KEY_GEN),
            CKM_SKIPJACK_ECB64 => Ok(MechanismType::SKIPJACK_ECB64),
            CKM_SKIPJACK_CBC64 => Ok(MechanismType::SKIPJACK_CBC64),
            CKM_SKIPJACK_OFB64 => Ok(MechanismType::SKIPJACK_OFB64),
            CKM_SKIPJACK_CFB64 => Ok(MechanismType::SKIPJACK_CFB64),
            CKM_SKIPJACK_CFB32 => Ok(MechanismType::SKIPJACK_CFB32),
            CKM_SKIPJACK_CFB16 => Ok(MechanismType::SKIPJACK_CFB16),
            CKM_SKIPJACK_CFB8 => Ok(MechanismType::SKIPJACK_CFB8),
            CKM_SKIPJACK_WRAP => Ok(MechanismType::SKIPJACK_WRAP),
            CKM_SKIPJACK_PRIVATE_WRAP => Ok(MechanismType::SKIPJACK_PRIVATE_WRAP),
            CKM_SKIPJACK_RELAYX => Ok(MechanismType::SKIPJACK_RELAYX),
            CKM_KEA_KEY_PAIR_GEN => Ok(MechanismType::KEA_KEY_PAIR_GEN),
            CKM_KEA_KEY_DERIVE => Ok(MechanismType::KEA_KEY_DERIVE),
            CKM_KEA_DERIVE => Ok(MechanismType::KEA_DERIVE),
            CKM_FORTEZZA_TIMESTAMP => Ok(MechanismType::FORTEZZA_TIMESTAMP),
            CKM_BATON_KEY_GEN => Ok(MechanismType::BATON_KEY_GEN),
            CKM_BATON_ECB128 => Ok(MechanismType::BATON_ECB128),
            CKM_BATON_ECB96 => Ok(MechanismType::BATON_ECB96),
            CKM_BATON_CBC128 => Ok(MechanismType::BATON_CBC128),
            CKM_BATON_COUNTER => Ok(MechanismType::BATON_COUNTER),
            CKM_BATON_SHUFFLE => Ok(MechanismType::BATON_SHUFFLE),
            CKM_BATON_WRAP => Ok(MechanismType::BATON_WRAP),

            CKM_EC_KEY_PAIR_GEN => Ok(MechanismType::EC_KEY_PAIR_GEN),

            CKM_ECDSA => Ok(MechanismType::ECDSA),
            CKM_ECDSA_SHA1 => Ok(MechanismType::ECDSA_SHA1),
            CKM_ECDSA_SHA224 => Ok(MechanismType::ECDSA_SHA224),
            CKM_ECDSA_SHA256 => Ok(MechanismType::ECDSA_SHA256),
            CKM_ECDSA_SHA384 => Ok(MechanismType::ECDSA_SHA384),
            CKM_ECDSA_SHA512 => Ok(MechanismType::ECDSA_SHA512),

            CKM_ECDSA_SHA3_224 => Ok(MechanismType::ECDSA_SHA3_224),
            CKM_ECDSA_SHA3_256 => Ok(MechanismType::ECDSA_SHA3_256),
            CKM_ECDSA_SHA3_384 => Ok(MechanismType::ECDSA_SHA3_384),
            CKM_ECDSA_SHA3_512 => Ok(MechanismType::ECDSA_SHA3_512),

            CKM_ECDH1_DERIVE => Ok(MechanismType::ECDH1_DERIVE),
            CKM_ECDH1_COFACTOR_DERIVE => Ok(MechanismType::ECDH1_COFACTOR_DERIVE),
            CKM_ECMQV_DERIVE => Ok(MechanismType::ECMQV_DERIVE),

            CKM_ECDH_AES_KEY_WRAP => Ok(MechanismType::ECDH_AES_KEY_WRAP),
            CKM_RSA_AES_KEY_WRAP => Ok(MechanismType::RSA_AES_KEY_WRAP),

            CKM_JUNIPER_KEY_GEN => Ok(MechanismType::JUNIPER_KEY_GEN),
            CKM_JUNIPER_ECB128 => Ok(MechanismType::JUNIPER_ECB128),
            CKM_JUNIPER_CBC128 => Ok(MechanismType::JUNIPER_CBC128),
            CKM_JUNIPER_COUNTER => Ok(MechanismType::JUNIPER_COUNTER),
            CKM_JUNIPER_SHUFFLE => Ok(MechanismType::JUNIPER_SHUFFLE),
            CKM_JUNIPER_WRAP => Ok(MechanismType::JUNIPER_WRAP),
            CKM_FASTHASH => Ok(MechanismType::FASTHASH),

            CKM_AES_KEY_GEN => Ok(MechanismType::AES_KEY_GEN),
            CKM_AES_ECB => Ok(MechanismType::AES_ECB),
            CKM_AES_CBC => Ok(MechanismType::AES_CBC),
            CKM_AES_MAC => Ok(MechanismType::AES_MAC),
            CKM_AES_MAC_GENERAL => Ok(MechanismType::AES_MAC_GENERAL),
            CKM_AES_CBC_PAD => Ok(MechanismType::AES_CBC_PAD),
            CKM_AES_CTR => Ok(MechanismType::AES_CTR),
            CKM_AES_GCM => Ok(MechanismType::AES_GCM),
            CKM_AES_CCM => Ok(MechanismType::AES_CCM),
            CKM_AES_CTS => Ok(MechanismType::AES_CTS),
            CKM_AES_CMAC => Ok(MechanismType::AES_CMAC),
            CKM_AES_CMAC_GENERAL => Ok(MechanismType::AES_CMAC_GENERAL),

            CKM_AES_XCBC_MAC => Ok(MechanismType::AES_XCBC_MAC),
            CKM_AES_XCBC_MAC_96 => Ok(MechanismType::AES_XCBC_MAC_96),
            CKM_AES_GMAC => Ok(MechanismType::AES_GMAC),

            CKM_BLOWFISH_KEY_GEN => Ok(MechanismType::BLOWFISH_KEY_GEN),
            CKM_BLOWFISH_CBC => Ok(MechanismType::BLOWFISH_CBC),
            CKM_TWOFISH_KEY_GEN => Ok(MechanismType::TWOFISH_KEY_GEN),
            CKM_TWOFISH_CBC => Ok(MechanismType::TWOFISH_CBC),
            CKM_BLOWFISH_CBC_PAD => Ok(MechanismType::BLOWFISH_CBC_PAD),
            CKM_TWOFISH_CBC_PAD => Ok(MechanismType::TWOFISH_CBC_PAD),

            CKM_DES_ECB_ENCRYPT_DATA => Ok(MechanismType::DES_ECB_ENCRYPT_DATA),
            CKM_DES_CBC_ENCRYPT_DATA => Ok(MechanismType::DES_CBC_ENCRYPT_DATA),
            CKM_DES3_ECB_ENCRYPT_DATA => Ok(MechanismType::DES3_ECB_ENCRYPT_DATA),
            CKM_DES3_CBC_ENCRYPT_DATA => Ok(MechanismType::DES3_CBC_ENCRYPT_DATA),
            CKM_AES_ECB_ENCRYPT_DATA => Ok(MechanismType::AES_ECB_ENCRYPT_DATA),
            CKM_AES_CBC_ENCRYPT_DATA => Ok(MechanismType::AES_CBC_ENCRYPT_DATA),

            CKM_GOSTR3410_KEY_PAIR_GEN => Ok(MechanismType::GOSTR3410_KEY_PAIR_GEN),
            CKM_GOSTR3410 => Ok(MechanismType::GOSTR3410),
            CKM_GOSTR3410_WITH_GOSTR3411 => Ok(MechanismType::GOSTR3410_WITH_GOSTR3411),
            CKM_GOSTR3410_KEY_WRAP => Ok(MechanismType::GOSTR3410_KEY_WRAP),
            CKM_GOSTR3410_DERIVE => Ok(MechanismType::GOSTR3410_DERIVE),
            CKM_GOSTR3411 => Ok(MechanismType::GOSTR3411),
            CKM_GOSTR3411_HMAC => Ok(MechanismType::GOSTR3411_HMAC),
            CKM_GOST28147_KEY_GEN => Ok(MechanismType::GOST28147_KEY_GEN),
            CKM_GOST28147_ECB => Ok(MechanismType::GOST28147_ECB),
            CKM_GOST28147 => Ok(MechanismType::GOST28147),
            CKM_GOST28147_MAC => Ok(MechanismType::GOST28147_MAC),
            CKM_GOST28147_KEY_WRAP => Ok(MechanismType::GOST28147_KEY_WRAP),

            CKM_DSA_PARAMETER_GEN => Ok(MechanismType::DSA_PARAMETER_GEN),
            CKM_DH_PKCS_PARAMETER_GEN => Ok(MechanismType::DH_PKCS_PARAMETER_GEN),
            CKM_X9_42_DH_PARAMETER_GEN => Ok(MechanismType::X9_42_DH_PARAMETER_GEN),
            CKM_DSA_PROBABLISTIC_PARAMETER_GEN => {
                Ok(MechanismType::DSA_PROBABLISTIC_PARAMETER_GEN)
            }
            CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN => {
                Ok(MechanismType::DSA_SHAWE_TAYLOR_PARAMETER_GEN)
            }

            CKM_AES_OFB => Ok(MechanismType::AES_OFB),
            CKM_AES_CFB64 => Ok(MechanismType::AES_CFB64),
            CKM_AES_CFB8 => Ok(MechanismType::AES_CFB8),
            CKM_AES_CFB128 => Ok(MechanismType::AES_CFB128),

            CKM_AES_CFB1 => Ok(MechanismType::AES_CFB1),
            // WAS: 0x00001090
            CKM_AES_KEY_WRAP => Ok(MechanismType::AES_KEY_WRAP),
            // WAS: 0x00001091
            CKM_AES_KEY_WRAP_PAD => Ok(MechanismType::AES_KEY_WRAP_PAD),

            CKM_RSA_PKCS_TPM_1_1 => Ok(MechanismType::RSA_PKCS_TPM_1_1),
            CKM_RSA_PKCS_OAEP_TPM_1_1 => Ok(MechanismType::RSA_PKCS_OAEP_TPM_1_1),

            CKM_VENDOR_DEFINED..=CK_MECHANISM_TYPE::MAX => {
                Ok(MechanismType(mechanism_type))
            }
            _ => Err(Error::NotSupported),
        }
    }
}

/// Specifies a particular mechanism and any parameters it requires.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Mechanism<'a> {
    RsaPkcsKeyPairGen,
    RsaPkcs,
    Rsa9796,
    RsaX509,

    Md2RsaPkcs,
    Md5RsaPkcs,
    Sha1RsaPkcs,

    Ripemd128RsaPkcs,
    Ripemd160RsaPkcs,
    // RsaPkcsOaep, // CK_RSA_PKCS_OAEP_PARAMS_T
    RsaX9_31KeyPairGen,
    RsaX9_31,
    Sha1RsaX9_31,
    RsaPkcsPss(RsaPkcsPssParams),
    Sha1RsaPkcsPss(RsaPkcsPssParams),
    DsaKeyPairGen,
    Dsa,
    DsaSha1,
    DsaSha224,
    DsaSha256,
    DsaSha384,
    DsaSha512,

    DhPkcsKeyPairGen,
    /// This is a mechanism for key derivation based on Diffie-Hellman
    /// key agreement, as defined in PKCS #3.
    /// This is what PKCS #3 calls "phase II".
    ///
    /// It has a parameter, which is the public value of the other party
    /// in the key agreement protocol, represented as a Cryptoki "Big integer"
    /// (i.e., a sequence of bytes, most-significant byte first).
    DhPkcsDerive(Vec<Byte>), // BIG_INTEGER_T

    X9_42DhKeyPairGen,
    X9_42DhDerive(X92_42Dh1DeriveParams<'a>), // CK_X9_42_DH1_DERIVE_PARAMS_T
    // X9_42DhHybridDerive, // CK_X9_42_DH2_DERIVE_PARAMS_T
    // X9_42MqvDerive, // CK_X9_42_MQV_DERIVE_PARAMS_T
    Sha256RsaPkcs,
    Sha384RsaPkcs,
    Sha512RsaPkcs,
    Sha256RsaPkcsPss(RsaPkcsPssParams),
    Sha384RsaPkcsPss(RsaPkcsPssParams),
    Sha512RsaPkcsPss(RsaPkcsPssParams),
    Sha224RsaPkcs,
    Sha224RsaPkcsPss(RsaPkcsPssParams),
    Sha512_224,
    Sha512_224Hmac,
    Sha512_224HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    // Sha512_224KeyDerivation, // UNDEFINED_T
    Sha512_256,
    Sha512_256Hmac,
    Sha512_256HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    // Sha512_256KeyDerivation, // UNDEFINED_T
    Sha512T(Ulong),            // CK_MAC_GENERAL_PARAMS
    Sha512THmac(Ulong),        // CK_MAC_GENERAL_PARAMS
    Sha512THmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    // sha512TKeyDerivation, // UNDEFINED_T
    Rc2KeyGen,
    Rc2Ecb(Ulong), // CK_RC2_PARAMS
    // Rc2Cbc, // CK_RC2_CBC_PARAMS_T
    Rc2Mac(Ulong), // CK_RC2_PARAMS

    // Rc2MacGeneral, // CK_RC2_MAC_GENERAL_PARAMS_T
    // Rc2CbcPad, // CK_RC2_CBC_PARAMS_T
    Rc4KeyGen,
    Rc4,
    DesKeyGen,
    DesEcb,
    /// It has a parameter, an initialization vector for this mode.
    DesCbc([u8; 8]),
    DesMac,

    DesMacGeneral(Ulong),
    /// It has a parameter, an initialization vector for this mode.
    DesCbcPad([u8; 8]),

    Des2KeyGen,
    Des3KeyGen,
    Des3Ecb,
    /// It has a parameter, an initialization vector for this mode.
    Des3Cbc([u8; 8]),
    Des3Mac,

    Des3MacGeneral(Ulong),
    /// It has a parameter, an initialization vector for this mode.
    Des3CbcPad([u8; 8]),
    Des3CmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    Des3Cmac,
    // CdmfKeyGen, // UNDEFINED_T
    // CdmfEcb, // UNDEFINED_T
    // CdmfCbc, // UNDEFINED_T
    // CdmfMac, // UNDEFINED_T
    // CdmfMacGeneral, // UNDEFINED_T
    // CdmfCbcPad, // UNDEFINED_T
    /// It has a parameter, an initialization vector for this mode.
    DesOfb64([u8; 8]),
    /// It has a parameter, an initialization vector for this mode.
    DesOfb8([u8; 8]),
    /// It has a parameter, an initialization vector for this mode.
    DesCfb64([u8; 8]),
    /// It has a parameter, an initialization vector for this mode.
    DesCfb8([u8; 8]),

    Md2,

    Md2Hmac,
    Md2HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS

    Md5,

    Md5Hmac,
    Md5HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS

    Sha1,

    Sha1Hmac,
    Sha1HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS

    Ripemd128,
    Ripemd128Hmac,
    Ripemd128HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    Ripemd160,
    Ripemd160Hmac,
    Ripemd160HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS

    Sha256,
    Sha256Hmac,
    Sha256HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    Sha224,
    Sha224Hmac,
    Sha224HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    Sha384,
    Sha384Hmac,
    Sha384HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    Sha512,
    Sha512Hmac,
    Sha512HmacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    SecuridKeyGen,
    // Securid, // CK_OTP_PARAMS_T
    HotpKeyGen,
    // Hotp, // CK_OTP_PARAMS_T
    // Acti, // CK_OTP_PARAMS_T
    ActiKeyGen,

    // CastKeyGen, // UNDEFINED_T
    // CastEcb, // UNDEFINED_T
    // CastCbc, // UNDEFINED_T
    // CastMac, // UNDEFINED_T
    // CastMacGeneral, // UNDEFINED_T
    // CastCbcPad, // UNDEFINED_T
    // Cast3KeyGen, // UNDEFINED_T
    // Cast3Ecb, // UNDEFINED_T
    // Cast3Cbc, // UNDEFINED_T
    // Cast3Mac, // UNDEFINED_T
    // Cast3MacGeneral, // UNDEFINED_T
    // Cast3CbcPad, // UNDEFINED_T
    // Cast128KeyGen, // UNDEFINED_T
    // Cast128Ecb, // UNDEFINED_T
    // Cast128Cbc, // UNDEFINED_T
    // Cast128Mac, // UNDEFINED_T
    // Cast128MacGeneral, // UNDEFINED_T
    // Cast128CbcPad, // UNDEFINED_T
    Rc5KeyGen,
    // Rc5Ecb, // CK_RC5_PARAMS_T
    // Rc5Cbc, // CK_RC5_CBC_PARAMS_T
    // Rc5Mac, // CK_RC5_PARAMS_T
    // Rc5MacGeneral, // CK_RC5_MAC_GENERAL_PARAMS_T
    // Rc5CbcPad, // CK_RC5_CBC_PARAMS_T
    // IdeaKeyGen, // UNDEFINED_T
    // IdeaEcb, // UNDEFINED_T
    // IdeaCbc, // UNDEFINED_T
    // IdeaMac, // UNDEFINED_T
    // IdeaMacGeneral, // UNDEFINED_T
    // IdeaCbcPad, // UNDEFINED_T
    GenericSecretKeyGen,
    ConcatenateBaseAndKey(ObjectHandle),
    // ConcatenateBaseAndData, // CK_KEY_DERIVATION_STRING_DATA_T
    // ConcatenateDataAndBase, // CK_KEY_DERIVATION_STRING_DATA_T
    // XorBaseAndData, // CK_KEY_DERIVATION_STRING_DATA_T
    ExtractKeyFromKey(Ulong), // CK_EXTRACT_PARAMS
    // Ssl3PreMasterKeyGen, // CK_VERSION_T
    // Ssl3MasterKeyDerive, // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
    // Ssl3KeyAndMacDerive, // CK_SSL3_KEY_MAT_PARAMS_T

    // Ssl3MasterKeyDeriveDh, // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
    // TlsPreMasterKeyGen, // UNDEFINED_T
    // TlsMasterKeyDerive, // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T
    // TlsKeyAndMacDerive, // CK_SSL3_KEY_MAT_PARAMS_T
    // TlsMasterKeyDeriveDh, // CK_SSL3_MASTER_KEY_DERIVE_PARAMS_T

    // TlsPrf, // CK_TLS_MAC_PARAMS_T
    Ssl3Md5Mac(Ulong),  // CK_MAC_GENERAL_PARAMS
    Ssl3Sha1Mac(Ulong), // CK_MAC_GENERAL_PARAMS
    // Md5KeyDerivation, // UNDEFINED_T
    // Md2KeyDerivation, // UNDEFINED_T
    // Sha1KeyDerivation, // UNDEFINED_T

    // Sha256KeyDerivation, // UNDEFINED_T
    // Sha384KeyDerivation, // UNDEFINED_T
    // Sha512KeyDerivation, // UNDEFINED_T
    // Sha224KeyDerivation, // UNDEFINED_T

    // PbeMd2DesCbc, // UNDEFINED_T
    // PbeMd5DesCbc, // UNDEFINED_T
    // PbeMd5CastCbc, // UNDEFINED_T
    // PbeMd5Cast3Cbc, // UNDEFINED_T
    // PbeMd5Cast128Cbc, // UNDEFINED_T
    // PbeSha1Cast128Cbc, // UNDEFINED_T
    // PbeSha1Rc4_128, // UNDEFINED_T
    // PbeSha1Rc4_40, // UNDEFINED_T
    // PbeSha1Des3EdeCbc, // CK_PBE_PARAMS_T
    // PbeSha1Des2EdeCbc, // CK_PBE_PARAMS_T
    // PbeSha1Rc2_128Cbc, // UNDEFINED_T
    // PbeSha1Rc2_40Cbc, // UNDEFINED_T

    // Pkcs5Pbkd2, // CK_PKCS5_PBKD2_PARAMS_T

    // PbaSha1WithSha1Hmac, // CK_PBE_PARAMS_T
    WtlsPreMasterKeyGen(Byte),
    // WtlsMasterKeyDerive, // UNDEFINED_T, ? CK_WTLS_MASTER_KEY_DERIVE_PARAMS or CK_WTLS_RANDOM_DATA ?
    // WtlsMasterKeyDeriveDhEcc, // CK_WTLS_MASTER_KEY_DERIVE_PARAMS
    // WtlsPrf, // CK_WTLS_PRF_PARAMS_T
    // WtlsServerKeyAndMacDerive, // UNDEFINED_T
    // WtlsClientKeyAndMacDerive, // UNDEFINED_T

    // Tls10MacServer, // UNDEFINED_T
    // Tls10MacClient, // UNDEFINED_T
    // Tls12Mac, // UNDEFINED_T
    // Tls12Kdf, // UNDEFINED_T
    // Tls12MasterKeyDerive, // CK_TLS12_MASTER_KEY_DERIVE_PARAMS_T
    // Tls12KeyAndMacDerive, // CK_TLS12_KEY_MAT_PARAMS_T
    // Tls12MasterKeyDeriveDh, // CK_TLS12_MASTER_KEY_DERIVE_DH_T
    // Tls12KeySafeDerive, // UNDEFINED_T
    // TlsMac, // CK_TLS_MAC_PARAMS_T
    // TlsKdf, // CK_TLS_KDF_PARAMS_T

    // KeyWrapLynks, // UNDEFINED_T
    // KeyWrapSetOaep, // UNDEFINED_T

    // CmsSig, // CK_CMS_SIG_PARAMS_T
    // KipDerive, // CK_KIP_PARAMS_T
    // KipWrap, // CK_KIP_PARAMS_T
    // KipMac, // CK_KIP_PARAMS_T
    CamelliaKeyGen,
    CamelliaEcb,
    /// Camellia-CBC, denoted CKM_CAMELLIA_CBC, is a mechanism for single-
    /// and multiple-part encryption and decryption; key wrapping; and
    /// key unwrapping, based on Camellia and cipher-block chaining mode.
    CamelliaCbc([u8; 16]),
    /// Camellia-MAC, denoted by CKM_CAMELLIA_MAC, is a special case of
    /// the general-length Camellia-MAC mechanism. Camellia-MAC always
    /// produces and verifies MACs that are half the block size in length.
    CamelliaMac,
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
    CamelliaMacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    /// Camellia-CBC with PKCS padding, denoted CKM_CAMELLIA_CBC_PAD,
    /// is a mechanism for single- and multiple-part encryption and decryption;
    /// key wrapping; and key unwrapping, based on Camellia;
    /// cipher-block chaining mode; and the block cipher padding method
    /// detailed in PKCS #7.
    CamelliaCbcPad([u8; 16]),
    // CamelliaEcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // CamelliaCbcEncryptData, // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_T
    // CamelliaCtr, // UNDEFINED_T
    AriaKeyGen,
    AriaEcb,
    /// ARIA-CBC, denoted CKM_ARIA_CBC, is a mechanism for single- and
    /// multiple-part encryption and decryption; key wrapping; and
    /// key unwrapping, based on ARIA and cipher-block chaining mode.
    AriaCbc([u8; 16]),
    AriaMac,
    AriaMacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    /// ARIA-CBC with PKCS padding, denoted CKM_ARIA_CBC_PAD, is a mechanism
    /// for single- and multiple-part encryption and decryption; key wrapping;
    /// and key unwrapping, based on ARIA; cipher-block chaining mode;
    /// and the block cipher padding method detailed in PKCS #7.
    AriaCbcPad([u8; 16]),
    // AriaEcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // AriaCbcEncryptData, // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_T
    SeedKeyGen,
    SeedEcb,
    /// SEED-CBC, denoted CKM_SEED_CBC, is a mechanism for single- and
    /// multiple-part encryption and decryption; key wrapping; and
    /// key unwrapping, based on SEED and cipher-block chaining mode.
    SeedCbc([u8; 16]),
    SeedMac,
    SeedMacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    /// SEED-CBC with PKCS padding, denoted CKM_SEED_CBC_PAD, is a mechanism
    /// for single- and multiple-part encryption and decryption; key wrapping;
    /// and key unwrapping, based on SEED; cipher-block chaining mode;
    /// and the block cipher padding method detailed in PKCS #7.
    SeedCbcPad([u8; 16]),
    // SeedEcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // SeedCbcEncryptData, // CK_CBC_ENCRYPT_DATA_PARAMS_T
    SkipjackKeyGen,
    /// SKIPJACK-ECB64, denoted CKM_SKIPJACK_ECB64, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 64-bit electronic codebook mode as defined in FIPS PUB 185.
    SkipjackEcb64([u8; 24]),
    /// SKIPJACK-CBC64, denoted CKM_SKIPJACK_CBC64, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 64-bit cipher-block chaining mode as defined in FIPS PUB 185.
    SkipjackCbc64([u8; 24]),
    /// SKIPJACK-OFB64, denoted CKM_SKIPJACK_OFB64, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 64-bit output feedback mode as defined in FIPS PUB 185.
    SkipjackOfb64([u8; 24]),
    /// SKIPJACK-CFB64, denoted CKM_SKIPJACK_CFB64, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 64-bit cipher feedback mode as defined in FIPS PUB 185.
    SkipjackCfb64([u8; 24]),
    /// SKIPJACK-CFB32, denoted CKM_SKIPJACK_CFB32, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 32-bit cipher feedback mode as defined in FIPS PUB 185.
    SkipjackCfb32([u8; 24]),
    /// SKIPJACK-CFB16, denoted CKM_SKIPJACK_CFB16, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 16-bit cipher feedback mode as defined in FIPS PUB 185.
    SkipjackCfb16([u8; 24]),
    /// SKIPJACK-CFB8, denoted CKM_SKIPJACK_CFB8, is a mechanism
    /// for single- and multiple-part encryption and decryption with SKIPJACK
    /// in 8-bit cipher feedback mode as defined in FIPS PUB 185.
    SkipjackCfb8([u8; 24]),
    SkipjackWrap,
    // SkipjackPrivateWrap, // CK_SKIPJACK_PRIVATE_WRAP_PARAMS_T
    // SkipjackRelayx, // CK_SKIPJACK_RELAYX_PARAMS_T
    KeaKeyPairGen,
    // KeaKeyDerive, // UNDEFINED_T
    // KeaDerive, // CK_KEA_DERIVE_PARAMS_T
    FortezzaTimestamp,
    BatonKeyGen,
    /// BATON-ECB128, denoted CKM_BATON_ECB128, is a mechanism
    /// for single- and multiple-part encryption and decryption with BATON
    /// in 128-bit electronic codebook mode.
    BatonEcb128([u8; 24]),
    /// BATON-ECB96, denoted CKM_BATON_ECB96, is a mechanism
    /// for single- and multiple-part encryption and decryption with BATON
    /// in 96-bit electronic codebook mode.
    BatonEcb96([u8; 24]),
    /// BATON-CBC128, denoted CKM_BATON_CBC128, is a mechanism
    /// for single- and multiple-part encryption and decryption with BATON
    /// in 128-bit cipher-block chaining mode.
    BatonCbc128([u8; 24]),
    /// BATON-COUNTER, denoted CKM_BATON_COUNTER, is a mechanism
    /// for single- and multiple-part encryption and decryption with BATON
    /// in counter mode.
    BatonCounter([u8; 24]),
    /// BATON-SHUFFLE, denoted CKM_BATON_SHUFFLE, is a mechanism
    /// for single- and multiple-part encryption and decryption with BATON
    /// in shuffle mode.
    BatonShuffle([u8; 24]),
    BatonWrap,

    EcKeyPairGen,

    Ecdsa,
    EcdsaSha1,
    // EcdsaSha224, // UNDEFINED_T
    // EcdsaSha256, // UNDEFINED_T
    // EcdsaSha384, // UNDEFINED_T
    // EcdsaSha512, // UNDEFINED_T
    Ecdh1Derive(Ecdh1DeriveParams<'a>),
    Ecdh1CofactorDerive(Ecdh1DeriveParams<'a>),
    // EcmqvDerive, // CK_ECMQV_DERIVE_PARAMS_T

    // EcdhAesKeyWrap, // CK_ECDH_AES_KEY_WRAP_PARAMS_T
    // RsaAesKeyWrap, // CK_RSA_AES_KEY_WRAP_PARAMS_T
    JuniperKeyGen,
    /// JUNIPER-ECB128, denoted CKM_JUNIPER_ECB128, is a mechanism
    /// for single- and multiple-part encryption and decryption with JUNIPER
    /// in 128-bit electronic codebook mode.
    ///
    /// It has a parameter, a 24-byte initialization vector.
    /// During an encryption operation, this IV is set to some value generated
    /// by the token"in other words, the application cannot specify
    /// a particular IV when encrypting. It can, of course, specify
    /// a particular IV when decrypting.
    JuniperEcb128([u8; 24]),
    /// JUNIPER-CBC128, denoted CKM_JUNIPER_CBC128, is a mechanism
    /// for single- and multiple-part encryption and decryption with JUNIPER
    /// in 128-bit cipher-block chaining mode.
    ///
    /// It has a parameter, a 24-byte initialization vector.
    /// During an encryption operation, this IV is set to some value generated
    /// by the token"in other words, the application cannot specify
    /// a particular IV when encrypting. It can, of course, specify
    /// a particular IV when decrypting.
    JuniperCbc128([u8; 24]),
    /// JUNIPER COUNTER, denoted CKM_JUNIPER_COUNTER, is a mechanism
    /// for single- and multiple-part encryption and decryption with JUNIPER
    /// in counter mode.
    ///
    /// It has a parameter, a 24-byte initialization vector.
    /// During an encryption operation, this IV is set to some value generated
    /// by the token"in other words, the application cannot specify
    /// a particular IV when encrypting. It can, of course, specify
    /// a particular IV when decrypting.
    JuniperCounter([u8; 24]),
    /// JUNIPER-SHUFFLE, denoted CKM_JUNIPER_SHUFFLE, is a mechanism
    /// for single- and multiple-part encryption and decryption with JUNIPER
    /// in shuffle mode.
    ///
    /// It has a parameter, a 24-byte initialization vector.
    /// During an encryption operation, this IV is set to some value generated
    /// by the token"in other words, the application cannot specify
    /// a particular IV when encrypting. It can, of course, specify
    /// a particular IV when decrypting.
    JuniperShuffle([u8; 24]),
    JuniperWrap,
    Fasthash,

    AesKeyGen,
    AesEcb,
    /// AES-CBC, denoted CKM_AES_CBC, is a mechanism for single- and
    /// multiple-part encryption and decryption; key wrapping; and
    /// key unwrapping, based on NIST's Advanced Encryption Standard and
    /// cipher-block chaining mode.
    ///
    /// It has a parameter, a 16-byte initialization vector.
    AesCbc([u8; 16]),
    AesMac,
    AesMacGeneral(Ulong), // CK_MAC_GENERAL_PARAMS
    /// AES-CBC with PKCS padding, denoted CKM_AES_CBC_PAD, is a mechanism
    /// for single- and multiple-part encryption and decryption; key wrapping;
    /// and key unwrapping, based on NIST's Advanced Encryption Standard;
    /// cipher-block chaining mode; and the block cipher padding method
    /// detailed in PKCS#7.
    ///
    /// It has a parameter, a 16-byte initialization vector.
    AesCbcPad([u8; 16]),
    // AesCtr, // CK_AES_CTR_PARAMS_T
    // AesGcm, // CK_GCM_PARAMS_T
    // AesCcm, // CK_CCM_PARAMS_T
    AesCts([u8; 16]),
    AesCmac(Ulong), // CK_MAC_GENERAL_PARAMS
    AesCmacGeneral,

    AesXcbcMac,
    AesXcbcMac96,
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
    AesGmac([u8; 12]),

    BlowfishKeyGen,
    /// Blowfish-CBC, denoted CKM_BLOWFISH_CBC, is a mechanism
    /// for single- and multiple-part encryption and decryption;
    /// key wrapping; and key unwrapping.
    BlowfishCbc([u8; 8]),
    TwofishKeyGen,
    /// Twofish-CBC, denoted CKM_TWOFISH_CBC, is a mechanism
    /// for single- and multiple-part encryption and decryption;
    /// key wrapping; and key unwrapping.
    TwofishCbc([u8; 16]),
    /// Blowfish-CBC, denoted CKM_BLOWFISH_CBC, is a mechanism
    /// for single- and multiple-part encryption and decryption;
    /// key wrapping; and key unwrapping.
    BlowfishCbcPad([u8; 8]),
    /// Twofish-CBC-PAD, denoted CKM_TWOFISH_CBC_PAD, is a mechanism
    /// for single- and multiple-part encryption and decryption,
    /// key wrapping and key unwrapping, cipher-block chaining mode
    /// and the block cipher padding method detailed in PKCS #7.
    TwofishCbcPad([u8; 16]),

    // DesEcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // DesCbcEncryptData, // CK_DES_CBC_ENCRYPT_DATA_PARAMS_T
    // Des3EcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // Des3CbcEncryptData, // CK_DES_CBC_ENCRYPT_DATA_PARAMS_T
    // AesEcbEncryptData, // CK_KEY_DERIVATION_STRING_DATA_T
    // AesCbcEncryptData, // CK_AES_CBC_ENCRYPT_DATA_PARAMS_T
    Gostr3410KeyPairGen,
    Gostr3410,
    Gostr3410WithGostr3411(Vec<Byte>), // DER-encoding of the object identifier
    // Gostr3410KeyWrap, // CK_GOSTR3410_KEY_WRAP_PARAMS_T
    // Gostr3410Derive, // CK_GOSTR3410_DERIVE_PARAMS_T
    Gostr3411(Vec<Byte>),     // DER-encoding of the object identifier
    Gostr3411Hmac(Vec<Byte>), // DER-encoding of the object identifier
    Gost28147KeyGen,          /* CKM_GOST28147_KEY_GEN INTERNATIONAL */
    Gost28147Ecb,             /* CKM_GOST28147_ECB INTERNATIONAL */
    /// GOST 28147-89 encryption mode except ECB, denoted CKM_GOST28147,
    /// is a mechanism for single and multiple-part encryption and decryption;
    /// key wrapping; and key unwrapping, based on [GOST 28147-89] and CFB,
    /// counter mode, and additional CBC mode defined in [RFC 4357] section 2.
    /// Encryption's parameters are specified in object identifier of
    /// attribute CKA_GOST28147_PARAMS.
    ///
    /// It has a parameter, which is an 8-byte initialization vector.
    /// This parameter may be omitted then a zero initialization vector is used.
    Gost28147([u8; 8]),
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
    Gost28147Mac([u8; 8]), // CKM_GOST28147_MAC INTERNATIONAL
    /// GOST 28147-89 keys as a KEK (key encryption keys) for encryption
    /// GOST 28147-89 keys, denoted by CKM_GOST28147_KEY_WRAP, is a mechanism
    /// for key wrapping; and key unwrapping, based on GOST 28147-89.
    /// Its purpose is to encrypt and decrypt keys have been generated by
    /// key generation mechanism for GOST 28147-89.
    ///
    /// It has a parameter, which is an 8-byte MAC initialization vector.
    /// This parameter may be omitted then a zero initialization vector is used.
    Gost28147KeyWrap([u8; 8]),

    DsaParameterGen,
    DhPkcsParameterGen,
    X9_42DhParameterGen,
    // DsaProbablisticParameterGen, // CK_DSA_PARAMETER_GEN_PARAM_T
    // DsaShaweTaylorParameterGen, // CK_DSA_PARAMETER_GEN_PARAM_T
    AesOfb([u8; 16]),
    AesCfb64([u8; 16]),
    AesCfb8([u8; 16]),
    AesCfb128([u8; 16]),

    // AesCfb1, // UNDEFINED_T
    // AesKeyWrap, // UNDEFINED_T, [u8; 8] or None
    // AesKeyWrapPad, // UNDEFINED_T, [u8; 8] or None
    RsaPkcsTpm11,
    RsaPkcsOaepTpm11,

    // SHA3
    // Sha3_256RsaPkcs, // UNDEFINED_T
    // Sha3_384RsaPkcs, // UNDEFINED_T
    // Sha3_512RsaPkcs, // UNDEFINED_T
    // Sha3_256RsaPkcsPss, // UNDEFINED_T
    // Sha3_384RsaPkcsPss, // UNDEFINED_T
    // Sha3_512RsaPkcsPss, // UNDEFINED_T
    // Sha3_224RsaPkcs, // UNDEFINED_T
    // Sha3_224RsaPkcsPss, // UNDEFINED_T
    // DsaSha3_224, // UNDEFINED_T
    // DsaSha3_256, // UNDEFINED_T
    // DsaSha3_384, // UNDEFINED_T
    // DsaSha3_512, // UNDEFINED_T
    // EcdsaSha3_224, // UNDEFINED_T
    // EcdsaSha3_256, // UNDEFINED_T
    // EcdsaSha3_384, // UNDEFINED_T
    // EcdsaSha3_512, // UNDEFINED_T
    // Sha3_256, // UNDEFINED_T
    // Sha3_256Hmac, // UNDEFINED_T
    // Sha3_256HmacGeneral, // UNDEFINED_T
    // Sha3_256KeyGen, // UNDEFINED_T
    // Sha3_224, // UNDEFINED_T
    // Sha3_224Hmac, // UNDEFINED_T
    // Sha3_224HmacGeneral, // UNDEFINED_T
    // Sha3_224KeyGen, // UNDEFINED_T
    // Sha3_384, // UNDEFINED_T
    // Sha3_384Hmac, // UNDEFINED_T
    // Sha3_384HmacGeneral, // UNDEFINED_T
    // Sha3_384KeyGen, // UNDEFINED_T
    // Sha3_512, // UNDEFINED_T
    // Sha3_512Hmac, // UNDEFINED_T
    // Sha3_512HmacGeneral, // UNDEFINED_T
    // Sha3_512KeyGen, // UNDEFINED_T
    // Sha3_256KeyDerive, // UNDEFINED_T
    // Sha3_224KeyDerive, // UNDEFINED_T
    // Sha3_384KeyDerive, // UNDEFINED_T
    // Sha3_512KeyDerive, // UNDEFINED_T
    // !SHA3
    /// Vendor defined.
    VendorDefined {
        mechanism_type: MechanismType,
        param: Option<&'a [Byte]>,
    },
}

impl<'a> Mechanism<'a> {
    pub fn new_vendor_defined(
        mechanism_type: MechanismType,
        param: Option<&'a [Byte]>,
    ) -> Result<Self> {
        if !mechanism_type.is_vendor_defined() {
            return Err(Error::InvalidInput);
        }
        Ok(Mechanism::VendorDefined {
            mechanism_type,
            param,
        })
    }
}

impl Mechanism<'_> {
    fn mechanism_type(&self) -> MechanismType {
        match self {
            Mechanism::RsaPkcsKeyPairGen => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            Mechanism::RsaPkcs => MechanismType::RSA_PKCS,
            Mechanism::Rsa9796 => MechanismType::RSA_9796,
            Mechanism::RsaX509 => MechanismType::RSA_X_509,
            Mechanism::Md2RsaPkcs => MechanismType::MD2_RSA_PKCS,
            Mechanism::Md5RsaPkcs => MechanismType::MD5_RSA_PKCS,
            Mechanism::Sha1RsaPkcs => MechanismType::SHA1_RSA_PKCS,
            Mechanism::Ripemd128RsaPkcs => MechanismType::RIPEMD128_RSA_PKCS,
            Mechanism::Ripemd160RsaPkcs => MechanismType::RIPEMD160_RSA_PKCS,
            // Mechanism::RsaPkcsOaep => MechanismType::RSA_PKCS_OAEP,
            Mechanism::RsaX9_31KeyPairGen => MechanismType::RSA_X9_31_KEY_PAIR_GEN,
            Mechanism::RsaX9_31 => MechanismType::RSA_X9_31,
            Mechanism::Sha1RsaX9_31 => MechanismType::SHA1_RSA_X9_31,
            Mechanism::RsaPkcsPss(_) => MechanismType::RSA_PKCS_PSS,
            Mechanism::Sha1RsaPkcsPss(_) => MechanismType::SHA1_RSA_PKCS_PSS,
            Mechanism::DsaKeyPairGen => MechanismType::DSA_KEY_PAIR_GEN,
            Mechanism::Dsa => MechanismType::DSA,
            Mechanism::DsaSha1 => MechanismType::DSA_SHA1,
            Mechanism::DsaSha224 => MechanismType::DSA_SHA224,
            Mechanism::DsaSha256 => MechanismType::DSA_SHA256,
            Mechanism::DsaSha384 => MechanismType::DSA_SHA384,
            Mechanism::DsaSha512 => MechanismType::DSA_SHA512,
            Mechanism::DhPkcsKeyPairGen => MechanismType::DH_PKCS_KEY_PAIR_GEN,
            Mechanism::DhPkcsDerive(_) => MechanismType::DH_PKCS_DERIVE,
            Mechanism::X9_42DhKeyPairGen => MechanismType::X9_42_DH_KEY_PAIR_GEN,
            Mechanism::X9_42DhDerive(_) => MechanismType::X9_42_DH_DERIVE,
            // Mechanism::X9_42DhHybridDerive(_) => MechanismType::X9_42_DH_HYBRID_DERIVE, // CK_X9_42_DH2_DERIVE_PARAMS_T
            // Mechanism::X9_42MqvDerive(_), => MechanismType::X9_42_MQV_DERIVE, // CK_X9_42_MQV_DERIVE_PARAMS_T
            Mechanism::Sha256RsaPkcs => MechanismType::SHA256_RSA_PKCS,
            Mechanism::Sha384RsaPkcs => MechanismType::SHA384_RSA_PKCS,
            Mechanism::Sha512RsaPkcs => MechanismType::SHA512_RSA_PKCS,
            Mechanism::Sha256RsaPkcsPss(_) => MechanismType::SHA256_RSA_PKCS_PSS,
            Mechanism::Sha384RsaPkcsPss(_) => MechanismType::SHA384_RSA_PKCS_PSS,
            Mechanism::Sha512RsaPkcsPss(_) => MechanismType::SHA512_RSA_PKCS_PSS,
            Mechanism::Sha224RsaPkcs => MechanismType::SHA224_RSA_PKCS,
            Mechanism::Sha224RsaPkcsPss(_) => MechanismType::SHA224_RSA_PKCS_PSS,
            Mechanism::Sha512_224 => MechanismType::SHA512_224,
            Mechanism::Sha512_224Hmac => MechanismType::SHA512_224_HMAC,
            Mechanism::Sha512_224HmacGeneral(_) => MechanismType::SHA512_224_HMAC_GENERAL,
            // Mechanism::Sha512_224KeyDerivation(_) => MechanismType::SHA512_224_KEY_DERIVATION,
            Mechanism::Sha512_256 => MechanismType::SHA512_256,
            Mechanism::Sha512_256Hmac => MechanismType::SHA512_256_HMAC,
            Mechanism::Sha512_256HmacGeneral(_) => MechanismType::SHA512_256_HMAC_GENERAL,
            // Mechanism::Sha512_224KeyDerivation(_) => MechanismType::SHA512_256_KEY_DERIVATION,
            Mechanism::Sha512T(_) => MechanismType::SHA512_T,
            Mechanism::Sha512THmac(_) => MechanismType::SHA512_T_HMAC,
            Mechanism::Sha512THmacGeneral(_) => MechanismType::SHA512_T_HMAC_GENERAL,
            // Mechanism::sha512TKeyDerivation(_) => MechanismType::SHA512_T_KEY_DERIVATION,
            Mechanism::Rc2KeyGen => MechanismType::RC2_KEY_GEN,
            Mechanism::Rc2Ecb(_) => MechanismType::RC2_ECB,
            // Mechanism::Rc2Cbc => MechanismType::RC2_CBC,
            Mechanism::Rc2Mac(_) => MechanismType::RC2_MAC,
            // Mechanism::Rc2MacGeneral(_) => MechanismType::RC2_MAC_GENERAL,
            // Mechanism::Rc2CbcPad(_) => MechanismType::RC2_CBC_PAD,
            Mechanism::Rc4KeyGen => MechanismType::RC4_KEY_GEN,
            Mechanism::Rc4 => MechanismType::RC4,
            Mechanism::DesKeyGen => MechanismType::DES_KEY_GEN,
            Mechanism::DesEcb => MechanismType::DES_ECB,
            Mechanism::DesCbc(_) => MechanismType::DES_CBC,
            Mechanism::DesMac => MechanismType::DES_MAC,
            Mechanism::DesMacGeneral(_) => MechanismType::DES_MAC_GENERAL,
            Mechanism::DesCbcPad(_) => MechanismType::DES_CBC_PAD,
            Mechanism::Des2KeyGen => MechanismType::DES2_KEY_GEN,
            Mechanism::Des3KeyGen => MechanismType::DES3_KEY_GEN,
            Mechanism::Des3Ecb => MechanismType::DES3_ECB,
            Mechanism::Des3Cbc(_) => MechanismType::DES3_CBC,
            Mechanism::Des3Mac => MechanismType::DES3_MAC,
            Mechanism::Des3MacGeneral(_) => MechanismType::DES3_MAC_GENERAL,
            Mechanism::Des3CbcPad(_) => MechanismType::DES3_CBC_PAD,
            Mechanism::Des3CmacGeneral(_) => MechanismType::DES3_CMAC_GENERAL,
            Mechanism::Des3Cmac => MechanismType::DES3_CMAC,
            // Mechanism::CdmfKeyGen => MechanismType::CDMF_KEY_GEN,
            // Mechanism::CdmfEcb => MechanismType::CDMF_ECB,
            // Mechanism::CdmfCbc => MechanismType::CDMF_CBC,
            // Mechanism::CdmfMac => MechanismType::CDMF_MAC,
            // Mechanism::CdmfMacGeneral => MechanismType::CDMF_MAC_GENERAL,
            // Mechanism::CdmfCbcPad => MechanismType::CDMF_CBC_PAD,
            Mechanism::DesOfb64(_) => MechanismType::DES_OFB64,
            Mechanism::DesOfb8(_) => MechanismType::DES_OFB8,
            Mechanism::DesCfb64(_) => MechanismType::DES_CFB64,
            Mechanism::DesCfb8(_) => MechanismType::DES_CFB8,
            Mechanism::Md2 => MechanismType::MD2,
            Mechanism::Md2Hmac => MechanismType::MD2_HMAC,
            Mechanism::Md2HmacGeneral(_) => MechanismType::MD2_HMAC_GENERAL,
            Mechanism::Md5 => MechanismType::MD5,
            Mechanism::Md5Hmac => MechanismType::MD5_HMAC,
            Mechanism::Md5HmacGeneral(_) => MechanismType::MD5_HMAC_GENERAL,
            Mechanism::Sha1 => MechanismType::SHA_1,
            Mechanism::Sha1Hmac => MechanismType::SHA_1_HMAC,
            Mechanism::Sha1HmacGeneral(_) => MechanismType::SHA_1_HMAC_GENERAL,
            Mechanism::Ripemd128 => MechanismType::RIPEMD128,
            Mechanism::Ripemd128Hmac => MechanismType::RIPEMD128_HMAC,
            Mechanism::Ripemd128HmacGeneral(_) => MechanismType::RIPEMD128_HMAC_GENERAL,
            Mechanism::Ripemd160 => MechanismType::RIPEMD160,
            Mechanism::Ripemd160Hmac => MechanismType::RIPEMD160_HMAC,
            Mechanism::Ripemd160HmacGeneral(_) => MechanismType::RIPEMD160_HMAC_GENERAL,
            Mechanism::Sha256 => MechanismType::SHA256,
            Mechanism::Sha256Hmac => MechanismType::SHA256_HMAC,
            Mechanism::Sha256HmacGeneral(_) => MechanismType::SHA256_HMAC_GENERAL,
            Mechanism::Sha224 => MechanismType::SHA224,
            Mechanism::Sha224Hmac => MechanismType::SHA224_HMAC,
            Mechanism::Sha224HmacGeneral(_) => MechanismType::SHA224_HMAC_GENERAL,
            Mechanism::Sha384 => MechanismType::SHA384,
            Mechanism::Sha384Hmac => MechanismType::SHA384_HMAC,
            Mechanism::Sha384HmacGeneral(_) => MechanismType::SHA384_HMAC_GENERAL,
            Mechanism::Sha512 => MechanismType::SHA512,
            Mechanism::Sha512Hmac => MechanismType::SHA512_HMAC,
            Mechanism::Sha512HmacGeneral(_) => MechanismType::SHA512_HMAC_GENERAL,
            Mechanism::SecuridKeyGen => MechanismType::SECURID_KEY_GEN,
            // Mechanism::Securid => MechanismType::SECURID,
            Mechanism::HotpKeyGen => MechanismType::HOTP_KEY_GEN,
            // Mechanism::Hotp(_) => MechanismType::HOTP,
            // Mechanism::Acti(_) => MechanismType::ACTI,
            Mechanism::ActiKeyGen => MechanismType::ACTI_KEY_GEN,
            // Mechanism::CastKeyGen => MechanismType::CAST_KEY_GEN, // UNDEFINED_T
            // Mechanism::CastEcb => MechanismType::CAST_ECB, // UNDEFINED_T
            // Mechanism::CastCbc => MechanismType::CAST_CBC, // UNDEFINED_T
            // Mechanism::CastMac => MechanismType::CAST_MAC, // UNDEFINED_T
            // Mechanism::CastMacGeneral => MechanismType::CAST_MAC_GENERAL, // UNDEFINED_T
            // Mechanism::CastCbcPad => MechanismType::CAST_CBC_PAD, // UNDEFINED_T
            // Mechanism::Cast3KeyGen => MechanismType::CAST3_KEY_GEN, // UNDEFINED_T
            // Mechanism::Cast3Ecb => MechanismType::CAST3_ECB, // UNDEFINED_T
            // Mechanism::Cast3Cbc => MechanismType::CAST3_CBC, // UNDEFINED_T
            // Mechanism::Cast3Mac => MechanismType::CAST3_MAC, // UNDEFINED_T
            // Mechanism::Cast3MacGeneral => MechanismType::CAST3_MAC_GENERAL, // UNDEFINED_T
            // Mechanism::Cast3CbcPad => MechanismType::CAST3_CBC_PAD, // UNDEFINED_T
            // Mechanism::Cast128KeyGen => MechanismType::CAST128_KEY_GEN, // UNDEFINED_T
            // Mechanism::Cast128Ecb => MechanismType::CAST128_ECB, // UNDEFINED_T
            // Mechanism::Cast128Cbc => MechanismType::CAST128_CBC, // UNDEFINED_T
            // Mechanism::Cast128Mac => MechanismType::CAST128_MAC, // UNDEFINED_T
            // Mechanism::Cast128MacGeneral => MechanismType::CAST128_MAC_GENERAL, // UNDEFINED_T
            // Mechanism::Cast128CbcPad => MechanismType::CAST128_CBC_PAD, // UNDEFINED_T
            Mechanism::Rc5KeyGen => MechanismType::RC5_KEY_GEN,
            // Mechanism::Rc5Ecb(_) => MechanismType::RC5_ECB,
            // Mechanism::Rc5Cbc(_) => MechanismType::RC5_CBC,
            // Mechanism::Rc5Mac(_) => MechanismType::RC5_MAC,
            // Mechanism::Rc5MacGeneral(_) => MechanismType::RC5_MAC_GENERAL,
            // Mechanism::Rc5CbcPad(_) => MechanismType::RC5_CBC_PAD,
            // Mechanism::IdeaKeyGen(_) => MechanismType::IDEA_KEY_GEN,
            // Mechanism::IdeaEcb(_) => MechanismType::IDEA_ECB,
            // Mechanism::IdeaCbc(_) => MechanismType::IDEA_CBC,
            // Mechanism::IdeaMac(_) => MechanismType::IDEA_MAC,
            // Mechanism::IdeaMacGeneral(_) => MechanismType::IDEA_MAC_GENERAL,
            // Mechanism::IdeaCbcPad(_) => MechanismType::IDEA_CBC_PAD,
            Mechanism::GenericSecretKeyGen => MechanismType::GENERIC_SECRET_KEY_GEN,
            Mechanism::ConcatenateBaseAndKey(_) => {
                MechanismType::CONCATENATE_BASE_AND_KEY
            }
            // Mechanism::ConcatenateDataAndBase(_) => MechanismType::CONCATENATE_DATA_AND_BASE,
            // Mechanism::XorBaseAndData(_) => MechanismType::XOR_BASE_AND_DATA,
            Mechanism::ExtractKeyFromKey(_) => MechanismType::EXTRACT_KEY_FROM_KEY,
            // Mechanism::Ssl3PreMasterKeyGen(_) => MechanismType::SSL3_PRE_MASTER_KEY_GEN,
            // Mechanism::Ssl3MasterKeyDerive(_) => MechanismType::SSL3_MASTER_KEY_DERIVE,
            // Mechanism::Ssl3KeyAndMacDerive(_) => MechanismType::SSL3_KEY_AND_MAC_DERIVE,
            // Mechanism::Ssl3MasterKeyDeriveDh(_) => MechanismType::SSL3_MASTER_KEY_DERIVE_DH,
            // Mechanism::TlsPreMasterKeyGen(_) => MechanismType::TLS_PRE_MASTER_KEY_GEN,
            // Mechanism::TlsMasterKeyDerive(_) => MechanismType::TLS_MASTER_KEY_DERIVE,
            // Mechanism::TlsKeyAndMacDerive(_) => MechanismType::TLS_KEY_AND_MAC_DERIVE,
            // Mechanism::TlsMasterKeyDeriveDh(_) => MechanismType::TLS_MASTER_KEY_DERIVE_DH,
            // Mechanism::TlsPrf(_) => MechanismType::TLS_PRF,
            Mechanism::Ssl3Md5Mac(_) => MechanismType::SSL3_MD5_MAC,
            Mechanism::Ssl3Sha1Mac(_) => MechanismType::SSL3_SHA1_MAC,
            // Mechanism::Md5KeyDerivation(_) => MechanismType::MD5_KEY_DERIVATION,
            // Mechanism::Md2KeyDerivation(_) => MechanismType::MD2_KEY_DERIVATION,
            // Mechanism::Sha1KeyDerivation(_) => MechanismType::SHA1_KEY_DERIVATION,
            // Mechanism::Sha256KeyDerivation(_) => MechanismType::SHA256_KEY_DERIVATION,
            // Mechanism::Sha384KeyDerivation(_) => MechanismType::SHA384_KEY_DERIVATION,
            // Mechanism::Sha512KeyDerivation(_) => MechanismType::SHA512_KEY_DERIVATION,
            // Mechanism::Sha224KeyDerivation(_) => MechanismType::SHA224_KEY_DERIVATION,
            // Mechanism::PbeMd2DesCbc(_) => MechanismType::PBE_MD2_DES_CBC,
            // Mechanism::PbeMd5DesCbc(_) => MechanismType::PBE_MD5_DES_CBC,
            // Mechanism::PbeMd5CastCbc(_) => MechanismType::PBE_MD5_CAST_CBC,
            // Mechanism::PbeMd5Cast3Cbc(_) => MechanismType::PBE_MD5_CAST3_CBC,
            // Mechanism::PbeMd5Cast128Cbc(_) => MechanismType::PBE_MD5_CAST128_CBC,
            // Mechanism::PbeSha1Cast128Cbc(_) => MechanismType::PBE_SHA1_CAST128_CBC,
            // Mechanism::PbeSha1Rc4_128(_) => MechanismType::PBE_SHA1_RC4_128,
            // Mechanism::PbeSha1Rc4_40(_) => MechanismType::PBE_SHA1_RC4_40,
            // Mechanism::PbeSha1Des3EdeCbc(_) => MechanismType::PBE_SHA1_DES3_EDE_CBC,
            // Mechanism::PbeSha1Des2EdeCbc(_) => MechanismType::PBE_SHA1_DES2_EDE_CBC,
            // Mechanism::PbeSha1Rc2_128Cbc(_) => MechanismType::PBE_SHA1_RC2_128_CBC,
            // Mechanism::PbeSha1Rc2_40Cbc(_) => MechanismType::PBE_SHA1_RC2_40_CBC,
            // Mechanism::Pkcs5Pbkd2(_) => MechanismType::PKCS5_PBKD2,
            // Mechanism::PbaSha1WithSha1Hmac(_) => MechanismType::PBA_SHA1_WITH_SHA1_HMAC,
            Mechanism::WtlsPreMasterKeyGen(_) => MechanismType::WTLS_PRE_MASTER_KEY_GEN,
            // Mechanism::WtlsMasterKeyDerive(_) => MechanismType::WTLS_MASTER_KEY_DERIVE,
            // Mechanism::WtlsMasterKeyDeriveDhEcc(_) => MechanismType::WTLS_MASTER_KEY_DERIVE_DH_ECC,
            // Mechanism::WtlsPrf(_) => MechanismType::WTLS_PRF,
            // Mechanism::WtlsServerKeyAndMacDerive(_) => MechanismType::WTLS_SERVER_KEY_AND_MAC_DERIVE,
            // Mechanism::WtlsClientKeyAndMacDerive(_) => MechanismType::WTLS_CLIENT_KEY_AND_MAC_DERIVE,

            // Mechanism::Tls10MacServer(_) => MechanismType::TLS10_MAC_SERVER,
            // Mechanism::Tls10MacClient(_) => MechanismType::TLS10_MAC_CLIENT,
            // Mechanism::Tls12Mac(_) => MechanismType::TLS12_MAC,
            // Mechanism::Tls12Kdf(_) => MechanismType::TLS12_KDF,
            // Mechanism::Tls12MasterKeyDerive(_) => MechanismType::TLS12_MASTER_KEY_DERIVE,
            // Mechanism::Tls12KeyAndMacDerive(_) => MechanismType::TLS12_KEY_AND_MAC_DERIVE,
            // Mechanism::Tls12MasterKeyDeriveDh(_) => MechanismType::TLS12_MASTER_KEY_DERIVE_DH,
            // Mechanism::Tls12KeySafeDerive(_) => MechanismType::TLS12_KEY_SAFE_DERIVE,
            // Mechanism::TlsMac(_) => MechanismType::TLS_MAC,
            // Mechanism::TlsKdf(_) => MechanismType::TLS_KDF,
            // Mechanism::KeyWrapLynks(_) => MechanismType::KEY_WRAP_LYNKS,
            // Mechanism::KeyWrapSetOaep(_) => MechanismType::KEY_WRAP_SET_OAEP,
            // Mechanism::CmsSig(_) => MechanismType::CMS_SIG,
            // Mechanism::KipDerive(_) => MechanismType::KIP_DERIVE,
            // Mechanism::KipWrap(_) => MechanismType::KIP_WRAP,
            // Mechanism::KipMac(_) => MechanismType::KIP_MAC,
            Mechanism::CamelliaKeyGen => MechanismType::CAMELLIA_KEY_GEN,
            Mechanism::CamelliaEcb => MechanismType::CAMELLIA_ECB,
            Mechanism::CamelliaCbc(_) => MechanismType::CAMELLIA_CBC,
            Mechanism::CamelliaMac => MechanismType::CAMELLIA_MAC,
            Mechanism::CamelliaMacGeneral(_) => MechanismType::CAMELLIA_MAC_GENERAL,
            Mechanism::CamelliaCbcPad(_) => MechanismType::CAMELLIA_CBC_PAD,
            // Mechanism::CamelliaEcbEncryptData(_) => MechanismType::CAMELLIA_ECB_ENCRYPT_DATA,
            // Mechanism::CamelliaCbcEncryptData(_) => MechanismType::CAMELLIA_CBC_ENCRYPT_DATA,
            // Mechanism::CamelliaCtr(_) => MechanismType::CAMELLIA_CTR,
            Mechanism::AriaKeyGen => MechanismType::ARIA_KEY_GEN,
            Mechanism::AriaEcb => MechanismType::ARIA_ECB,
            Mechanism::AriaCbc(_) => MechanismType::ARIA_CBC,
            Mechanism::AriaMac => MechanismType::ARIA_MAC,
            Mechanism::AriaMacGeneral(_) => MechanismType::ARIA_MAC_GENERAL,
            Mechanism::AriaCbcPad(_) => MechanismType::ARIA_CBC_PAD,
            // Mechanism::AriaEcbEncryptData(_) => MechanismType::ARIA_ECB_ENCRYPT_DATA,
            // Mechanism::AriaCbcEncryptData(_) => MechanismType::ARIA_CBC_ENCRYPT_DATA,
            Mechanism::SeedKeyGen => MechanismType::SEED_KEY_GEN,
            Mechanism::SeedEcb => MechanismType::SEED_ECB,
            Mechanism::SeedCbc(_) => MechanismType::SEED_CBC,
            Mechanism::SeedMac => MechanismType::SEED_MAC,
            Mechanism::SeedMacGeneral(_) => MechanismType::SEED_MAC_GENERAL,
            Mechanism::SeedCbcPad(_) => MechanismType::SEED_CBC_PAD,
            // Mechanism::SeedEcbEncryptData(_) => MechanismType::SEED_ECB_ENCRYPT_DATA,
            // Mechanism::SeedCbcEncryptData(_) => MechanismType::SEED_CBC_ENCRYPT_DATA,
            Mechanism::SkipjackKeyGen => MechanismType::SKIPJACK_KEY_GEN,
            Mechanism::SkipjackEcb64(_) => MechanismType::SKIPJACK_ECB64,
            Mechanism::SkipjackCbc64(_) => MechanismType::SKIPJACK_CBC64,
            Mechanism::SkipjackOfb64(_) => MechanismType::SKIPJACK_OFB64,
            Mechanism::SkipjackCfb64(_) => MechanismType::SKIPJACK_CFB64,
            Mechanism::SkipjackCfb32(_) => MechanismType::SKIPJACK_CFB32,
            Mechanism::SkipjackCfb16(_) => MechanismType::SKIPJACK_CFB16,
            Mechanism::SkipjackCfb8(_) => MechanismType::SKIPJACK_CFB8,
            Mechanism::SkipjackWrap => MechanismType::SKIPJACK_WRAP,
            // Mechanism::SkipjackPrivateWrap => MechanismType::SKIPJACK_PRIVATE_WRAP,
            // Mechanism::SkipjackRelayx => MechanismType::SKIPJACK_RELAYX,
            Mechanism::KeaKeyPairGen => MechanismType::KEA_KEY_PAIR_GEN,
            // Mechanism::KeaKeyDerive => MechanismType::KEA_KEY_DERIVE,
            // Mechanism::KeaDerive => MechanismType::KEA_DERIVE,
            Mechanism::FortezzaTimestamp => MechanismType::FORTEZZA_TIMESTAMP,
            Mechanism::BatonKeyGen => MechanismType::BATON_KEY_GEN,
            Mechanism::BatonEcb128(_) => MechanismType::BATON_ECB128,
            Mechanism::BatonEcb96(_) => MechanismType::BATON_ECB96,
            Mechanism::BatonCbc128(_) => MechanismType::BATON_CBC128,
            Mechanism::BatonCounter(_) => MechanismType::BATON_COUNTER,
            Mechanism::BatonShuffle(_) => MechanismType::BATON_SHUFFLE,
            Mechanism::BatonWrap => MechanismType::BATON_WRAP,
            Mechanism::EcKeyPairGen => MechanismType::EC_KEY_PAIR_GEN,
            Mechanism::Ecdsa => MechanismType::ECDSA,
            Mechanism::EcdsaSha1 => MechanismType::ECDSA_SHA1,
            // Mechanism::EcdsaSha224(_) => MechanismType::ECDSA_SHA224,
            // Mechanism::EcdsaSha256(_) => MechanismType::ECDSA_SHA256,
            // Mechanism::EcdsaSha384(_) => MechanismType::ECDSA_SHA384,
            // Mechanism::EcdsaSha512(_) => MechanismType::ECDSA_SHA512,
            Mechanism::Ecdh1Derive(_) => MechanismType::ECDH1_DERIVE,
            Mechanism::Ecdh1CofactorDerive(_) => MechanismType::ECDH1_COFACTOR_DERIVE,
            // Mechanism::EcmqvDerive(_) => MechanismType::ECMQV_DERIVE,
            // Mechanism::EcdhAesKeyWrap(_) => MechanismType::ECDH_AES_KEY_WRAP,
            // Mechanism::RsaAesKeyWrap(_) => MechanismType::RSA_AES_KEY_WRAP,
            Mechanism::JuniperKeyGen => MechanismType::JUNIPER_KEY_GEN,
            Mechanism::JuniperEcb128(_) => MechanismType::JUNIPER_ECB128,
            Mechanism::JuniperCbc128(_) => MechanismType::JUNIPER_CBC128,
            Mechanism::JuniperCounter(_) => MechanismType::JUNIPER_COUNTER,
            Mechanism::JuniperShuffle(_) => MechanismType::JUNIPER_SHUFFLE,
            Mechanism::JuniperWrap => MechanismType::JUNIPER_WRAP,
            Mechanism::Fasthash => MechanismType::FASTHASH,
            Mechanism::AesKeyGen => MechanismType::AES_KEY_GEN,
            Mechanism::AesEcb => MechanismType::AES_ECB,
            Mechanism::AesCbc(_) => MechanismType::AES_CBC,
            Mechanism::AesMac => MechanismType::AES_MAC,
            Mechanism::AesMacGeneral(_) => MechanismType::AES_MAC_GENERAL,
            Mechanism::AesCbcPad(_) => MechanismType::AES_CBC_PAD,
            // Mechanism::AesCtr(_) => MechanismType::AES_CTR,
            // Mechanism::AesGcm(_) => MechanismType::AES_GCM,
            // Mechanism::AesCcm(_) => MechanismType::AES_CCM,
            Mechanism::AesCts(_) => MechanismType::AES_CTS,
            Mechanism::AesCmac(_) => MechanismType::AES_CMAC,
            Mechanism::AesCmacGeneral => MechanismType::AES_CMAC_GENERAL,
            Mechanism::AesXcbcMac => MechanismType::AES_XCBC_MAC,
            Mechanism::AesXcbcMac96 => MechanismType::AES_XCBC_MAC_96,
            Mechanism::AesGmac(_) => MechanismType::AES_GMAC,
            Mechanism::BlowfishKeyGen => MechanismType::BLOWFISH_KEY_GEN,
            Mechanism::BlowfishCbc(_) => MechanismType::BLOWFISH_CBC,
            Mechanism::TwofishKeyGen => MechanismType::TWOFISH_KEY_GEN,
            Mechanism::TwofishCbc(_) => MechanismType::TWOFISH_CBC,
            Mechanism::BlowfishCbcPad(_) => MechanismType::BLOWFISH_CBC_PAD,
            Mechanism::TwofishCbcPad(_) => MechanismType::TWOFISH_CBC_PAD,
            // Mechanism::DesEcbEncryptData(_) => MechanismType::DES_ECB_ENCRYPT_DATA,
            // Mechanism::DesCbcEncryptData(_) => MechanismType::DES_CBC_ENCRYPT_DATA,
            // Mechanism::Des3EcbEncryptData(_) => MechanismType::DES3_ECB_ENCRYPT_DATA,
            // Mechanism::Des3CbcEncryptData(_) => MechanismType::DES3_CBC_ENCRYPT_DATA,
            // Mechanism::AesEcbEncryptData(_) => MechanismType::AES_ECB_ENCRYPT_DATA,
            // Mechanism::AesCbcEncryptData(_) => MechanismType::AES_CBC_ENCRYPT_DATA,
            Mechanism::Gostr3410KeyPairGen => MechanismType::GOSTR3410_KEY_PAIR_GEN,
            Mechanism::Gostr3410 => MechanismType::GOSTR3410,
            Mechanism::Gostr3410WithGostr3411(_) => {
                MechanismType::GOSTR3410_WITH_GOSTR3411
            }
            // Mechanism::Gostr3410KeyWrap(_) => MechanismType::GOSTR3410_KEY_WRAP,
            // Mechanism::Gostr3410Derive(_) => MechanismType::GOSTR3410_DERIVE,
            Mechanism::Gostr3411(_) => MechanismType::GOSTR3411,
            Mechanism::Gostr3411Hmac(_) => MechanismType::GOSTR3411_HMAC,
            Mechanism::Gost28147KeyGen => MechanismType::GOST28147_KEY_GEN,
            Mechanism::Gost28147Ecb => MechanismType::GOST28147_ECB,
            Mechanism::Gost28147(_) => MechanismType::GOST28147,
            Mechanism::Gost28147Mac(_) => MechanismType::GOST28147_MAC,
            Mechanism::Gost28147KeyWrap(_) => MechanismType::GOST28147_KEY_WRAP,
            Mechanism::DsaParameterGen => MechanismType::DSA_PARAMETER_GEN,
            Mechanism::DhPkcsParameterGen => MechanismType::DH_PKCS_PARAMETER_GEN,
            Mechanism::X9_42DhParameterGen => MechanismType::X9_42_DH_PARAMETER_GEN,
            // Mechanism::DsaProbablisticParameterGen => MechanismType::DSA_PROBABLISTIC_PARAMETER_GEN,
            // Mechanism::DsaShaweTaylorParameterGen => MechanismType::DSA_SHAWE_TAYLOR_PARAMETER_GEN,
            Mechanism::AesOfb(_) => MechanismType::AES_OFB,
            Mechanism::AesCfb64(_) => MechanismType::AES_CFB64,
            Mechanism::AesCfb8(_) => MechanismType::AES_CFB8,
            Mechanism::AesCfb128(_) => MechanismType::AES_CFB128,
            // Mechanism::AesCfb1(_) => MechanismType::AES_CFB1,
            // Mechanism::AesKeyWrap(_) => MechanismType::AES_KEY_WRAP,
            // Mechanism::AesKeyWrapPad(_) => MechanismType::AES_KEY_WRAP_PAD,
            Mechanism::RsaPkcsTpm11 => MechanismType::RSA_PKCS_TPM_1_1,
            Mechanism::RsaPkcsOaepTpm11 => MechanismType::RSA_PKCS_OAEP_TPM_1_1,

            // SHA3
            // Mechanism::Sha3_256RsaPkcs(_) => MechanismType::SHA3_256_RSA_PKCS,
            // Mechanism::Sha3_384RsaPkcs(_) => MechanismType::SHA3_384_RSA_PKCS,
            // Mechanism::Sha3_512RsaPkcs(_) => MechanismType::SHA3_512_RSA_PKCS,
            // Mechanism::Sha3_256RsaPkcsPss(_) => MechanismType::SHA3_256_RSA_PKCS_PSS,
            // Mechanism::Sha3_384RsaPkcsPss(_) => MechanismType::SHA3_384_RSA_PKCS_PSS,
            // Mechanism::Sha3_512RsaPkcsPss(_) => MechanismType::SHA3_512_RSA_PKCS_PSS,
            // Mechanism::Sha3_224RsaPkcs(_) => MechanismType::SHA3_224_RSA_PKCS,
            // Mechanism::Sha3_224RsaPkcsPss(_) => MechanismType::SHA3_224_RSA_PKCS_PSS,
            // Mechanism::DsaSha3_224(_) => MechanismType::DSA_SHA3_224,
            // Mechanism::DsaSha3_256(_) => MechanismType::DSA_SHA3_256,
            // Mechanism::DsaSha3_384(_) => MechanismType::DSA_SHA3_384,
            // Mechanism::DsaSha3_512(_) => MechanismType::DSA_SHA3_512,
            // Mechanism::EcdsaSha3_224(_) => MechanismType::ECDSA_SHA3_224,
            // Mechanism::EcdsaSha3_256(_) => MechanismType::ECDSA_SHA3_256,
            // Mechanism::EcdsaSha3_384(_) => MechanismType::ECDSA_SHA3_384,
            // Mechanism::EcdsaSha3_512(_) => MechanismType::ECDSA_SHA3_512,
            // Mechanism::Sha3_256(_) => MechanismType::SHA3_256,
            // Mechanism::Sha3_256Hmac(_) => MechanismType::SHA3_256_HMAC,
            // Mechanism::Sha3_256HmacGeneral(_) => MechanismType::SHA3_256_HMAC_GENERAL,
            // Mechanism::Sha3_256KeyGen(_) => MechanismType::SHA3_256_KEY_GEN,
            // Mechanism::Sha3_224(_) => MechanismType::SHA3_224,
            // Mechanism::Sha3_224Hmac(_) => MechanismType::SHA3_224_HMAC,
            // Mechanism::Sha3_224HmacGeneral(_) => MechanismType::SHA3_224_HMAC_GENERAL,
            // Mechanism::Sha3_224KeyGen(_) => MechanismType::SHA3_224_KEY_GEN,
            // Mechanism::Sha3_384(_) => MechanismType::SHA3_384,
            // Mechanism::Sha3_384Hmac(_) => MechanismType::SHA3_384_HMAC,
            // Mechanism::Sha3_384HmacGeneral(_) => MechanismType::SHA3_384_HMAC_GENERAL,
            // Mechanism::Sha3_384KeyGen(_) => MechanismType::SHA3_384_KEY_GEN,
            // Mechanism::Sha3_512(_) => MechanismType::SHA3_512,
            // Mechanism::Sha3_512Hmac(_) => MechanismType::SHA3_512_HMAC,
            // Mechanism::Sha3_512HmacGeneral(_) => MechanismType::SHA3_512_HMAC_GENERAL,
            // Mechanism::Sha3_512KeyGen(_) => MechanismType::SHA3_512_KEY_GEN,
            // Mechanism::Sha3_256KeyDerive(_) => MechanismType::SHA3_256_KEY_DERIVE,
            // Mechanism::Sha3_224KeyDerive(_) => MechanismType::SHA3_224_KEY_DERIVE,
            // Mechanism::Sha3_384KeyDerive(_) => MechanismType::SHA3_384_KEY_DERIVE,
            // Mechanism::Sha3_512KeyDerive(_) => MechanismType::SHA3_512_KEY_DERIVE,
            // !SHA3
            Mechanism::VendorDefined { mechanism_type, .. } => *mechanism_type,
        }
    }

    fn ptr(&self) -> CK_VOID_PTR {
        match self {
            // No param
            Mechanism::RsaPkcsKeyPairGen
            | Mechanism::RsaPkcs
            | Mechanism::Rsa9796
            | Mechanism::RsaX509
            | Mechanism::Md2RsaPkcs
            | Mechanism::Md5RsaPkcs
            | Mechanism::Sha1RsaPkcs
            | Mechanism::Ripemd128RsaPkcs
            | Mechanism::Ripemd160RsaPkcs
            | Mechanism::RsaX9_31KeyPairGen
            | Mechanism::RsaX9_31
            | Mechanism::Sha1RsaX9_31
            | Mechanism::DsaKeyPairGen
            | Mechanism::Dsa
            | Mechanism::DsaSha1
            | Mechanism::DsaSha224
            | Mechanism::DsaSha256
            | Mechanism::DsaSha384
            | Mechanism::DsaSha512
            | Mechanism::DhPkcsKeyPairGen
            | Mechanism::X9_42DhKeyPairGen
            | Mechanism::Sha256RsaPkcs
            | Mechanism::Sha384RsaPkcs
            | Mechanism::Sha512RsaPkcs
            | Mechanism::Sha224RsaPkcs
            | Mechanism::Sha512_224
            | Mechanism::Sha512_224Hmac
            | Mechanism::Sha512_256
            | Mechanism::Sha512_256Hmac
            | Mechanism::Rc2KeyGen
            | Mechanism::Rc4KeyGen
            | Mechanism::Rc4
            | Mechanism::DesKeyGen
            | Mechanism::DesEcb
            | Mechanism::DesMac
            | Mechanism::Des2KeyGen
            | Mechanism::Des3KeyGen
            | Mechanism::Des3Ecb
            | Mechanism::Des3Cmac
            | Mechanism::Des3Mac
            | Mechanism::Md2
            | Mechanism::Md2Hmac
            | Mechanism::Md5
            | Mechanism::Md5Hmac
            | Mechanism::Sha1
            | Mechanism::Sha1Hmac
            | Mechanism::Ripemd128
            | Mechanism::Ripemd128Hmac
            | Mechanism::Ripemd160
            | Mechanism::Ripemd160Hmac
            | Mechanism::Sha256
            | Mechanism::Sha256Hmac
            | Mechanism::Sha224
            | Mechanism::Sha224Hmac
            | Mechanism::Sha384
            | Mechanism::Sha384Hmac
            | Mechanism::Sha512
            | Mechanism::Sha512Hmac
            | Mechanism::SecuridKeyGen
            | Mechanism::HotpKeyGen
            | Mechanism::ActiKeyGen
            | Mechanism::Rc5KeyGen
            | Mechanism::GenericSecretKeyGen
            | Mechanism::CamelliaKeyGen
            | Mechanism::CamelliaEcb
            | Mechanism::CamelliaMac
            | Mechanism::AriaKeyGen
            | Mechanism::AriaEcb
            | Mechanism::AriaMac
            | Mechanism::SeedKeyGen
            | Mechanism::SeedEcb
            | Mechanism::SeedMac
            | Mechanism::SkipjackKeyGen
            | Mechanism::SkipjackWrap
            | Mechanism::KeaKeyPairGen
            | Mechanism::FortezzaTimestamp
            | Mechanism::BatonKeyGen
            | Mechanism::BatonWrap
            | Mechanism::EcKeyPairGen
            | Mechanism::Ecdsa
            | Mechanism::EcdsaSha1
            | Mechanism::JuniperKeyGen
            | Mechanism::JuniperWrap
            | Mechanism::Fasthash
            | Mechanism::AesKeyGen
            | Mechanism::AesEcb
            | Mechanism::AesMac
            | Mechanism::AesCmacGeneral
            | Mechanism::AesXcbcMac
            | Mechanism::AesXcbcMac96
            | Mechanism::BlowfishKeyGen
            | Mechanism::TwofishKeyGen
            | Mechanism::Gostr3410KeyPairGen
            | Mechanism::Gostr3410
            | Mechanism::Gost28147KeyGen
            | Mechanism::Gost28147Ecb
            | Mechanism::DsaParameterGen
            | Mechanism::DhPkcsParameterGen
            | Mechanism::X9_42DhParameterGen
            | Mechanism::RsaPkcsTpm11
            | Mechanism::RsaPkcsOaepTpm11 => std::ptr::null_mut() as CK_VOID_PTR,

            Mechanism::DhPkcsDerive(param)
            | Mechanism::Gostr3410WithGostr3411(param)
            | Mechanism::Gostr3411(param)
            | Mechanism::Gostr3411Hmac(param) => param.as_ptr() as CK_VOID_PTR,

            Mechanism::RsaPkcsPss(param)
            | Mechanism::Sha1RsaPkcsPss(param)
            | Mechanism::Sha256RsaPkcsPss(param)
            | Mechanism::Sha384RsaPkcsPss(param)
            | Mechanism::Sha512RsaPkcsPss(param)
            | Mechanism::Sha224RsaPkcsPss(param) => {
                param as *const RsaPkcsPssParams as CK_VOID_PTR
            }

            Mechanism::WtlsPreMasterKeyGen(param) => param as *const Byte as CK_VOID_PTR,

            Mechanism::Sha512_224HmacGeneral(param)
            | Mechanism::Sha512_256HmacGeneral(param)
            | Mechanism::Sha512T(param)
            | Mechanism::Sha512THmac(param)
            | Mechanism::Sha512THmacGeneral(param)
            | Mechanism::Rc2Ecb(param)
            | Mechanism::Rc2Mac(param)
            | Mechanism::DesMacGeneral(param)
            | Mechanism::Des3MacGeneral(param)
            | Mechanism::Des3CmacGeneral(param)
            | Mechanism::Md2HmacGeneral(param)
            | Mechanism::Md5HmacGeneral(param)
            | Mechanism::Sha1HmacGeneral(param)
            | Mechanism::Ripemd128HmacGeneral(param)
            | Mechanism::Ripemd160HmacGeneral(param)
            | Mechanism::Sha256HmacGeneral(param)
            | Mechanism::Sha224HmacGeneral(param)
            | Mechanism::Sha384HmacGeneral(param)
            | Mechanism::Sha512HmacGeneral(param)
            | Mechanism::ConcatenateBaseAndKey(param)
            | Mechanism::ExtractKeyFromKey(param)
            | Mechanism::Ssl3Md5Mac(param)
            | Mechanism::Ssl3Sha1Mac(param)
            | Mechanism::CamelliaMacGeneral(param)
            | Mechanism::AriaMacGeneral(param)
            | Mechanism::SeedMacGeneral(param)
            | Mechanism::AesMacGeneral(param)
            | Mechanism::AesCmac(param) => param as *const u64 as CK_VOID_PTR,

            Mechanism::DesCbc(param)
            | Mechanism::DesCbcPad(param)
            | Mechanism::Des3Cbc(param)
            | Mechanism::Des3CbcPad(param)
            | Mechanism::DesOfb64(param)
            | Mechanism::DesOfb8(param)
            | Mechanism::DesCfb64(param)
            | Mechanism::DesCfb8(param)
            | Mechanism::BlowfishCbc(param)
            | Mechanism::BlowfishCbcPad(param)
            | Mechanism::Gost28147(param)
            | Mechanism::Gost28147Mac(param)
            | Mechanism::Gost28147KeyWrap(param) => param as *const _ as CK_VOID_PTR,

            Mechanism::AesGmac(param) => param as *const _ as CK_VOID_PTR,

            Mechanism::CamelliaCbc(param)
            | Mechanism::CamelliaCbcPad(param)
            | Mechanism::AriaCbc(param)
            | Mechanism::AriaCbcPad(param)
            | Mechanism::SeedCbc(param)
            | Mechanism::SeedCbcPad(param)
            | Mechanism::AesCbc(param)
            | Mechanism::AesCbcPad(param)
            | Mechanism::AesCts(param)
            | Mechanism::TwofishCbc(param)
            | Mechanism::TwofishCbcPad(param)
            | Mechanism::AesOfb(param)
            | Mechanism::AesCfb64(param)
            | Mechanism::AesCfb8(param)
            | Mechanism::AesCfb128(param) => param as *const _ as CK_VOID_PTR,

            Mechanism::SkipjackEcb64(param)
            | Mechanism::SkipjackCbc64(param)
            | Mechanism::SkipjackOfb64(param)
            | Mechanism::SkipjackCfb64(param)
            | Mechanism::SkipjackCfb32(param)
            | Mechanism::SkipjackCfb16(param)
            | Mechanism::SkipjackCfb8(param)
            | Mechanism::BatonEcb128(param)
            | Mechanism::BatonEcb96(param)
            | Mechanism::BatonCbc128(param)
            | Mechanism::BatonCounter(param)
            | Mechanism::BatonShuffle(param)
            | Mechanism::JuniperEcb128(param)
            | Mechanism::JuniperCbc128(param)
            | Mechanism::JuniperCounter(param)
            | Mechanism::JuniperShuffle(param) => param as *const _ as CK_VOID_PTR,

            Mechanism::Ecdh1Derive(param) | Mechanism::Ecdh1CofactorDerive(param) => {
                param as *const Ecdh1DeriveParams as CK_VOID_PTR
            }

            Mechanism::X9_42DhDerive(param) => {
                param as *const X92_42Dh1DeriveParams as CK_VOID_PTR
            }

            Mechanism::VendorDefined { param, .. } => param
                .map_or(std::ptr::null_mut() as CK_VOID_PTR, |p| {
                    p.as_ptr() as CK_VOID_PTR
                }),
        }
    }

    fn len(&self) -> Ulong {
        match self {
            // No param
            Mechanism::RsaPkcsKeyPairGen
            | Mechanism::RsaPkcs
            | Mechanism::Rsa9796
            | Mechanism::RsaX509
            | Mechanism::Md2RsaPkcs
            | Mechanism::Md5RsaPkcs
            | Mechanism::Sha1RsaPkcs
            | Mechanism::Ripemd128RsaPkcs
            | Mechanism::Ripemd160RsaPkcs
            | Mechanism::RsaX9_31KeyPairGen
            | Mechanism::RsaX9_31
            | Mechanism::Sha1RsaX9_31
            | Mechanism::DsaKeyPairGen
            | Mechanism::Dsa
            | Mechanism::DsaSha1
            | Mechanism::DsaSha224
            | Mechanism::DsaSha256
            | Mechanism::DsaSha384
            | Mechanism::DsaSha512
            | Mechanism::DhPkcsKeyPairGen
            | Mechanism::X9_42DhKeyPairGen
            | Mechanism::Sha256RsaPkcs
            | Mechanism::Sha384RsaPkcs
            | Mechanism::Sha512RsaPkcs
            | Mechanism::Sha224RsaPkcs
            | Mechanism::Sha512_224
            | Mechanism::Sha512_224Hmac
            | Mechanism::Sha512_256
            | Mechanism::Sha512_256Hmac
            | Mechanism::Rc2KeyGen
            | Mechanism::Rc4KeyGen
            | Mechanism::Rc4
            | Mechanism::DesKeyGen
            | Mechanism::DesEcb
            | Mechanism::DesMac
            | Mechanism::Des2KeyGen
            | Mechanism::Des3KeyGen
            | Mechanism::Des3Ecb
            | Mechanism::Des3Cmac
            | Mechanism::Des3Mac
            | Mechanism::Md2
            | Mechanism::Md2Hmac
            | Mechanism::Md5
            | Mechanism::Md5Hmac
            | Mechanism::Sha1
            | Mechanism::Sha1Hmac
            | Mechanism::Ripemd128
            | Mechanism::Ripemd128Hmac
            | Mechanism::Ripemd160
            | Mechanism::Ripemd160Hmac
            | Mechanism::Sha256
            | Mechanism::Sha256Hmac
            | Mechanism::Sha224
            | Mechanism::Sha224Hmac
            | Mechanism::Sha384
            | Mechanism::Sha384Hmac
            | Mechanism::Sha512
            | Mechanism::Sha512Hmac
            | Mechanism::SecuridKeyGen
            | Mechanism::HotpKeyGen
            | Mechanism::ActiKeyGen
            | Mechanism::Rc5KeyGen
            | Mechanism::GenericSecretKeyGen
            | Mechanism::CamelliaKeyGen
            | Mechanism::CamelliaEcb
            | Mechanism::CamelliaMac
            | Mechanism::AriaKeyGen
            | Mechanism::AriaEcb
            | Mechanism::AriaMac
            | Mechanism::SeedKeyGen
            | Mechanism::SeedEcb
            | Mechanism::SeedMac
            | Mechanism::SkipjackKeyGen
            | Mechanism::SkipjackWrap
            | Mechanism::KeaKeyPairGen
            | Mechanism::FortezzaTimestamp
            | Mechanism::BatonKeyGen
            | Mechanism::BatonWrap
            | Mechanism::EcKeyPairGen
            | Mechanism::Ecdsa
            | Mechanism::EcdsaSha1
            | Mechanism::JuniperKeyGen
            | Mechanism::JuniperWrap
            | Mechanism::Fasthash
            | Mechanism::AesKeyGen
            | Mechanism::AesEcb
            | Mechanism::AesMac
            | Mechanism::AesCmacGeneral
            | Mechanism::AesXcbcMac
            | Mechanism::AesXcbcMac96
            | Mechanism::BlowfishKeyGen
            | Mechanism::TwofishKeyGen
            | Mechanism::Gostr3410KeyPairGen
            | Mechanism::Gostr3410
            | Mechanism::Gost28147KeyGen
            | Mechanism::Gost28147Ecb
            | Mechanism::DsaParameterGen
            | Mechanism::DhPkcsParameterGen
            | Mechanism::X9_42DhParameterGen
            | Mechanism::RsaPkcsTpm11
            | Mechanism::RsaPkcsOaepTpm11 => 0 as Ulong,

            Mechanism::DhPkcsDerive(param)
            | Mechanism::Gostr3410WithGostr3411(param)
            | Mechanism::Gostr3411(param)
            | Mechanism::Gostr3411Hmac(param) => {
                (std::mem::size_of::<Byte>() * param.len()) as Ulong
            }

            Mechanism::RsaPkcsPss(_param)
            | Mechanism::Sha1RsaPkcsPss(_param)
            | Mechanism::Sha256RsaPkcsPss(_param)
            | Mechanism::Sha384RsaPkcsPss(_param)
            | Mechanism::Sha512RsaPkcsPss(_param)
            | Mechanism::Sha224RsaPkcsPss(_param) => {
                std::mem::size_of::<RsaPkcsPssParams>() as Ulong
            }

            Mechanism::WtlsPreMasterKeyGen(_param) => {
                std::mem::size_of::<Byte>() as Ulong
            }

            Mechanism::Sha512_224HmacGeneral(_param)
            | Mechanism::Sha512_256HmacGeneral(_param)
            | Mechanism::Sha512T(_param)
            | Mechanism::Sha512THmac(_param)
            | Mechanism::Sha512THmacGeneral(_param)
            | Mechanism::Rc2Ecb(_param)
            | Mechanism::Rc2Mac(_param)
            | Mechanism::DesMacGeneral(_param)
            | Mechanism::Des3MacGeneral(_param)
            | Mechanism::Des3CmacGeneral(_param)
            | Mechanism::Md2HmacGeneral(_param)
            | Mechanism::Md5HmacGeneral(_param)
            | Mechanism::Sha1HmacGeneral(_param)
            | Mechanism::Ripemd128HmacGeneral(_param)
            | Mechanism::Ripemd160HmacGeneral(_param)
            | Mechanism::Sha256HmacGeneral(_param)
            | Mechanism::Sha224HmacGeneral(_param)
            | Mechanism::Sha384HmacGeneral(_param)
            | Mechanism::Sha512HmacGeneral(_param)
            | Mechanism::ConcatenateBaseAndKey(_param)
            | Mechanism::ExtractKeyFromKey(_param)
            | Mechanism::Ssl3Md5Mac(_param)
            | Mechanism::Ssl3Sha1Mac(_param)
            | Mechanism::CamelliaMacGeneral(_param)
            | Mechanism::AriaMacGeneral(_param)
            | Mechanism::SeedMacGeneral(_param)
            | Mechanism::AesMacGeneral(_param)
            | Mechanism::AesCmac(_param) => std::mem::size_of::<Ulong>() as Ulong,

            Mechanism::DesCbc(_param)
            | Mechanism::DesCbcPad(_param)
            | Mechanism::Des3Cbc(_param)
            | Mechanism::Des3CbcPad(_param)
            | Mechanism::DesOfb64(_param)
            | Mechanism::DesOfb8(_param)
            | Mechanism::DesCfb64(_param)
            | Mechanism::DesCfb8(_param)
            | Mechanism::BlowfishCbc(_param)
            | Mechanism::BlowfishCbcPad(_param)
            | Mechanism::Gost28147(_param)
            | Mechanism::Gost28147Mac(_param)
            | Mechanism::Gost28147KeyWrap(_param) => {
                std::mem::size_of::<[u8; 8]>() as Ulong
            }

            Mechanism::AesGmac(_param) => std::mem::size_of::<[u8; 12]>() as Ulong,

            Mechanism::CamelliaCbc(_param)
            | Mechanism::CamelliaCbcPad(_param)
            | Mechanism::AriaCbc(_param)
            | Mechanism::AriaCbcPad(_param)
            | Mechanism::SeedCbc(_param)
            | Mechanism::SeedCbcPad(_param)
            | Mechanism::AesCbc(_param)
            | Mechanism::AesCbcPad(_param)
            | Mechanism::AesCts(_param)
            | Mechanism::TwofishCbc(_param)
            | Mechanism::TwofishCbcPad(_param)
            | Mechanism::AesOfb(_param)
            | Mechanism::AesCfb64(_param)
            | Mechanism::AesCfb8(_param)
            | Mechanism::AesCfb128(_param) => std::mem::size_of::<[u8; 16]>() as Ulong,

            Mechanism::SkipjackEcb64(_param)
            | Mechanism::SkipjackCbc64(_param)
            | Mechanism::SkipjackOfb64(_param)
            | Mechanism::SkipjackCfb64(_param)
            | Mechanism::SkipjackCfb32(_param)
            | Mechanism::SkipjackCfb16(_param)
            | Mechanism::SkipjackCfb8(_param)
            | Mechanism::BatonEcb128(_param)
            | Mechanism::BatonEcb96(_param)
            | Mechanism::BatonCbc128(_param)
            | Mechanism::BatonCounter(_param)
            | Mechanism::BatonShuffle(_param)
            | Mechanism::JuniperEcb128(_param)
            | Mechanism::JuniperCbc128(_param)
            | Mechanism::JuniperCounter(_param)
            | Mechanism::JuniperShuffle(_param) => {
                std::mem::size_of::<[u8; 24]>() as Ulong
            }

            Mechanism::Ecdh1Derive(_param) | Mechanism::Ecdh1CofactorDerive(_param) => {
                std::mem::size_of::<Ecdh1DeriveParams>() as Ulong
            }

            Mechanism::X9_42DhDerive(_param) => {
                std::mem::size_of::<X92_42Dh1DeriveParams>() as Ulong
            }

            Mechanism::VendorDefined { param, .. } => {
                param.map_or(0, |p| std::mem::size_of_val(p) as Ulong)
            }
        }
    }
}

impl From<&Mechanism<'_>> for CK_MECHANISM {
    fn from(mechanism: &Mechanism) -> Self {
        Self {
            mechanism: mechanism.mechanism_type().into(),
            pParameter: mechanism.ptr(),
            ulParameterLen: mechanism.len(),
        }
    }
}

// No out Mechanism
// impl !TryFrom<CK_MECHANISM> for Mechanism<'_> {}

// CK_MECHANISM_INFO

bitflags! {
    /// Flags specifying mechanism capabilities for [`CK_MECHANISM_INFO`].
    #[derive(Debug, Clone)]
    pub struct MechanismInfoFlags: CK_FLAGS {
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
    /// The minimum size of the key for the mechanism (whether this is
    /// measured in bits or in bytes is mechanism-dependent).
    /// For some mechanisms has meaningless values.
    pub min_key_size: Ulong,
    /// The maximum size of the key for the mechanism (whether this is
    /// measured in bits or in bytes is mechanism-dependent).
    /// For some mechanisms has meaningless values.
    pub max_key_size: Ulong,
    /// Flags specifying mechanism capabilities.
    pub flags: MechanismInfoFlags,
}

impl MechanismInfo {
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
            min_key_size: ck_mechanism_info.ulMinKeySize,
            max_key_size: ck_mechanism_info.ulMaxKeySize,
            flags: MechanismInfoFlags::from_bits_truncate(ck_mechanism_info.flags),
        }
    }
}

// CK_EC_KDF_TYPE, CK_X9_42_DH_KDF_TYPE

// TODO: add vendor defined
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyDerivationFunctionType(CK_ULONG);

// TODO: add missing types
/// Identifies the classes (or types) of objects that Cryptoki recognizes.
impl KeyDerivationFunctionType {
    pub const NULL: KeyDerivationFunctionType = KeyDerivationFunctionType(CKD_NULL);
    pub const SHA1_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA1_KDF);
    pub const SHA1_KDF_ASN1: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA1_KDF_ASN1);
    pub const SHA1_KDF_CONCATENATE: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA1_KDF_CONCATENATE);
    pub const SHA224_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA224_KDF);
    pub const SHA256_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA256_KDF);
    pub const SHA384_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA384_KDF);
    pub const SHA512_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_SHA512_KDF);
    pub const CPDIVERSIFY_KDF: KeyDerivationFunctionType =
        KeyDerivationFunctionType(CKD_CPDIVERSIFY_KDF);
}

impl Deref for KeyDerivationFunctionType {
    type Target = CK_ULONG;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<KeyDerivationFunctionType> for CK_ULONG {
    fn from(kdf: KeyDerivationFunctionType) -> Self {
        *kdf
    }
}

impl std::fmt::Display for KeyDerivationFunctionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            KeyDerivationFunctionType::NULL => write!(f, "CKD_NULL"),
            KeyDerivationFunctionType::SHA1_KDF => write!(f, "CKD_SHA1_KDF"),
            KeyDerivationFunctionType::SHA1_KDF_ASN1 => write!(f, "CKD_SHA1_KDF_ASN1"),
            KeyDerivationFunctionType::SHA1_KDF_CONCATENATE => {
                write!(f, "CKD_SHA1_KDF_CONCATENATE")
            }
            KeyDerivationFunctionType::SHA224_KDF => write!(f, "CKD_SHA224_KDF"),
            KeyDerivationFunctionType::SHA256_KDF => write!(f, "CKD_SHA256_KDF"),
            KeyDerivationFunctionType::SHA384_KDF => write!(f, "CKD_SHA384_KDF"),
            KeyDerivationFunctionType::SHA512_KDF => write!(f, "CKD_SHA512_KDF"),
            KeyDerivationFunctionType::CPDIVERSIFY_KDF => {
                write!(f, "CKD_CPDIVERSIFY_KDF")
            }
            _ => write!(f, "Unknown key derivation type"),
        }
    }
}

impl TryFrom<CK_ULONG> for KeyDerivationFunctionType {
    type Error = Error;

    fn try_from(kdf: CK_ULONG) -> Result<Self> {
        match kdf {
            CKD_NULL => Ok(KeyDerivationFunctionType::NULL),
            CKD_SHA1_KDF => Ok(KeyDerivationFunctionType::SHA1_KDF),
            CKD_SHA1_KDF_ASN1 => Ok(KeyDerivationFunctionType::SHA1_KDF_ASN1),
            CKD_SHA1_KDF_CONCATENATE => {
                Ok(KeyDerivationFunctionType::SHA1_KDF_CONCATENATE)
            }
            CKD_SHA224_KDF => Ok(KeyDerivationFunctionType::SHA224_KDF),
            CKD_SHA256_KDF => Ok(KeyDerivationFunctionType::SHA256_KDF),
            CKD_SHA384_KDF => Ok(KeyDerivationFunctionType::SHA384_KDF),
            CKD_SHA512_KDF => Ok(KeyDerivationFunctionType::SHA512_KDF),
            CKD_CPDIVERSIFY_KDF => Ok(KeyDerivationFunctionType::CPDIVERSIFY_KDF),
            _ => {
                eprintln!("Undefined ({:#X}) key derivation type", kdf);
                Err(Error::NotSupported)
            }
        }
    }
}

// Params

/// Key Derivation Function (KDF) applied to derive keying data
/// from a shared secret.
///
/// The key derivation function will be used by the EC or
/// X9.42 Diffie-Hellman key agreement schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDerivationFunction<'a> {
    kdf_type: KeyDerivationFunctionType,
    shared_data: Option<&'a [Byte]>,
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
        shared_data: Option<&'a [Byte]>,
    ) -> Result<Self> {
        let _shr_data_len = shared_data.map_or(0, <[Byte]>::len);
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
    shared_data: *const Byte,
    /// The length in bytes of the other party's EC public key
    public_data_len: Ulong,
    /// Pointer to other party's EC public key value.
    public_data: *const Byte,
    /// Phantom type
    _phantom: std::marker::PhantomData<&'a [Byte]>,
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
    pub fn new(kdf: KeyDerivationFunction<'a>, public_data: &'a [Byte]) -> Self {
        Self {
            kdf: kdf.kdf_type,
            shared_data_len: kdf.shared_data.map_or(0, <[Byte]>::len) as Ulong,
            shared_data: kdf.shared_data.map_or(std::ptr::null(), <[Byte]>::as_ptr),
            public_data_len: public_data.len() as Ulong,
            public_data: public_data.as_ptr(),
            _phantom: std::marker::PhantomData,
        }
    }
}

// CK_X9_42_DH1_DERIVE_PARAMS

/// Structure that provides the parameters for the [`Mechanism::X9_42DhDerive`]
/// key derivation mechanisms, where each party contributes one key pair.
#[derive(Copy, Debug, Clone)]
#[repr(C)]
pub struct X92_42Dh1DeriveParams<'a> {
    /// Key derivation function used on the shared secret value
    kdf: KeyDerivationFunctionType,
    /// The length in bytes of the other info. [Optional]
    other_info_len: Ulong,
    /// Pointer to some data shared between the two parties [Optional]
    other_info: *const Byte,
    /// The length in bytes of the other party's X9.42 Diffie-Hellman
    /// public key
    public_data_len: Ulong,
    /// Pointer to other party's X9.42 Diffie-Hellman public key value.
    public_data: *const Byte,
    /// Phantom type
    _phantom: std::marker::PhantomData<&'a [Byte]>,
}

impl<'a> X92_42Dh1DeriveParams<'a> {
    /// Construct X9_42_DH derivation parameters.
    ///
    /// # Parameters
    ///
    /// * `kdf` - The key derivation function to use.
    /// * `public_data` - The other party's X9.42 Diffie-Hellman public key value.
    pub fn new(kdf: KeyDerivationFunction<'a>, public_data: &'a [Byte]) -> Self {
        Self {
            kdf: kdf.kdf_type,
            other_info_len: kdf.shared_data.map_or(0, <[Byte]>::len) as Ulong,
            other_info: kdf.shared_data.map_or(std::ptr::null(), <[Byte]>::as_ptr),
            public_data_len: public_data.len() as Ulong,
            public_data: public_data.as_ptr(),
            _phantom: std::marker::PhantomData,
        }
    }
}

// CK_RSA_PKCS_MGF_TYPE

/// Indicate the Message Generation Function (MGF) applied to a message block
/// when formatting a message block for the PKCS #1 OAEP encryption scheme or
/// the PKCS #1 PSS signature scheme.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct RsaPkcsMgfType(CK_RSA_PKCS_MGF_TYPE);

/// Identifies the classes (or types) of objects that Cryptoki recognizes.
impl RsaPkcsMgfType {
    pub const MGF1_SHA1: RsaPkcsMgfType = RsaPkcsMgfType(CKG_MGF1_SHA1);
    pub const MGF1_SHA224: RsaPkcsMgfType = RsaPkcsMgfType(CKG_MGF1_SHA224);
    pub const MGF1_SHA256: RsaPkcsMgfType = RsaPkcsMgfType(CKG_MGF1_SHA256);
    pub const MGF1_SHA384: RsaPkcsMgfType = RsaPkcsMgfType(CKG_MGF1_SHA384);
    pub const MGF1_SHA512: RsaPkcsMgfType = RsaPkcsMgfType(CKG_MGF1_SHA512);
}

impl Deref for RsaPkcsMgfType {
    type Target = CK_RSA_PKCS_MGF_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<RsaPkcsMgfType> for CK_RSA_PKCS_MGF_TYPE {
    fn from(mgf: RsaPkcsMgfType) -> Self {
        *mgf
    }
}

impl std::fmt::Display for RsaPkcsMgfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RsaPkcsMgfType::MGF1_SHA1 => write!(f, "CKG_MGF1_SHA1"),
            RsaPkcsMgfType::MGF1_SHA224 => write!(f, "CKG_MGF1_SHA224"),
            RsaPkcsMgfType::MGF1_SHA256 => write!(f, "CKG_MGF1_SHA256"),
            RsaPkcsMgfType::MGF1_SHA384 => {
                write!(f, "CKG_MGF1_SHA384")
            }
            RsaPkcsMgfType::MGF1_SHA512 => write!(f, "CKG_MGF1_SHA512"),
            _ => write!(f, "Unknown message generation function"),
        }
    }
}

impl TryFrom<CK_RSA_PKCS_MGF_TYPE> for RsaPkcsMgfType {
    type Error = Error;

    fn try_from(mgf: CK_RSA_PKCS_MGF_TYPE) -> Result<Self> {
        match mgf {
            CKG_MGF1_SHA1 => Ok(RsaPkcsMgfType::MGF1_SHA1),
            CKG_MGF1_SHA224 => Ok(RsaPkcsMgfType::MGF1_SHA224),
            CKG_MGF1_SHA256 => Ok(RsaPkcsMgfType::MGF1_SHA256),
            CKG_MGF1_SHA384 => Ok(RsaPkcsMgfType::MGF1_SHA384),
            CKG_MGF1_SHA512 => Ok(RsaPkcsMgfType::MGF1_SHA512),
            _ => {
                eprintln!("Undefined ({:#X}) message generation function", mgf);
                Err(Error::NotSupported)
            }
        }
    }
}

/// Parameters of the RsaPkcsPss mechanism
pub type RsaPkcsPssParams = CK_RSA_PKCS_PSS_PARAMS;

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
            hashAlg: hash_alg.into(),
            mgf: mgf.into(),
            sLen: s_len,
        }
    }
}
