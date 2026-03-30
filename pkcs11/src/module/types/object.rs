use std::{convert::TryFrom, ops::Deref};

use crate::error::{Error, Result};

use super::{general::*, MechanismType};

pub type ObjectHandle = CK_OBJECT_HANDLE;

// CK_OBJECT_CLASS

/// Identifies the classes (or types) of objects that Cryptoki recognizes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObjectClass(CK_OBJECT_CLASS);

impl ObjectClass {
    /// Data objects hold information defined by an application.
    pub const DATA: ObjectClass = ObjectClass(CKO_DATA);
    /// Certificate objects hold public-key or attribute certificates.
    pub const CERTIFICATE: ObjectClass = ObjectClass(CKO_CERTIFICATE);
    /// Public key object.
    pub const PUBLIC_KEY: ObjectClass = ObjectClass(CKO_PUBLIC_KEY);
    /// Private key object.
    pub const PRIVATE_KEY: ObjectClass = ObjectClass(CKO_PRIVATE_KEY);
    /// Secret key object.
    pub const SECRET_KEY: ObjectClass = ObjectClass(CKO_SECRET_KEY);
    /// Hardware feature objects represent features of the device.
    pub const HW_FEATURE: ObjectClass = ObjectClass(CKO_HW_FEATURE);
    /// Domain parameter objects hold public domain parameters.
    pub const DOMAIN_PARAMETERS: ObjectClass = ObjectClass(CKO_DOMAIN_PARAMETERS);
    /// Mechanism objects provide information about mechanisms
    /// supported by a device beyond that given by
    /// the CK_MECHANISM_INFO structure.
    pub const MECHANISM: ObjectClass = ObjectClass(CKO_MECHANISM);
    /// OTP key object.
    pub const OTP_KEY: ObjectClass = ObjectClass(CKO_OTP_KEY);
}

impl ObjectClass {
    pub fn new_vendor_defined(value: CK_OBJECT_CLASS) -> Result<ObjectClass> {
        if value >= CKO_VENDOR_DEFINED {
            Ok(ObjectClass(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKO_VENDOR_DEFINED
    }
}

impl Deref for ObjectClass {
    type Target = CK_OBJECT_CLASS;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ObjectClass> for CK_OBJECT_CLASS {
    fn from(object_class: ObjectClass) -> Self {
        *object_class
    }
}

impl std::fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ObjectClass::DATA => write!(f, "CKO_DATA"),
            ObjectClass::CERTIFICATE => write!(f, "CKO_CERTIFICATE"),
            ObjectClass::PUBLIC_KEY => write!(f, "CKO_PUBLIC_KEY"),
            ObjectClass::PRIVATE_KEY => write!(f, "CKO_PRIVATE_KEY"),
            ObjectClass::SECRET_KEY => write!(f, "CKO_SECRET_KEY"),
            ObjectClass::HW_FEATURE => write!(f, "CKO_HW_FEATURE"),
            ObjectClass::DOMAIN_PARAMETERS => write!(f, "CKO_DOMAIN_PARAMETERS"),
            ObjectClass::MECHANISM => write!(f, "CKO_MECHANISM"),
            ObjectClass::OTP_KEY => write!(f, "CKO_OTP_KEY"),
            _ if self.is_vendor_defined() => {
                write!(f, "CKO_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown object type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_OBJECT_CLASS> for ObjectClass {
    type Error = Error;

    fn try_from(object_class: CK_OBJECT_CLASS) -> Result<Self> {
        match object_class {
            CKO_DATA => Ok(ObjectClass::DATA),
            CKO_CERTIFICATE => Ok(ObjectClass::CERTIFICATE),
            CKO_PUBLIC_KEY => Ok(ObjectClass::PUBLIC_KEY),
            CKO_PRIVATE_KEY => Ok(ObjectClass::PRIVATE_KEY),
            CKO_SECRET_KEY => Ok(ObjectClass::SECRET_KEY),
            CKO_HW_FEATURE => Ok(ObjectClass::HW_FEATURE),
            CKO_DOMAIN_PARAMETERS => Ok(ObjectClass::DOMAIN_PARAMETERS),
            CKO_MECHANISM => Ok(ObjectClass::MECHANISM),
            CKO_OTP_KEY => Ok(ObjectClass::OTP_KEY),
            CKO_VENDOR_DEFINED..=CK_OBJECT_CLASS::MAX => Ok(ObjectClass(object_class)),
            _ => Err(Error::NotSupported),
        }
    }
}

// CK_HW_FEATURE_TYPE

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct HwFeatureType(CK_HW_FEATURE_TYPE);

/// Identifies the classes (or types) of objects that Cryptoki recognizes.
impl HwFeatureType {
    /// Monotonic counter objects represent hardware counters that exist on
    /// the device. The counter is guaranteed to increase each time its value
    /// is read, but not necessarily by one. This might be used by an
    /// application for generating serial numbers to get some
    /// assurance of uniqueness per token.
    pub const MONOTONIC_COUNTER: HwFeatureType = HwFeatureType(CKH_MONOTONIC_COUNTER);
    /// Clock objects represent real-time clocks that exist on the device.
    /// This represents the same clock source as the utcTime field
    /// in the CK_TOKEN_INFO structure.
    pub const CLOCK: HwFeatureType = HwFeatureType(CKH_CLOCK);
    /// User interface objects represent the presentation
    /// capabilities of the device.
    pub const USER_INTERFACE: HwFeatureType = HwFeatureType(CKH_USER_INTERFACE);
}

impl HwFeatureType {
    pub fn new_vendor_defined(value: CK_HW_FEATURE_TYPE) -> Result<HwFeatureType> {
        if value >= CKH_VENDOR_DEFINED {
            Ok(HwFeatureType(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKH_VENDOR_DEFINED
    }
}

impl Deref for HwFeatureType {
    type Target = CK_HW_FEATURE_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HwFeatureType> for CK_HW_FEATURE_TYPE {
    fn from(hw_feature_type: HwFeatureType) -> Self {
        *hw_feature_type
    }
}

impl std::fmt::Display for HwFeatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            HwFeatureType::MONOTONIC_COUNTER => write!(f, "CKH_MONOTONIC_COUNTER"),
            HwFeatureType::CLOCK => write!(f, "CKH_CLOCK"),
            HwFeatureType::USER_INTERFACE => write!(f, "CKH_USER_INTERFACE"),
            _ if self.is_vendor_defined() => {
                write!(f, "CKH_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown hardware feature type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_HW_FEATURE_TYPE> for HwFeatureType {
    type Error = Error;

    fn try_from(hw_feature_type: CK_HW_FEATURE_TYPE) -> Result<Self> {
        match hw_feature_type {
            CKH_MONOTONIC_COUNTER => Ok(HwFeatureType::MONOTONIC_COUNTER),
            CKH_CLOCK => Ok(HwFeatureType::CLOCK),
            CKH_USER_INTERFACE => Ok(HwFeatureType::USER_INTERFACE),
            CKH_VENDOR_DEFINED..=CK_HW_FEATURE_TYPE::MAX => {
                Ok(HwFeatureType(hw_feature_type))
            }
            _ => Err(Error::NotSupported),
        }
    }
}

// CK_KEY_TYPE

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyType(CK_KEY_TYPE);

// TODO: add missing types
/// Identifies the classes (or types) of objects that Cryptoki recognizes.
impl KeyType {
    /// RSA key.
    pub const RSA: KeyType = KeyType(CKK_RSA);
    /// DSA key.
    pub const DSA: KeyType = KeyType(CKK_DSA);
    /// DH key.
    pub const DH: KeyType = KeyType(CKK_DH);
    /// EC key.
    pub const EC: KeyType = KeyType(CKK_EC);
    /// X9_42_DH key.
    pub const X9_42_DH: KeyType = KeyType(CKK_X9_42_DH);
    /// KEA key.
    pub const KEA: KeyType = KeyType(CKK_KEA);
    /// Generic Secret key.
    pub const GENERIC_SECRET: KeyType = KeyType(CKK_GENERIC_SECRET);
    /// RC2 key.
    pub const RC2: KeyType = KeyType(CKK_RC2);
    /// RC4 key.
    pub const RC4: KeyType = KeyType(CKK_RC4);
    /// DES key.
    pub const DES: KeyType = KeyType(CKK_DES);
    /// DES2 key.
    pub const DES2: KeyType = KeyType(CKK_DES2);
    /// DES3 secret.
    pub const DES3: KeyType = KeyType(CKK_DES3);
    /// CAST key.
    pub const CAST: KeyType = KeyType(CKK_CAST);
    /// CAST3 key.
    pub const CAST3: KeyType = KeyType(CKK_CAST3);
    /// CAST128 key.
    pub const CAST128: KeyType = KeyType(CKK_CAST128);
    /// RC5 key.
    pub const RC5: KeyType = KeyType(CKK_RC5);
    /// IDEA key.
    pub const IDEA: KeyType = KeyType(CKK_IDEA);
    /// SKIPJACK key.
    pub const SKIPJACK: KeyType = KeyType(CKK_SKIPJACK);
    /// BATON key.
    pub const BATON: KeyType = KeyType(CKK_BATON);
    /// JUNIPER key.
    pub const JUNIPER: KeyType = KeyType(CKK_JUNIPER);
    /// CDMF key.
    pub const CDMF: KeyType = KeyType(CKK_CDMF);
    /// AES key.
    pub const AES: KeyType = KeyType(CKK_AES);
    /// BLOWFISH key.
    pub const BLOWFISH: KeyType = KeyType(CKK_BLOWFISH);
    /// TWOFISH key.
    pub const TWOFISH: KeyType = KeyType(CKK_TWOFISH);
    /// SECURID key.
    pub const SECURID: KeyType = KeyType(CKK_SECURID);
    /// HOTP key.
    pub const HOTP: KeyType = KeyType(CKK_HOTP);
    /// ACTI key.
    pub const ACTI: KeyType = KeyType(CKK_ACTI);
    /// CAMELLIA key.
    pub const CAMELLIA: KeyType = KeyType(CKK_CAMELLIA);
    /// ARIA key.
    pub const ARIA: KeyType = KeyType(CKK_ARIA);
    /// MD5 HMAC key.
    pub const MD5_HMAC: KeyType = KeyType(CKK_MD5_HMAC);
    /// SHA1 HMAC key.
    pub const SHA_1_HMAC: KeyType = KeyType(CKK_SHA_1_HMAC);
    /// RIPEMD128 HMAC key.
    pub const RIPEMD128_HMAC: KeyType = KeyType(CKK_RIPEMD128_HMAC);
    /// RIPEMD160 HMAC key.
    pub const RIPEMD160_HMAC: KeyType = KeyType(CKK_RIPEMD160_HMAC);
    /// SHA256 HMAC key.
    pub const SHA256_HMAC: KeyType = KeyType(CKK_SHA256_HMAC);
    /// SHA384 HMAC key.
    pub const SHA384_HMAC: KeyType = KeyType(CKK_SHA384_HMAC);
    /// SHA512 HMAC key.
    pub const SHA512_HMAC: KeyType = KeyType(CKK_SHA512_HMAC);
    /// SHA224 HMAC key.
    pub const SHA224_HMAC: KeyType = KeyType(CKK_SHA224_HMAC);
    /// SEED key.
    pub const SEED: KeyType = KeyType(CKK_SEED);
    /// GOSTR3410 key.
    pub const GOSTR3410: KeyType = KeyType(CKK_GOSTR3410);
    /// GOSTR3411 key.
    pub const GOSTR3411: KeyType = KeyType(CKK_GOSTR3411);
    /// GOST28147 key.
    pub const GOST28147: KeyType = KeyType(CKK_GOST28147);
}

impl KeyType {
    pub fn new_vendor_defined(value: CK_KEY_TYPE) -> Result<KeyType> {
        if value >= CKK_VENDOR_DEFINED {
            Ok(KeyType(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKK_VENDOR_DEFINED
    }
}

impl Deref for KeyType {
    type Target = CK_KEY_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<KeyType> for CK_KEY_TYPE {
    fn from(key_type: KeyType) -> Self {
        *key_type
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            KeyType::RSA => write!(f, "CKK_RSA"),
            KeyType::DSA => write!(f, "CKK_DSA"),
            KeyType::DH => write!(f, "CKK_DH"),
            KeyType::EC => write!(f, "CKK_EC"),
            KeyType::X9_42_DH => write!(f, "CKK_X9_42_DH"),
            KeyType::KEA => write!(f, "CKK_KEA"),
            KeyType::GENERIC_SECRET => write!(f, "CKK_GENERIC_SECRET"),
            KeyType::RC2 => write!(f, "CKK_RC2"),
            KeyType::RC4 => write!(f, "CKK_RC4"),
            KeyType::DES => write!(f, "CKK_DES"),
            KeyType::DES2 => write!(f, "CKK_DES2"),
            KeyType::DES3 => write!(f, "CKK_DES3"),
            KeyType::CAST => write!(f, "CKK_CAST"),
            KeyType::CAST3 => write!(f, "CKK_CAST3"),
            KeyType::CAST128 => write!(f, "CKK_CAST128"),
            KeyType::RC5 => write!(f, "CKK_RC5"),
            KeyType::IDEA => write!(f, "CKK_IDEA"),
            KeyType::SKIPJACK => write!(f, "CKK_SKIPJACK"),
            KeyType::BATON => write!(f, "CKK_BATON"),
            KeyType::JUNIPER => write!(f, "CKK_JUNIPER"),
            KeyType::CDMF => write!(f, "CKK_CDMF"),
            KeyType::AES => write!(f, "CKK_AES"),
            KeyType::BLOWFISH => write!(f, "CKK_BLOWFISH"),
            KeyType::TWOFISH => write!(f, "CKK_TWOFISH"),
            KeyType::SECURID => write!(f, "CKK_SECURID"),
            KeyType::HOTP => write!(f, "CKK_HOTP"),
            KeyType::ACTI => write!(f, "CKK_ACTI"),
            KeyType::CAMELLIA => write!(f, "CKK_CAMELLIA"),
            KeyType::ARIA => write!(f, "CKK_ARIA"),
            KeyType::MD5_HMAC => write!(f, "CKK_MD5_HMAC"),
            KeyType::SHA_1_HMAC => write!(f, "CKK_SHA_1_HMAC"),
            KeyType::RIPEMD128_HMAC => write!(f, "CKK_RIPEMD128_HMAC"),
            KeyType::RIPEMD160_HMAC => write!(f, "CKK_RIPEMD160_HMAC"),
            KeyType::SHA256_HMAC => write!(f, "CKK_SHA256_HMAC"),
            KeyType::SHA384_HMAC => write!(f, "CKK_SHA384_HMAC"),
            KeyType::SHA512_HMAC => write!(f, "CKK_SHA512_HMAC"),
            KeyType::SHA224_HMAC => write!(f, "CKK_SHA224_HMAC"),
            KeyType::SEED => write!(f, "CKK_SEED"),
            KeyType::GOSTR3410 => write!(f, "CKK_GOSTR3410"),
            KeyType::GOSTR3411 => write!(f, "CKK_GOSTR3411"),
            KeyType::GOST28147 => write!(f, "CKK_GOST28147"),
            _ if self.is_vendor_defined() => {
                write!(f, "CKK_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown key type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_KEY_TYPE> for KeyType {
    type Error = Error;

    fn try_from(key_type: CK_KEY_TYPE) -> Result<Self> {
        match key_type {
            CKK_RSA => Ok(KeyType::RSA),
            CKK_DSA => Ok(KeyType::DSA),
            CKK_DH => Ok(KeyType::DH),
            CKK_EC => Ok(KeyType::EC),
            CKK_X9_42_DH => Ok(KeyType::X9_42_DH),
            CKK_KEA => Ok(KeyType::KEA),
            CKK_GENERIC_SECRET => Ok(KeyType::GENERIC_SECRET),
            CKK_RC2 => Ok(KeyType::RC2),
            CKK_RC4 => Ok(KeyType::RC4),
            CKK_DES => Ok(KeyType::DES),
            CKK_DES2 => Ok(KeyType::DES2),
            CKK_DES3 => Ok(KeyType::DES3),
            CKK_CAST => Ok(KeyType::CAST),
            CKK_CAST3 => Ok(KeyType::CAST3),
            CKK_CAST128 => Ok(KeyType::CAST128),
            CKK_RC5 => Ok(KeyType::RC5),
            CKK_IDEA => Ok(KeyType::IDEA),
            CKK_SKIPJACK => Ok(KeyType::SKIPJACK),
            CKK_BATON => Ok(KeyType::BATON),
            CKK_JUNIPER => Ok(KeyType::JUNIPER),
            CKK_CDMF => Ok(KeyType::CDMF),
            CKK_AES => Ok(KeyType::AES),
            CKK_BLOWFISH => Ok(KeyType::BLOWFISH),
            CKK_TWOFISH => Ok(KeyType::TWOFISH),
            CKK_SECURID => Ok(KeyType::SECURID),
            CKK_HOTP => Ok(KeyType::HOTP),
            CKK_ACTI => Ok(KeyType::ACTI),
            CKK_CAMELLIA => Ok(KeyType::CAMELLIA),
            CKK_ARIA => Ok(KeyType::ARIA),
            CKK_MD5_HMAC => Ok(KeyType::MD5_HMAC),
            CKK_SHA_1_HMAC => Ok(KeyType::SHA_1_HMAC),
            CKK_RIPEMD128_HMAC => Ok(KeyType::RIPEMD128_HMAC),
            CKK_RIPEMD160_HMAC => Ok(KeyType::RIPEMD160_HMAC),
            CKK_SHA256_HMAC => Ok(KeyType::SHA256_HMAC),
            CKK_SHA384_HMAC => Ok(KeyType::SHA384_HMAC),
            CKK_SHA512_HMAC => Ok(KeyType::SHA512_HMAC),
            CKK_SHA224_HMAC => Ok(KeyType::SHA224_HMAC),
            CKK_SEED => Ok(KeyType::SEED),
            CKK_GOSTR3410 => Ok(KeyType::GOSTR3410),
            CKK_GOSTR3411 => Ok(KeyType::GOSTR3411),
            CKK_GOST28147 => Ok(KeyType::GOST28147),
            CKK_VENDOR_DEFINED..=CK_KEY_TYPE::MAX => Ok(KeyType(key_type)),
            _ => Err(Error::NotSupported),
        }
    }
}

// CK_CERTIFICATE_TYPE

/// Identifies a certificate type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct CertificateType(CK_CERTIFICATE_TYPE);

impl CertificateType {
    /// X.509 certificate objects hold X.509 public key certificates.
    pub const X_509: CertificateType = CertificateType(CKC_X_509);
    /// X.509 attribute certificate objects hold X.509 attribute certificates.
    pub const X_509_ATTR_CERT: CertificateType = CertificateType(CKC_X_509_ATTR_CERT);
    /// WTLS certificate objects hold WTLS public key certificates.
    pub const WTLS: CertificateType = CertificateType(CKC_WTLS);
}

impl CertificateType {
    pub fn new_vendor_defined(value: CK_CERTIFICATE_TYPE) -> Result<CertificateType> {
        if value >= CKC_VENDOR_DEFINED {
            Ok(CertificateType(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKC_VENDOR_DEFINED
    }
}

impl Deref for CertificateType {
    type Target = CK_CERTIFICATE_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<CertificateType> for CK_CERTIFICATE_TYPE {
    fn from(certificate_type: CertificateType) -> Self {
        *certificate_type
    }
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            CertificateType::X_509 => write!(f, "CKC_X_509"),
            CertificateType::X_509_ATTR_CERT => write!(f, "CKC_X_509_ATTR_CERT"),
            CertificateType::WTLS => write!(f, "CKC_WTLS"),
            _ if self.is_vendor_defined() => {
                write!(f, "CKC_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown certificate type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_CERTIFICATE_TYPE> for CertificateType {
    type Error = Error;

    fn try_from(certificate_type: CK_CERTIFICATE_TYPE) -> Result<Self> {
        match certificate_type {
            CKC_X_509 => Ok(CertificateType::X_509),
            CKC_X_509_ATTR_CERT => Ok(CertificateType::X_509_ATTR_CERT),
            CKC_WTLS => Ok(CertificateType::WTLS),
            CKC_VENDOR_DEFINED..=CK_CERTIFICATE_TYPE::MAX => {
                Ok(CertificateType(certificate_type))
            }
            _ => Err(Error::NotSupported),
        }
    }
}

// CK_CERTIFICATE_CATEGORY

/// Identifies a certificate category.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct CertificateCategory(CK_CERTIFICATE_CATEGORY);

impl CertificateCategory {
    /// No category specified.
    pub const UNSPECIFIED: CertificateCategory =
        CertificateCategory(CK_CERTIFICATE_CATEGORY_UNSPECIFIED);
    /// Certificate belongs to owner of the token.
    pub const TOKEN_USER: CertificateCategory =
        CertificateCategory(CK_CERTIFICATE_CATEGORY_TOKEN_USER);
    /// Certificate belongs to a certificate authority.
    pub const AUTHORITY: CertificateCategory =
        CertificateCategory(CK_CERTIFICATE_CATEGORY_AUTHORITY);
    /// Certificate belongs to an end entity (i.e.: not a CA).
    pub const OTHER_ENTITY: CertificateCategory =
        CertificateCategory(CK_CERTIFICATE_CATEGORY_OTHER_ENTITY);
}

impl Deref for CertificateCategory {
    type Target = CK_CERTIFICATE_CATEGORY;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<CertificateCategory> for CK_CERTIFICATE_CATEGORY {
    fn from(certificate_category: CertificateCategory) -> Self {
        *certificate_category
    }
}

impl std::fmt::Display for CertificateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            CertificateCategory::UNSPECIFIED => {
                write!(f, "CK_CERTIFICATE_CATEGORY_UNSPECIFIED")
            }
            CertificateCategory::TOKEN_USER => {
                write!(f, "CK_CERTIFICATE_CATEGORY_TOKEN_USER")
            }
            CertificateCategory::AUTHORITY => {
                write!(f, "CK_CERTIFICATE_CATEGORY_AUTHORITY")
            }
            CertificateCategory::OTHER_ENTITY => {
                write!(f, "CK_CERTIFICATE_CATEGORY_OTHER_ENTITY")
            }
            _ => write!(f, "Unknown certificate category"),
        }
    }
}

impl TryFrom<CK_CERTIFICATE_CATEGORY> for CertificateCategory {
    type Error = Error;

    fn try_from(certificate_category: CK_CERTIFICATE_CATEGORY) -> Result<Self> {
        match certificate_category {
            CK_CERTIFICATE_CATEGORY_UNSPECIFIED => Ok(CertificateCategory::UNSPECIFIED),
            CK_CERTIFICATE_CATEGORY_TOKEN_USER => Ok(CertificateCategory::TOKEN_USER),
            CK_CERTIFICATE_CATEGORY_AUTHORITY => Ok(CertificateCategory::AUTHORITY),
            CK_CERTIFICATE_CATEGORY_OTHER_ENTITY => Ok(CertificateCategory::OTHER_ENTITY),
            _ => {
                eprintln!(
                    "Undefined ({:#X}) certificate category",
                    certificate_category
                );
                Err(Error::NotSupported)
            }
        }
    }
}

// CK_JAVA_MIDP_SECURITY_DOMAIN

/// Identifies the Java MIDP security domain of a certificate.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct JavaMidpSecurityDomain(CK_JAVA_MIDP_SECURITY_DOMAIN);

impl JavaMidpSecurityDomain {
    /// No domain specified.
    pub const UNSPECIFIED: JavaMidpSecurityDomain =
        JavaMidpSecurityDomain(CK_SECURITY_DOMAIN_UNSPECIFIED);
    /// Manufacturer protection domain.
    pub const MANUFACTURER: JavaMidpSecurityDomain =
        JavaMidpSecurityDomain(CK_SECURITY_DOMAIN_MANUFACTURER);
    /// Operator protection domain.
    pub const DOMAIN_OPERATOR: JavaMidpSecurityDomain =
        JavaMidpSecurityDomain(CK_SECURITY_DOMAIN_OPERATOR);
    /// Third party protection domain.
    pub const THIRD_PARTY: JavaMidpSecurityDomain =
        JavaMidpSecurityDomain(CK_SECURITY_DOMAIN_THIRD_PARTY);
}

impl Deref for JavaMidpSecurityDomain {
    type Target = CK_JAVA_MIDP_SECURITY_DOMAIN;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<JavaMidpSecurityDomain> for CK_JAVA_MIDP_SECURITY_DOMAIN {
    fn from(security_domain: JavaMidpSecurityDomain) -> Self {
        *security_domain
    }
}

impl std::fmt::Display for JavaMidpSecurityDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            JavaMidpSecurityDomain::UNSPECIFIED => {
                write!(f, "CK_SECURITY_DOMAIN_UNSPECIFIED")
            }
            JavaMidpSecurityDomain::MANUFACTURER => {
                write!(f, "CK_SECURITY_DOMAIN_MANUFACTURER")
            }
            JavaMidpSecurityDomain::DOMAIN_OPERATOR => {
                write!(f, "CK_SECURITY_DOMAIN_OPERATOR")
            }
            JavaMidpSecurityDomain::THIRD_PARTY => {
                write!(f, "CK_SECURITY_DOMAIN_THIRD_PARTY")
            }
            _ => write!(f, "Unknown certificate category"),
        }
    }
}

impl TryFrom<CK_JAVA_MIDP_SECURITY_DOMAIN> for JavaMidpSecurityDomain {
    type Error = Error;

    fn try_from(security_domain: CK_JAVA_MIDP_SECURITY_DOMAIN) -> Result<Self> {
        match security_domain {
            CK_SECURITY_DOMAIN_UNSPECIFIED => Ok(JavaMidpSecurityDomain::UNSPECIFIED),
            CK_SECURITY_DOMAIN_MANUFACTURER => Ok(JavaMidpSecurityDomain::MANUFACTURER),
            CK_SECURITY_DOMAIN_OPERATOR => Ok(JavaMidpSecurityDomain::DOMAIN_OPERATOR),
            CK_SECURITY_DOMAIN_THIRD_PARTY => Ok(JavaMidpSecurityDomain::THIRD_PARTY),
            _ => {
                eprintln!("Undefined ({:#X}) certificate category", security_domain);
                Err(Error::NotSupported)
            }
        }
    }
}

// CK_ATTRIBUTE_TYPE

/// Identifies an attribute type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
#[non_exhaustive]
pub struct AttributeType(CK_ATTRIBUTE_TYPE);

impl AttributeType {
    /// Object class type.
    pub const CLASS: AttributeType = AttributeType(CKA_CLASS);
    /// Identifies whether the object is a token object or a session object.
    pub const TOKEN: AttributeType = AttributeType(CKA_TOKEN);
    /// Identifies whether the ojbect is private.
    pub const PRIVATE: AttributeType = AttributeType(CKA_PRIVATE);
    /// Description of the object.
    pub const LABEL: AttributeType = AttributeType(CKA_LABEL);
    /// Description of the application that manages the object.
    pub const APPLICATION: AttributeType = AttributeType(CKA_APPLICATION);
    /// Value of the object.
    pub const VALUE: AttributeType = AttributeType(CKA_VALUE);
    /// DER-encoding of the object identifier indicating the data object type.
    pub const OBJECT_ID: AttributeType = AttributeType(CKA_OBJECT_ID);
    /// Type of certificate.
    pub const CERTIFICATE_TYPE: AttributeType = AttributeType(CKA_CERTIFICATE_TYPE);
    /// Certificate issuer name.
    pub const ISSUER: AttributeType = AttributeType(CKA_ISSUER);
    /// Serial number.
    pub const SERIAL_NUMBER: AttributeType = AttributeType(CKA_SERIAL_NUMBER);
    /// DER-encoding of the attribute certificate's issuer field. This is
    /// distinct from the `ISSUER` attribute contained in CKC_X_509
    /// certificates because the ASN.1 syntax and encoding are different.
    pub const AC_ISSUER: AttributeType = AttributeType(CKA_AC_ISSUER);
    /// DER-encoding of the attribute certificate's subject field. This is
    /// distinct from the `SUBJECT`attribute contained in CKC_X_509
    /// certificates because the ASN.1 syntax and encoding are different.
    pub const OWNER: AttributeType = AttributeType(CKA_OWNER);
    /// BER-encoding of a sequence of object identifier values corresponding
    /// to the attribute types contained in the certificate. When present,
    /// this field offers an opportunity for applications to search for a
    /// particular attribute certificate without fetching and parsing the
    /// certificate itself.
    pub const ATTR_TYPES: AttributeType = AttributeType(CKA_ATTR_TYPES);
    /// The object can be trusted for the application that it was created.
    pub const TRUSTED: AttributeType = AttributeType(CKA_TRUSTED);
    /// Is used to indicate if a stored certificate is a user certificate
    /// for which the corresponding private key is available on the token
    /// ("token user"), a CA certificate ("authority"), or another end-entity
    /// certificate ("other entity"). This attribute may not be modified after
    /// an object is created.
    pub const CERTIFICATE_CATEGORY: AttributeType =
        AttributeType(CKA_CERTIFICATE_CATEGORY);
    /// Associates a certificate with a Java MIDP security domain.
    pub const JAVA_MIDP_SECURITY_DOMAIN: AttributeType =
        AttributeType(CKA_JAVA_MIDP_SECURITY_DOMAIN);
    /// If not empty this attribute gives the URL where the object
    /// can be obtained.
    pub const URL: AttributeType = AttributeType(CKA_URL);
    /// Hash of the subject public key (default empty).
    /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
    pub const HASH_OF_SUBJECT_PUBLIC_KEY: AttributeType =
        AttributeType(CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
    /// Hash of the issuer public key (default empty).
    /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
    pub const HASH_OF_ISSUER_PUBLIC_KEY: AttributeType =
        AttributeType(CKA_HASH_OF_ISSUER_PUBLIC_KEY);
    /// Defines the mechanism used to calculate `HASH_OF_SUBJECT_PUBLIC_KEY`
    /// and `HASH_OF_ISSUER_PUBLIC_KEY`. If the attribute is not present then
    /// the type defaults to SHA-1.
    pub const NAME_HASH_ALGORITHM: AttributeType = AttributeType(CKA_NAME_HASH_ALGORITHM);
    /// Object checksum.
    pub const CHECK_VALUE: AttributeType = AttributeType(CKA_CHECK_VALUE);
    /// Type of key.
    pub const KEY_TYPE: AttributeType = AttributeType(CKA_KEY_TYPE);
    /// Object subject name.
    pub const SUBJECT: AttributeType = AttributeType(CKA_SUBJECT);
    /// Key identifier.
    pub const ID: AttributeType = AttributeType(CKA_ID);
    /// Identifies whether the object is sensitive.
    pub const SENSITIVE: AttributeType = AttributeType(CKA_SENSITIVE);
    /// Identifies whether the key supports encryption.
    pub const ENCRYPT: AttributeType = AttributeType(CKA_ENCRYPT);
    /// Identifies whether the key supports decryption.
    pub const DECRYPT: AttributeType = AttributeType(CKA_DECRYPT);
    /// Identifies whether the key supports wrapping
    /// (i.e., can be used to wrap other keys).
    pub const WRAP: AttributeType = AttributeType(CKA_WRAP);
    /// Identifies whether the key supports unwrapping
    /// (i.e., can be used to unwrap other keys).
    pub const UNWRAP: AttributeType = AttributeType(CKA_UNWRAP);
    /// Identifies whether the key supports signatures.
    pub const SIGN: AttributeType = AttributeType(CKA_SIGN);
    /// Identifies whether the key supports signatures where the data
    /// can be recovered from the signature.
    pub const SIGN_RECOVER: AttributeType = AttributeType(CKA_SIGN_RECOVER);
    /// Identifies whether the key supports verification
    pub const VERIFY: AttributeType = AttributeType(CKA_VERIFY);
    /// Identifies whether the key supports verification where the data
    /// is recovered from the signature.
    pub const VERIFY_RECOVER: AttributeType = AttributeType(CKA_VERIFY_RECOVER);
    /// Identifies whether the key supports key derivation
    /// (i.e., if other keys can be derived from this one).
    pub const DERIVE: AttributeType = AttributeType(CKA_DERIVE);
    /// Start date for the object.
    pub const START_DATE: AttributeType = AttributeType(CKA_START_DATE);
    /// End date for the object.
    pub const END_DATE: AttributeType = AttributeType(CKA_END_DATE);
    /// Modulus n for an RSA private key.
    pub const MODULUS: AttributeType = AttributeType(CKA_MODULUS);
    /// Length in bits of the modulus of a key.
    pub const MODULUS_BITS: AttributeType = AttributeType(CKA_MODULUS_BITS);
    /// Public exponent e for an RSA private key.
    pub const PUBLIC_EXPONENT: AttributeType = AttributeType(CKA_PUBLIC_EXPONENT);
    /// Private exponent d for an RSA private key.
    pub const PRIVATE_EXPONENT: AttributeType = AttributeType(CKA_PRIVATE_EXPONENT);
    /// Prime p for an RSA private key.
    pub const PRIME_1: AttributeType = AttributeType(CKA_PRIME_1);
    /// Prime q for an RSA private key.
    pub const PRIME_2: AttributeType = AttributeType(CKA_PRIME_2);
    /// Private exponent d modulo p-1 for an RSA private key.
    pub const EXPONENT_1: AttributeType = AttributeType(CKA_EXPONENT_1);
    /// Private exponent d modulo q-1 for an RSA private key.
    pub const EXPONENT_2: AttributeType = AttributeType(CKA_EXPONENT_2);
    /// CRT coefficient q^{-1} mod p for an RSA private key.
    pub const COEFFICIENT: AttributeType = AttributeType(CKA_COEFFICIENT);
    /// DER-encoding of the SubjectPublicKeyInfo for the public key.
    pub const PUBLIC_KEY_INFO: AttributeType = AttributeType(CKA_PUBLIC_KEY_INFO);
    /// Prime number value of a key.
    pub const PRIME: AttributeType = AttributeType(CKA_PRIME);
    /// Subprime number value of a key.
    pub const SUBPRIME: AttributeType = AttributeType(CKA_SUBPRIME);
    /// Base number value of a key.
    pub const BASE: AttributeType = AttributeType(CKA_BASE);
    /// Length in bits of the prime number of a key.
    pub const PRIME_BITS: AttributeType = AttributeType(CKA_PRIME_BITS);
    /// Length in bits of the subprime number of a key.
    pub const SUB_PRIME_BITS: AttributeType = AttributeType(CKA_SUB_PRIME_BITS);
    /// Length in bits of the object value.
    pub const VALUE_BITS: AttributeType = AttributeType(CKA_VALUE_BITS);
    /// Object value lenght.
    pub const VALUE_LEN: AttributeType = AttributeType(CKA_VALUE_LEN);
    /// Identifies whether the key is extractable and can be wrapped.
    pub const EXTRACTABLE: AttributeType = AttributeType(CKA_EXTRACTABLE);
    /// True only if object was either
    ///   * generated locally (i.e., on the token)
    ///     with a `generate_key` or generate_key_pair call
    ///   * created with a `copy_object` call as a copy of a key
    ///     which had its `LOCAL` attribute set to true
    pub const LOCAL: AttributeType = AttributeType(CKA_LOCAL);
    /// Indicates if the key has never had the `EXTRACTABLE` attribute set to true.
    pub const NEVER_EXTRACTABLE: AttributeType = AttributeType(CKA_NEVER_EXTRACTABLE);
    /// Indicates if key has always had the `SENSITIVE` attribute set to true.
    pub const ALWAYS_SENSITIVE: AttributeType = AttributeType(CKA_ALWAYS_SENSITIVE);
    /// Identifies the key generation mechanism used to generate the key material.
    pub const KEY_GEN_MECHANISM: AttributeType = AttributeType(CKA_KEY_GEN_MECHANISM);
    /// Identifies whether the object can be modified.
    pub const MODIFIABLE: AttributeType = AttributeType(CKA_MODIFIABLE);
    /// Identifies whether the object can be copied.
    /// Can not be set to true once it is set to false.
    pub const COPYABLE: AttributeType = AttributeType(CKA_COPYABLE);
    /// Identifies whether the object can be destroyed.
    pub const DESTROYABLE: AttributeType = AttributeType(CKA_DESTROYABLE);
    /// Parameters that define an elliptic curve.
    pub const EC_PARAMS: AttributeType = AttributeType(CKA_EC_PARAMS);
    /// Parameters that define an elliptic curve point.
    pub const EC_POINT: AttributeType = AttributeType(CKA_EC_POINT);
    /// Can be used to force re-authentication (i.e. force the user
    /// to provide a PIN) for each use of a private key.
    pub const ALWAYS_AUTHENTICATE: AttributeType = AttributeType(CKA_ALWAYS_AUTHENTICATE);
    /// Identifies whether the key can only be wrapped with a wrapping key
    /// that has CKA_TRUSTED set to true.
    pub const WRAP_WITH_TRUSTED: AttributeType = AttributeType(CKA_WRAP_WITH_TRUSTED);
    /// For wrapping keys. The attribute template to match against any keys
    /// wrapped using this wrapping key. Keys that do not match cannot be
    /// wrapped. The number of attributes in the array is the ulValueLen
    /// component of the attribute divided by the size of `Attribute`.
    pub const WRAP_TEMPLATE: AttributeType = AttributeType(CKA_WRAP_TEMPLATE);
    /// For wrapping keys. The attribute template to apply to any keys
    /// unwrapped using this wrapping key. Any user supplied template
    /// is applied after this template as if the object has already been
    /// created. The number of attributes in the array is the ulValueLen
    /// component of the attribute divided by the size of `Attribute`.
    pub const UNWRAP_TEMPLATE: AttributeType = AttributeType(CKA_UNWRAP_TEMPLATE);
    /// The format of the OTP value (e.g. decimal (default), hexadecimal, binary).
    pub const OTP_FORMAT: AttributeType = AttributeType(CKA_OTP_FORMAT);
    /// The length of the OTP value in digits or bytes, depending
    /// on `OTP_FORMAT`.
    pub const OTP_LENGTH: AttributeType = AttributeType(CKA_OTP_LENGTH);
    /// The time interval in seconds between OTP value refreshes.
    pub const OTP_TIME_INTERVAL: AttributeType = AttributeType(CKA_OTP_TIME_INTERVAL);
    /// Identifies whether the token is capable of returning OTPs suitable for
    /// human consumption.
    pub const OTP_USER_FRIENDLY_MODE: AttributeType =
        AttributeType(CKA_OTP_USER_FRIENDLY_MODE);
    /// Identifies challenge parameter requirements when generating or verifying
    /// OTP values.
    pub const OTP_CHALLENGE_REQUIREMENT: AttributeType =
        AttributeType(CKA_OTP_CHALLENGE_REQUIREMENT);
    /// Identifies time parameter requirements when generating or verifying
    /// OTP values.
    pub const OTP_TIME_REQUIREMENT: AttributeType =
        AttributeType(CKA_OTP_TIME_REQUIREMENT);
    /// Identifies counter parameter requirements when generating or verifying
    /// OTP values.
    pub const OTP_COUNTER_REQUIREMENT: AttributeType =
        AttributeType(CKA_OTP_COUNTER_REQUIREMENT);
    /// Identifies pin parameter requirements when generating or verifying
    /// OTP values.
    pub const OTP_PIN_REQUIREMENT: AttributeType = AttributeType(CKA_OTP_PIN_REQUIREMENT);
    /// Value of the associated internal counter.
    pub const OTP_COUNTER: AttributeType = AttributeType(CKA_OTP_COUNTER);
    /// Value of the associated internal UTC time in the form YYYYMMDDhhmmss.
    pub const OTP_TIME: AttributeType = AttributeType(CKA_OTP_TIME);
    /// Text string that identifies a user associated with the OTP key (may be
    /// used to enhance the user experience).
    pub const OTP_USER_IDENTIFIER: AttributeType = AttributeType(CKA_OTP_USER_IDENTIFIER);
    /// Text string that identifies a service that may validate OTPs
    /// generated by this key.
    pub const OTP_SERVICE_IDENTIFIER: AttributeType =
        AttributeType(CKA_OTP_SERVICE_IDENTIFIER);
    /// Logotype image that identifies a service that may validate OTPs
    /// generated by this key.
    pub const OTP_SERVICE_LOGO: AttributeType = AttributeType(CKA_OTP_SERVICE_LOGO);
    /// MIME type of the `OTP_SERVICE_LOGO` attribute value.
    pub const OTP_SERVICE_LOGO_TYPE: AttributeType =
        AttributeType(CKA_OTP_SERVICE_LOGO_TYPE);
    /// Parameters that define GOST R 34.10.
    pub const GOSTR3410_PARAMS: AttributeType = AttributeType(CKA_GOSTR3410_PARAMS);
    /// Parameters that define GOST R 34.11.
    pub const GOSTR3411_PARAMS: AttributeType = AttributeType(CKA_GOSTR3411_PARAMS);
    /// Parameters that define GOST 28147.
    pub const GOST28147_PARAMS: AttributeType = AttributeType(CKA_GOST28147_PARAMS);
    /// Identifies a hardware feature type of a device.
    pub const HW_FEATURE_TYPE: AttributeType = AttributeType(CKA_HW_FEATURE_TYPE);
    /// The value of the counter will reset to a previously returned value if
    /// the token is initialized using C_InitToken.
    pub const RESET_ON_INIT: AttributeType = AttributeType(CKA_RESET_ON_INIT);
    /// The value of the counter has been reset at least once at some point
    /// in time.
    pub const HAS_RESET: AttributeType = AttributeType(CKA_HAS_RESET);
    /// Screen resolution (in pixels) in X-axis (e.g. 1280).
    pub const PIXEL_X: AttributeType = AttributeType(CKA_PIXEL_X);
    /// Screen resolution (in pixels) in Y-axis (e.g. 1024).
    pub const PIXEL_Y: AttributeType = AttributeType(CKA_PIXEL_Y);
    /// DPI, pixels per inch.
    pub const RESOLUTION: AttributeType = AttributeType(CKA_RESOLUTION);
    /// For character-oriented displays; number of character rows (e.g. 24).
    pub const CHAR_ROWS: AttributeType = AttributeType(CKA_CHAR_ROWS);
    /// For character-oriented displays: number of character columns (e.g. 80).
    /// If display is of proportional-font type, this is the width of the
    /// display in "em"-s (letter "M"), see CC/PP Struct.
    pub const CHAR_COLUMNS: AttributeType = AttributeType(CKA_CHAR_COLUMNS);
    /// Color support.
    pub const COLOR: AttributeType = AttributeType(CKA_COLOR);
    /// The number of bits of color or grayscale information per pixel.
    pub const BITS_PER_PIXEL: AttributeType = AttributeType(CKA_BITS_PER_PIXEL);
    /// String indicating supported character sets, as defined by IANA MIBenum
    /// sets (www.iana.org). Supported character sets are separated with ";".
    /// E.g. a token supporting iso-8859-1 and US-ASCII would set the attribute
    /// value to "4;3".
    pub const CHAR_SETS: AttributeType = AttributeType(CKA_CHAR_SETS);
    /// String indicating supported content transfer encoding methods, as
    /// defined by IANA (www.iana.org). Supported methods are separated
    /// with ";". E.g. a token supporting 7bit, 8bit and base64 could set
    /// the attribute value to "7bit;8bit;base64".
    pub const ENCODING_METHODS: AttributeType = AttributeType(CKA_ENCODING_METHODS);
    /// String indicating supported (presentable) MIME-types, as defined by
    /// IANA (www.iana.org). Supported types are separated with ";".
    /// E.g. a token supporting MIME types "a/b", "a/c" and "a/d" would set
    /// the attribute value to "a/b;a/c;a/d".
    pub const MIME_TYPES: AttributeType = AttributeType(CKA_MIME_TYPES);
    /// The type of mechanism object.
    pub const MECHANISM_TYPE: AttributeType = AttributeType(CKA_MECHANISM_TYPE);
    /// Attributes the token always will include in the set of CMS signed
    /// attributes.
    pub const REQUIRED_CMS_ATTRIBUTES: AttributeType =
        AttributeType(CKA_REQUIRED_CMS_ATTRIBUTES);
    /// Attributes the token will include in the set of CMS signed attributes
    /// in the absence of any attributes specified by the application.
    pub const DEFAULT_CMS_ATTRIBUTES: AttributeType =
        AttributeType(CKA_DEFAULT_CMS_ATTRIBUTES);
    /// Attributes the token may include in the set of CMS signed attributes
    /// upon request by the application.
    pub const SUPPORTED_CMS_ATTRIBUTES: AttributeType =
        AttributeType(CKA_SUPPORTED_CMS_ATTRIBUTES);
    /// A list of mechanisms allowed to be used with this key.
    pub const ALLOWED_MECHANISMS: AttributeType = AttributeType(CKA_ALLOWED_MECHANISMS);
}

impl AttributeType {
    pub fn new_vendor_defined(value: CK_ATTRIBUTE_TYPE) -> Result<AttributeType> {
        if value >= CKC_VENDOR_DEFINED {
            Ok(AttributeType(value))
        } else {
            Err(Error::InvalidInput)
        }
    }

    pub fn is_vendor_defined(&self) -> bool {
        self.0 >= CKC_VENDOR_DEFINED
    }
}

impl Deref for AttributeType {
    type Target = CK_ATTRIBUTE_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AttributeType> for CK_ATTRIBUTE_TYPE {
    fn from(attribute_type: AttributeType) -> Self {
        *attribute_type
    }
}

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            AttributeType::CLASS => write!(f, "CKA_CLASS"),
            AttributeType::TOKEN => write!(f, "CKA_TOKEN"),
            AttributeType::PRIVATE => write!(f, "CKA_PRIVATE"),
            AttributeType::LABEL => write!(f, "CKA_LABEL"),
            AttributeType::APPLICATION => write!(f, "CKA_APPLICATION"),
            AttributeType::VALUE => write!(f, "CKA_VALUE"),
            AttributeType::OBJECT_ID => write!(f, "CKA_OBJECT_ID"),
            AttributeType::CERTIFICATE_TYPE => write!(f, "CKA_CERTIFICATE_TYPE"),
            AttributeType::ISSUER => write!(f, "CKA_ISSUER"),
            AttributeType::SERIAL_NUMBER => write!(f, "CKA_SERIAL_NUMBER"),
            AttributeType::AC_ISSUER => write!(f, "CKA_AC_ISSUER"),
            AttributeType::OWNER => write!(f, "CKA_OWNER"),
            AttributeType::ATTR_TYPES => write!(f, "CKA_ATTR_TYPES"),
            AttributeType::TRUSTED => write!(f, "CKA_TRUSTED"),
            AttributeType::CERTIFICATE_CATEGORY => write!(f, "CKA_CERTIFICATE_CATEGORY"),
            AttributeType::JAVA_MIDP_SECURITY_DOMAIN => {
                write!(f, "CKA_JAVA_MIDP_SECURITY_DOMAIN")
            }
            AttributeType::URL => write!(f, "CKA_URL"),
            AttributeType::HASH_OF_SUBJECT_PUBLIC_KEY => {
                write!(f, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY")
            }
            AttributeType::HASH_OF_ISSUER_PUBLIC_KEY => {
                write!(f, "CKA_HASH_OF_ISSUER_PUBLIC_KEY")
            }
            AttributeType::NAME_HASH_ALGORITHM => write!(f, "CKA_NAME_HASH_ALGORITHM"),
            AttributeType::CHECK_VALUE => write!(f, "CKA_CHECK_VALUE"),
            AttributeType::KEY_TYPE => write!(f, "CKA_KEY_TYPE"),
            AttributeType::SUBJECT => write!(f, "CKA_SUBJECT"),
            AttributeType::ID => write!(f, "CKA_ID"),
            AttributeType::SENSITIVE => write!(f, "CKA_SENSITIVE"),
            AttributeType::ENCRYPT => write!(f, "CKA_ENCRYPT"),
            AttributeType::DECRYPT => write!(f, "CKA_DECRYPT"),
            AttributeType::WRAP => write!(f, "CKA_WRAP"),
            AttributeType::UNWRAP => write!(f, "CKA_UNWRAP"),
            AttributeType::SIGN => write!(f, "CKA_SIGN"),
            AttributeType::SIGN_RECOVER => write!(f, "CKA_SIGN_RECOVER"),
            AttributeType::VERIFY => write!(f, "CKA_VERIFY"),
            AttributeType::VERIFY_RECOVER => write!(f, "CKA_VERIFY_RECOVER"),
            AttributeType::DERIVE => write!(f, "CKA_DERIVE"),
            AttributeType::START_DATE => write!(f, "CKA_START_DATE"),
            AttributeType::END_DATE => write!(f, "CKA_END_DATE"),
            AttributeType::MODULUS => write!(f, "CKA_MODULUS"),
            AttributeType::MODULUS_BITS => write!(f, "CKA_MODULUS_BITS"),
            AttributeType::PUBLIC_EXPONENT => write!(f, "CKA_PUBLIC_EXPONENT"),
            AttributeType::PRIVATE_EXPONENT => write!(f, "CKA_PRIVATE_EXPONENT"),
            AttributeType::PRIME_1 => write!(f, "CKA_PRIME_1"),
            AttributeType::PRIME_2 => write!(f, "CKA_PRIME_2"),
            AttributeType::EXPONENT_1 => write!(f, "CKA_EXPONENT_1"),
            AttributeType::EXPONENT_2 => write!(f, "CKA_EXPONENT_2"),
            AttributeType::COEFFICIENT => write!(f, "CKA_COEFFICIENT"),
            AttributeType::PUBLIC_KEY_INFO => write!(f, "CKA_PUBLIC_KEY_INFO"),
            AttributeType::PRIME => write!(f, "CKA_PRIME"),
            AttributeType::SUBPRIME => write!(f, "CKA_SUBPRIME"),
            AttributeType::BASE => write!(f, "CKA_BASE"),
            AttributeType::PRIME_BITS => write!(f, "CKA_PRIME_BITS"),
            AttributeType::SUB_PRIME_BITS => write!(f, "CKA_SUB_PRIME_BITS"),
            AttributeType::VALUE_BITS => write!(f, "CKA_VALUE_BITS"),
            AttributeType::VALUE_LEN => write!(f, "CKA_VALUE_LEN"),
            AttributeType::EXTRACTABLE => write!(f, "CKA_EXTRACTABLE"),
            AttributeType::LOCAL => write!(f, "CKA_LOCAL"),
            AttributeType::NEVER_EXTRACTABLE => write!(f, "CKA_NEVER_EXTRACTABLE"),
            AttributeType::ALWAYS_SENSITIVE => write!(f, "CKA_ALWAYS_SENSITIVE"),
            AttributeType::KEY_GEN_MECHANISM => write!(f, "CKA_KEY_GEN_MECHANISM"),
            AttributeType::MODIFIABLE => write!(f, "CKA_MODIFIABLE"),
            AttributeType::COPYABLE => write!(f, "CKA_COPYABLE"),
            AttributeType::DESTROYABLE => write!(f, "CKA_DESTROYABLE"),
            AttributeType::EC_PARAMS => write!(f, "CKA_EC_PARAMS"),
            AttributeType::EC_POINT => write!(f, "CKA_EC_POINT"),
            AttributeType::ALWAYS_AUTHENTICATE => write!(f, "CKA_ALWAYS_AUTHENTICATE"),
            AttributeType::WRAP_WITH_TRUSTED => write!(f, "CKA_WRAP_WITH_TRUSTED"),
            AttributeType::WRAP_TEMPLATE => write!(f, "CKA_WRAP_TEMPLATE"),
            AttributeType::UNWRAP_TEMPLATE => write!(f, "CKA_UNWRAP_TEMPLATE"),
            AttributeType::OTP_FORMAT => write!(f, "CKA_OTP_FORMAT"),
            AttributeType::OTP_LENGTH => write!(f, "CKA_OTP_LENGTH"),
            AttributeType::OTP_TIME_INTERVAL => write!(f, "CKA_OTP_TIME_INTERVAL"),
            AttributeType::OTP_USER_FRIENDLY_MODE => {
                write!(f, "CKA_OTP_USER_FRIENDLY_MODE")
            }
            AttributeType::OTP_CHALLENGE_REQUIREMENT => {
                write!(f, "CKA_OTP_CHALLENGE_REQUIREMENT")
            }
            AttributeType::OTP_TIME_REQUIREMENT => write!(f, "CKA_OTP_TIME_REQUIREMENT"),
            AttributeType::OTP_COUNTER_REQUIREMENT => {
                write!(f, "CKA_OTP_COUNTER_REQUIREMENT")
            }
            AttributeType::OTP_PIN_REQUIREMENT => write!(f, "CKA_OTP_PIN_REQUIREMENT"),
            AttributeType::OTP_COUNTER => write!(f, "CKA_OTP_COUNTER"),
            AttributeType::OTP_TIME => write!(f, "CKA_OTP_TIME"),
            AttributeType::OTP_USER_IDENTIFIER => write!(f, "CKA_OTP_USER_IDENTIFIER"),
            AttributeType::OTP_SERVICE_IDENTIFIER => {
                write!(f, "CKA_OTP_SERVICE_IDENTIFIER")
            }
            AttributeType::OTP_SERVICE_LOGO => write!(f, "CKA_OTP_SERVICE_LOGO"),
            AttributeType::OTP_SERVICE_LOGO_TYPE => {
                write!(f, "CKA_OTP_SERVICE_LOGO_TYPE")
            }
            AttributeType::GOSTR3410_PARAMS => write!(f, "CKA_GOSTR3410_PARAMS"),
            AttributeType::GOSTR3411_PARAMS => write!(f, "CKA_GOSTR3411_PARAMS"),
            AttributeType::GOST28147_PARAMS => write!(f, "CKA_GOST28147_PARAMS"),
            AttributeType::HW_FEATURE_TYPE => write!(f, "CKA_HW_FEATURE_TYPE"),
            AttributeType::RESET_ON_INIT => write!(f, "CKA_RESET_ON_INIT"),
            AttributeType::HAS_RESET => write!(f, "CKA_HAS_RESET"),
            AttributeType::PIXEL_X => write!(f, "CKA_PIXEL_X"),
            AttributeType::PIXEL_Y => write!(f, "CKA_PIXEL_Y"),
            AttributeType::RESOLUTION => write!(f, "CKA_RESOLUTION"),
            AttributeType::CHAR_ROWS => write!(f, "CKA_CHAR_ROWS"),
            AttributeType::CHAR_COLUMNS => write!(f, "CKA_CHAR_COLUMNS"),
            AttributeType::COLOR => write!(f, "CKA_COLOR"),
            AttributeType::BITS_PER_PIXEL => write!(f, "CKA_BITS_PER_PIXEL"),
            AttributeType::CHAR_SETS => write!(f, "CKA_CHAR_SETS"),
            AttributeType::ENCODING_METHODS => write!(f, "CKA_ENCODING_METHODS"),
            AttributeType::MIME_TYPES => write!(f, "CKA_MIME_TYPES"),
            AttributeType::MECHANISM_TYPE => write!(f, "CKA_MECHANISM_TYPE"),
            AttributeType::REQUIRED_CMS_ATTRIBUTES => {
                write!(f, "CKA_REQUIRED_CMS_ATTRIBUTES")
            }
            AttributeType::DEFAULT_CMS_ATTRIBUTES => {
                write!(f, "CKA_DEFAULT_CMS_ATTRIBUTES")
            }
            AttributeType::SUPPORTED_CMS_ATTRIBUTES => {
                write!(f, "CKA_SUPPORTED_CMS_ATTRIBUTES")
            }
            AttributeType::ALLOWED_MECHANISMS => write!(f, "CKA_ALLOWED_MECHANISMS"),
            _ if self.is_vendor_defined() => {
                write!(f, "CKA_VENDOR_DEFINED({:#x})", self.0)
            }
            other => write!(f, "Unknown attribute type: {:#X}", *other),
        }
    }
}

impl TryFrom<CK_ATTRIBUTE_TYPE> for AttributeType {
    type Error = Error;

    fn try_from(attribute_type: CK_ATTRIBUTE_TYPE) -> Result<Self> {
        match attribute_type {
            CKA_CLASS => Ok(AttributeType::CLASS),
            CKA_TOKEN => Ok(AttributeType::TOKEN),
            CKA_PRIVATE => Ok(AttributeType::PRIVATE),
            CKA_LABEL => Ok(AttributeType::LABEL),
            CKA_APPLICATION => Ok(AttributeType::APPLICATION),
            CKA_VALUE => Ok(AttributeType::VALUE),
            CKA_OBJECT_ID => Ok(AttributeType::OBJECT_ID),
            CKA_CERTIFICATE_TYPE => Ok(AttributeType::CERTIFICATE_TYPE),
            CKA_ISSUER => Ok(AttributeType::ISSUER),
            CKA_SERIAL_NUMBER => Ok(AttributeType::SERIAL_NUMBER),
            CKA_AC_ISSUER => Ok(AttributeType::AC_ISSUER),
            CKA_OWNER => Ok(AttributeType::OWNER),
            CKA_ATTR_TYPES => Ok(AttributeType::ATTR_TYPES),
            CKA_TRUSTED => Ok(AttributeType::TRUSTED),
            CKA_CERTIFICATE_CATEGORY => Ok(AttributeType::CERTIFICATE_CATEGORY),
            CKA_JAVA_MIDP_SECURITY_DOMAIN => Ok(AttributeType::JAVA_MIDP_SECURITY_DOMAIN),
            CKA_URL => Ok(AttributeType::URL),
            CKA_HASH_OF_SUBJECT_PUBLIC_KEY => {
                Ok(AttributeType::HASH_OF_SUBJECT_PUBLIC_KEY)
            }
            CKA_HASH_OF_ISSUER_PUBLIC_KEY => Ok(AttributeType::HASH_OF_ISSUER_PUBLIC_KEY),
            CKA_NAME_HASH_ALGORITHM => Ok(AttributeType::NAME_HASH_ALGORITHM),
            CKA_CHECK_VALUE => Ok(AttributeType::CHECK_VALUE),
            CKA_KEY_TYPE => Ok(AttributeType::KEY_TYPE),
            CKA_SUBJECT => Ok(AttributeType::SUBJECT),
            CKA_ID => Ok(AttributeType::ID),
            CKA_SENSITIVE => Ok(AttributeType::SENSITIVE),
            CKA_ENCRYPT => Ok(AttributeType::ENCRYPT),
            CKA_DECRYPT => Ok(AttributeType::DECRYPT),
            CKA_WRAP => Ok(AttributeType::WRAP),
            CKA_UNWRAP => Ok(AttributeType::UNWRAP),
            CKA_SIGN => Ok(AttributeType::SIGN),
            CKA_SIGN_RECOVER => Ok(AttributeType::SIGN_RECOVER),
            CKA_VERIFY => Ok(AttributeType::VERIFY),
            CKA_VERIFY_RECOVER => Ok(AttributeType::VERIFY_RECOVER),
            CKA_DERIVE => Ok(AttributeType::DERIVE),
            CKA_START_DATE => Ok(AttributeType::START_DATE),
            CKA_END_DATE => Ok(AttributeType::END_DATE),
            CKA_MODULUS => Ok(AttributeType::MODULUS),
            CKA_MODULUS_BITS => Ok(AttributeType::MODULUS_BITS),
            CKA_PUBLIC_EXPONENT => Ok(AttributeType::PUBLIC_EXPONENT),
            CKA_PRIVATE_EXPONENT => Ok(AttributeType::PRIVATE_EXPONENT),
            CKA_PRIME_1 => Ok(AttributeType::PRIME_1),
            CKA_PRIME_2 => Ok(AttributeType::PRIME_2),
            CKA_EXPONENT_1 => Ok(AttributeType::EXPONENT_1),
            CKA_EXPONENT_2 => Ok(AttributeType::EXPONENT_2),
            CKA_COEFFICIENT => Ok(AttributeType::COEFFICIENT),
            CKA_PUBLIC_KEY_INFO => Ok(AttributeType::PUBLIC_KEY_INFO),
            CKA_PRIME => Ok(AttributeType::PRIME),
            CKA_SUBPRIME => Ok(AttributeType::SUBPRIME),
            CKA_BASE => Ok(AttributeType::BASE),
            CKA_PRIME_BITS => Ok(AttributeType::PRIME_BITS),
            CKA_SUB_PRIME_BITS => Ok(AttributeType::SUB_PRIME_BITS),
            CKA_VALUE_BITS => Ok(AttributeType::VALUE_BITS),
            CKA_VALUE_LEN => Ok(AttributeType::VALUE_LEN),
            CKA_EXTRACTABLE => Ok(AttributeType::EXTRACTABLE),
            CKA_LOCAL => Ok(AttributeType::LOCAL),
            CKA_NEVER_EXTRACTABLE => Ok(AttributeType::NEVER_EXTRACTABLE),
            CKA_ALWAYS_SENSITIVE => Ok(AttributeType::ALWAYS_SENSITIVE),
            CKA_KEY_GEN_MECHANISM => Ok(AttributeType::KEY_GEN_MECHANISM),
            CKA_MODIFIABLE => Ok(AttributeType::MODIFIABLE),
            CKA_COPYABLE => Ok(AttributeType::COPYABLE),
            CKA_DESTROYABLE => Ok(AttributeType::DESTROYABLE),
            CKA_EC_PARAMS => Ok(AttributeType::EC_PARAMS),
            CKA_EC_POINT => Ok(AttributeType::EC_POINT),
            CKA_ALWAYS_AUTHENTICATE => Ok(AttributeType::ALWAYS_AUTHENTICATE),
            CKA_WRAP_WITH_TRUSTED => Ok(AttributeType::WRAP_WITH_TRUSTED),
            CKA_WRAP_TEMPLATE => Ok(AttributeType::WRAP_TEMPLATE),
            CKA_UNWRAP_TEMPLATE => Ok(AttributeType::UNWRAP_TEMPLATE),
            CKA_OTP_FORMAT => Ok(AttributeType::OTP_FORMAT),
            CKA_OTP_LENGTH => Ok(AttributeType::OTP_LENGTH),
            CKA_OTP_TIME_INTERVAL => Ok(AttributeType::OTP_TIME_INTERVAL),
            CKA_OTP_USER_FRIENDLY_MODE => Ok(AttributeType::OTP_USER_FRIENDLY_MODE),
            CKA_OTP_CHALLENGE_REQUIREMENT => Ok(AttributeType::OTP_CHALLENGE_REQUIREMENT),
            CKA_OTP_TIME_REQUIREMENT => Ok(AttributeType::OTP_TIME_REQUIREMENT),
            CKA_OTP_COUNTER_REQUIREMENT => Ok(AttributeType::OTP_COUNTER_REQUIREMENT),
            CKA_OTP_PIN_REQUIREMENT => Ok(AttributeType::OTP_PIN_REQUIREMENT),
            CKA_OTP_COUNTER => Ok(AttributeType::OTP_COUNTER),
            CKA_OTP_TIME => Ok(AttributeType::OTP_TIME),
            CKA_OTP_USER_IDENTIFIER => Ok(AttributeType::OTP_USER_IDENTIFIER),
            CKA_OTP_SERVICE_IDENTIFIER => Ok(AttributeType::OTP_SERVICE_IDENTIFIER),
            CKA_OTP_SERVICE_LOGO => Ok(AttributeType::OTP_SERVICE_LOGO),
            CKA_OTP_SERVICE_LOGO_TYPE => Ok(AttributeType::OTP_SERVICE_LOGO_TYPE),
            CKA_GOSTR3410_PARAMS => Ok(AttributeType::GOSTR3410_PARAMS),
            CKA_GOSTR3411_PARAMS => Ok(AttributeType::GOSTR3411_PARAMS),
            CKA_GOST28147_PARAMS => Ok(AttributeType::GOST28147_PARAMS),
            CKA_HW_FEATURE_TYPE => Ok(AttributeType::HW_FEATURE_TYPE),
            CKA_RESET_ON_INIT => Ok(AttributeType::RESET_ON_INIT),
            CKA_HAS_RESET => Ok(AttributeType::HAS_RESET),
            CKA_PIXEL_X => Ok(AttributeType::PIXEL_X),
            CKA_PIXEL_Y => Ok(AttributeType::PIXEL_Y),
            CKA_RESOLUTION => Ok(AttributeType::RESOLUTION),
            CKA_CHAR_ROWS => Ok(AttributeType::CHAR_ROWS),
            CKA_CHAR_COLUMNS => Ok(AttributeType::CHAR_COLUMNS),
            CKA_COLOR => Ok(AttributeType::COLOR),
            CKA_BITS_PER_PIXEL => Ok(AttributeType::BITS_PER_PIXEL),
            CKA_CHAR_SETS => Ok(AttributeType::CHAR_SETS),
            CKA_ENCODING_METHODS => Ok(AttributeType::ENCODING_METHODS),
            CKA_MIME_TYPES => Ok(AttributeType::MIME_TYPES),
            CKA_MECHANISM_TYPE => Ok(AttributeType::MECHANISM_TYPE),
            CKA_REQUIRED_CMS_ATTRIBUTES => Ok(AttributeType::REQUIRED_CMS_ATTRIBUTES),
            CKA_DEFAULT_CMS_ATTRIBUTES => Ok(AttributeType::DEFAULT_CMS_ATTRIBUTES),
            CKA_SUPPORTED_CMS_ATTRIBUTES => Ok(AttributeType::SUPPORTED_CMS_ATTRIBUTES),
            CKA_ALLOWED_MECHANISMS => Ok(AttributeType::ALLOWED_MECHANISMS),
            CKA_VENDOR_DEFINED..=CK_ATTRIBUTE_TYPE::MAX => {
                Ok(AttributeType(attribute_type))
            }
            _ => Err(Error::NotSupported),
        }
    }
}

/// Identifies an attribute.
///
/// An array of Attribute is called a "template" and is used for creating,
/// manipulating and searching for objects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attribute {
    Class(ObjectClass),
    Token(bool),
    Private(bool),
    Label(String),
    Application(String),
    Value(Vec<Byte>),
    ObjectId(Vec<Byte>),
    CertificateType(CertificateType),
    Issuer(Vec<Byte>),
    SerialNumber(Vec<Byte>),
    AcIssuer(Vec<Byte>),
    Owner(Vec<Byte>),
    AttrTypes(Vec<Byte>),
    Trusted(bool),
    CertificateCategory(CertificateCategory),
    JavaMidpSecurityDomain(JavaMidpSecurityDomain),
    Url(String),
    HashOfSubjectPublicKey(Vec<Byte>),
    HashOfIssuerPublicKey(Vec<Byte>),
    NameHashAlgorithm(MechanismType),
    CheckValue(Vec<Byte>),
    KeyType(KeyType),
    Subject(Vec<Byte>),
    Id(Vec<Byte>),
    Sensitive(bool),
    Encrypt(bool),
    Decrypt(bool),
    Wrap(bool),
    Unwrap(bool),
    Sign(bool),
    SignRecover(bool),
    Verify(bool),
    VerifyRecover(bool),
    Derive(bool),
    StartDate(Date),
    EndDate(Date),
    Modulus(Vec<Byte>),
    ModulusBits(Ulong),
    PublicExponent(Vec<Byte>),
    PrivateExponent(Vec<Byte>),
    Prime1(Vec<Byte>),
    Prime2(Vec<Byte>),
    Exponent1(Vec<Byte>),
    Exponent2(Vec<Byte>),
    Coefficient(Vec<Byte>),
    PublicKeyInfo(Vec<Byte>),
    Prime(Vec<Byte>),
    SubPrime(Vec<Byte>),
    Base(Vec<Byte>),
    PrimeBits(Ulong),
    SubPrimeBits(Ulong),
    ValueBits(Ulong),
    ValueLen(Ulong),
    Extractable(bool),
    Local(bool),
    NeverExtractable(bool),
    AlwaysSensitive(bool),
    KeyGenMechanism(MechanismType),
    Modifiable(bool),
    CopyAble(bool),
    DestroyAble(bool),
    EcParams(Vec<Byte>),
    EcPoint(Vec<Byte>),
    AlwaysAuthenticate(bool),
    WrapWithTrusted(bool),
    // WrapTemplate(Vec<Attribute>),
    // UnwrapTemplate(Vec<Attribute>),
    OtpFormat(Ulong),
    OtpLength(Ulong),
    OtpTimeInterval(Ulong),
    OtpUserFriendlyMode(bool),
    OtpChallengeRequirement(Ulong),
    OtpTimeRequirement(Ulong),
    OtpCounterRequirement(Ulong),
    OtpPinRequirement(Ulong),
    OtpCounter(Vec<Byte>),
    OtpTime(Vec<Byte>),
    OtpUserIdentifier(Vec<Byte>),
    OtpServiceIdentifier(Vec<Byte>),
    OtpServiceLogo(Vec<Byte>),
    OtpServiceLogoType(Vec<Byte>),
    GostR3410(Vec<Byte>),
    GostR3411(Vec<Byte>),
    Gots28147(Vec<Byte>),
    HwFeatureType(HwFeatureType),
    ResetOnInit(bool),
    HasReset(bool),
    PixelX(Ulong),
    PixelY(Ulong),
    Resolution(Ulong),
    CharRows(Ulong),
    CharColumns(Ulong),
    Color(bool),
    BitsPerPixel(Ulong),
    CharSets(Vec<Byte>),
    EncodingMethods(Vec<Byte>),
    MimeTypes(Vec<Byte>),
    MechanismType(MechanismType),
    RequiredCmsAttributes(Vec<Byte>),
    DefaultCmsAttributes(Vec<Byte>),
    SupportedCmsAttributes(Vec<Byte>),
    AllowedMechanisms(Vec<MechanismType>),

    /// Vendor defined.
    VendorDefined {
        attr_type: AttributeType,
        value: Vec<Byte>,
    },
}

impl Attribute {
    fn attribute_type(&self) -> AttributeType {
        match self {
            Attribute::Class(_) => AttributeType::CLASS,
            Attribute::Token(_) => AttributeType::TOKEN,
            Attribute::Private(_) => AttributeType::PRIVATE,
            Attribute::Label(_) => AttributeType::LABEL,
            Attribute::Application(_) => AttributeType::APPLICATION,
            Attribute::Value(_) => AttributeType::VALUE,
            Attribute::ObjectId(_) => AttributeType::OBJECT_ID,
            Attribute::CertificateType(_) => AttributeType::CERTIFICATE_TYPE,
            Attribute::Issuer(_) => AttributeType::ISSUER,
            Attribute::SerialNumber(_) => AttributeType::SERIAL_NUMBER,
            Attribute::AcIssuer(_) => AttributeType::AC_ISSUER,
            Attribute::Owner(_) => AttributeType::OWNER,
            Attribute::AttrTypes(_) => AttributeType::ATTR_TYPES,
            Attribute::Trusted(_) => AttributeType::TRUSTED,
            Attribute::CertificateCategory(_) => AttributeType::CERTIFICATE_CATEGORY,
            Attribute::JavaMidpSecurityDomain(_) => {
                AttributeType::JAVA_MIDP_SECURITY_DOMAIN
            }
            Attribute::Url(_) => AttributeType::URL,
            Attribute::HashOfSubjectPublicKey(_) => {
                AttributeType::HASH_OF_SUBJECT_PUBLIC_KEY
            }
            Attribute::HashOfIssuerPublicKey(_) => {
                AttributeType::HASH_OF_ISSUER_PUBLIC_KEY
            }
            Attribute::NameHashAlgorithm(_) => AttributeType::NAME_HASH_ALGORITHM,
            Attribute::CheckValue(_) => AttributeType::CHECK_VALUE,
            Attribute::KeyType(_) => AttributeType::KEY_TYPE,
            Attribute::Subject(_) => AttributeType::SUBJECT,
            Attribute::Id(_) => AttributeType::ID,
            Attribute::Sensitive(_) => AttributeType::SENSITIVE,
            Attribute::Encrypt(_) => AttributeType::ENCRYPT,
            Attribute::Decrypt(_) => AttributeType::DECRYPT,
            Attribute::Wrap(_) => AttributeType::WRAP,
            Attribute::Unwrap(_) => AttributeType::UNWRAP,
            Attribute::Sign(_) => AttributeType::SIGN,
            Attribute::SignRecover(_) => AttributeType::SIGN_RECOVER,
            Attribute::Verify(_) => AttributeType::VERIFY,
            Attribute::VerifyRecover(_) => AttributeType::VERIFY_RECOVER,
            Attribute::Derive(_) => AttributeType::DERIVE,
            Attribute::StartDate(_) => AttributeType::START_DATE,
            Attribute::EndDate(_) => AttributeType::END_DATE,
            Attribute::Modulus(_) => AttributeType::MODULUS,
            Attribute::ModulusBits(_) => AttributeType::MODULUS_BITS,
            Attribute::PublicExponent(_) => AttributeType::PUBLIC_EXPONENT,
            Attribute::PrivateExponent(_) => AttributeType::PRIVATE_EXPONENT,
            Attribute::Prime1(_) => AttributeType::PRIME_1,
            Attribute::Prime2(_) => AttributeType::PRIME_2,
            Attribute::Exponent1(_) => AttributeType::EXPONENT_1,
            Attribute::Exponent2(_) => AttributeType::EXPONENT_2,
            Attribute::Coefficient(_) => AttributeType::COEFFICIENT,
            Attribute::PublicKeyInfo(_) => AttributeType::PUBLIC_KEY_INFO,
            Attribute::Prime(_) => AttributeType::PRIME,
            Attribute::SubPrime(_) => AttributeType::SUBPRIME,
            Attribute::Base(_) => AttributeType::BASE,
            Attribute::PrimeBits(_) => AttributeType::PRIME_BITS,
            Attribute::SubPrimeBits(_) => AttributeType::SUB_PRIME_BITS,
            Attribute::ValueBits(_) => AttributeType::VALUE_BITS,
            Attribute::ValueLen(_) => AttributeType::VALUE_LEN,
            Attribute::Extractable(_) => AttributeType::EXTRACTABLE,
            Attribute::Local(_) => AttributeType::LOCAL,
            Attribute::NeverExtractable(_) => AttributeType::NEVER_EXTRACTABLE,
            Attribute::AlwaysSensitive(_) => AttributeType::ALWAYS_SENSITIVE,
            Attribute::KeyGenMechanism(_) => AttributeType::KEY_GEN_MECHANISM,
            Attribute::Modifiable(_) => AttributeType::MODIFIABLE,
            Attribute::CopyAble(_) => AttributeType::COPYABLE,
            Attribute::DestroyAble(_) => AttributeType::DESTROYABLE,
            Attribute::EcParams(_) => AttributeType::EC_PARAMS,
            Attribute::EcPoint(_) => AttributeType::EC_POINT,
            Attribute::AlwaysAuthenticate(_) => AttributeType::ALWAYS_AUTHENTICATE,
            Attribute::WrapWithTrusted(_) => AttributeType::WRAP_WITH_TRUSTED,
            // Attribute::WrapTemplate(_) => AttributeType::WRAP_TEMPLATE,
            // Attribute::UnwrapTemplate(_) => AttributeType::UNWRAP_TEMPLATE,
            Attribute::OtpFormat(_) => AttributeType::OTP_FORMAT,
            Attribute::OtpLength(_) => AttributeType::OTP_LENGTH,
            Attribute::OtpTimeInterval(_) => AttributeType::OTP_TIME_INTERVAL,
            Attribute::OtpUserFriendlyMode(_) => AttributeType::OTP_USER_FRIENDLY_MODE,
            Attribute::OtpChallengeRequirement(_) => {
                AttributeType::OTP_CHALLENGE_REQUIREMENT
            }
            Attribute::OtpTimeRequirement(_) => AttributeType::OTP_TIME_REQUIREMENT,
            Attribute::OtpCounterRequirement(_) => AttributeType::OTP_COUNTER_REQUIREMENT,
            Attribute::OtpPinRequirement(_) => AttributeType::OTP_PIN_REQUIREMENT,
            Attribute::OtpCounter(_) => AttributeType::OTP_COUNTER,
            Attribute::OtpTime(_) => AttributeType::OTP_TIME,
            Attribute::OtpUserIdentifier(_) => AttributeType::OTP_USER_IDENTIFIER,
            Attribute::OtpServiceIdentifier(_) => AttributeType::OTP_SERVICE_IDENTIFIER,
            Attribute::OtpServiceLogo(_) => AttributeType::OTP_SERVICE_LOGO,
            Attribute::OtpServiceLogoType(_) => AttributeType::OTP_SERVICE_LOGO_TYPE,
            Attribute::GostR3410(_) => AttributeType::GOSTR3410_PARAMS,
            Attribute::GostR3411(_) => AttributeType::GOSTR3411_PARAMS,
            Attribute::Gots28147(_) => AttributeType::GOST28147_PARAMS,
            Attribute::HwFeatureType(_) => AttributeType::HW_FEATURE_TYPE,
            Attribute::ResetOnInit(_) => AttributeType::RESET_ON_INIT,
            Attribute::HasReset(_) => AttributeType::HAS_RESET,
            Attribute::PixelX(_) => AttributeType::PIXEL_X,
            Attribute::PixelY(_) => AttributeType::PIXEL_Y,
            Attribute::Resolution(_) => AttributeType::RESOLUTION,
            Attribute::CharRows(_) => AttributeType::CHAR_ROWS,
            Attribute::CharColumns(_) => AttributeType::CHAR_COLUMNS,
            Attribute::Color(_) => AttributeType::COLOR,
            Attribute::BitsPerPixel(_) => AttributeType::BITS_PER_PIXEL,
            Attribute::CharSets(_) => AttributeType::CHAR_SETS,
            Attribute::EncodingMethods(_) => AttributeType::ENCODING_METHODS,
            Attribute::MimeTypes(_) => AttributeType::MIME_TYPES,
            Attribute::MechanismType(_) => AttributeType::MECHANISM_TYPE,
            Attribute::RequiredCmsAttributes(_) => AttributeType::REQUIRED_CMS_ATTRIBUTES,
            Attribute::DefaultCmsAttributes(_) => AttributeType::DEFAULT_CMS_ATTRIBUTES,
            Attribute::SupportedCmsAttributes(_) => {
                AttributeType::SUPPORTED_CMS_ATTRIBUTES
            }
            Attribute::AllowedMechanisms(_) => AttributeType::ALLOWED_MECHANISMS,
            Attribute::VendorDefined { attr_type, .. } => *attr_type,
        }
    }

    fn ptr(&self) -> CK_VOID_PTR {
        match self {
            // bool
            Attribute::Token(b)
            | Attribute::Private(b)
            | Attribute::Trusted(b)
            | Attribute::Sensitive(b)
            | Attribute::Encrypt(b)
            | Attribute::Decrypt(b)
            | Attribute::Wrap(b)
            | Attribute::Unwrap(b)
            | Attribute::Sign(b)
            | Attribute::SignRecover(b)
            | Attribute::Verify(b)
            | Attribute::VerifyRecover(b)
            | Attribute::Derive(b)
            | Attribute::Extractable(b)
            | Attribute::Local(b)
            | Attribute::NeverExtractable(b)
            | Attribute::AlwaysSensitive(b)
            | Attribute::Modifiable(b)
            | Attribute::CopyAble(b)
            | Attribute::DestroyAble(b)
            | Attribute::AlwaysAuthenticate(b)
            | Attribute::WrapWithTrusted(b)
            | Attribute::OtpUserFriendlyMode(b)
            | Attribute::ResetOnInit(b)
            | Attribute::HasReset(b)
            | Attribute::Color(b) => b as *const _ as CK_VOID_PTR,

            // Ulong
            Attribute::ModulusBits(ulong)
            | Attribute::PrimeBits(ulong)
            | Attribute::SubPrimeBits(ulong)
            | Attribute::ValueBits(ulong)
            | Attribute::ValueLen(ulong)
            | Attribute::OtpFormat(ulong)
            | Attribute::OtpLength(ulong)
            | Attribute::OtpTimeInterval(ulong)
            | Attribute::OtpChallengeRequirement(ulong)
            | Attribute::OtpTimeRequirement(ulong)
            | Attribute::OtpCounterRequirement(ulong)
            | Attribute::OtpPinRequirement(ulong)
            | Attribute::PixelX(ulong)
            | Attribute::PixelY(ulong)
            | Attribute::Resolution(ulong)
            | Attribute::CharRows(ulong)
            | Attribute::CharColumns(ulong)
            | Attribute::BitsPerPixel(ulong) => ulong as *const _ as CK_VOID_PTR,

            // String
            Attribute::Label(s) | Attribute::Application(s) | Attribute::Url(s) => {
                s.as_ptr() as CK_VOID_PTR
            }

            // Vec<Byte>
            Attribute::Value(v)
            | Attribute::ObjectId(v)
            | Attribute::Issuer(v)
            | Attribute::SerialNumber(v)
            | Attribute::AcIssuer(v)
            | Attribute::Owner(v)
            | Attribute::AttrTypes(v)
            | Attribute::HashOfSubjectPublicKey(v)
            | Attribute::HashOfIssuerPublicKey(v)
            | Attribute::CheckValue(v)
            | Attribute::Subject(v)
            | Attribute::Id(v)
            | Attribute::Modulus(v)
            | Attribute::PublicExponent(v)
            | Attribute::PrivateExponent(v)
            | Attribute::Prime1(v)
            | Attribute::Prime2(v)
            | Attribute::Exponent1(v)
            | Attribute::Exponent2(v)
            | Attribute::Coefficient(v)
            | Attribute::PublicKeyInfo(v)
            | Attribute::Prime(v)
            | Attribute::SubPrime(v)
            | Attribute::Base(v)
            | Attribute::EcParams(v)
            | Attribute::EcPoint(v)
            | Attribute::OtpCounter(v)
            | Attribute::OtpTime(v)
            | Attribute::OtpUserIdentifier(v)
            | Attribute::OtpServiceIdentifier(v)
            | Attribute::OtpServiceLogo(v)
            | Attribute::OtpServiceLogoType(v)
            | Attribute::GostR3410(v)
            | Attribute::GostR3411(v)
            | Attribute::Gots28147(v)
            | Attribute::CharSets(v)
            | Attribute::EncodingMethods(v)
            | Attribute::MimeTypes(v)
            | Attribute::RequiredCmsAttributes(v)
            | Attribute::DefaultCmsAttributes(v)
            | Attribute::SupportedCmsAttributes(v) => v.as_ptr() as CK_VOID_PTR,

            // Date
            Attribute::StartDate(date) | Attribute::EndDate(date) => {
                date as *const _ as CK_VOID_PTR
            }

            //
            Attribute::Class(c) => c as *const _ as CK_VOID_PTR,
            Attribute::CertificateType(t) => t as *const _ as CK_VOID_PTR,
            Attribute::CertificateCategory(c) => c as *const _ as CK_VOID_PTR,
            Attribute::JavaMidpSecurityDomain(d) => d as *const _ as CK_VOID_PTR,
            Attribute::NameHashAlgorithm(t) => t as *const _ as CK_VOID_PTR,
            Attribute::KeyGenMechanism(t) => t as *const _ as CK_VOID_PTR,
            Attribute::KeyType(t) => t as *const _ as CK_VOID_PTR,
            Attribute::HwFeatureType(t) => t as *const _ as CK_VOID_PTR,
            Attribute::MechanismType(t) => t as *const _ as CK_VOID_PTR,

            //
            Attribute::AllowedMechanisms(mechanisms) => {
                mechanisms.as_ptr() as CK_VOID_PTR
            } // Attribute::WrapTemplate(attr)
            // | Attribute::UnwrapTemplate(attr) =>

            //
            Attribute::VendorDefined { value, .. } => value.as_ptr() as CK_VOID_PTR,
        }
    }

    fn len(&self) -> Ulong {
        match self {
            // bool
            Attribute::Token(_)
            | Attribute::Private(_)
            | Attribute::Trusted(_)
            | Attribute::Sensitive(_)
            | Attribute::Encrypt(_)
            | Attribute::Decrypt(_)
            | Attribute::Wrap(_)
            | Attribute::Unwrap(_)
            | Attribute::Sign(_)
            | Attribute::SignRecover(_)
            | Attribute::Verify(_)
            | Attribute::VerifyRecover(_)
            | Attribute::Derive(_)
            | Attribute::Extractable(_)
            | Attribute::Local(_)
            | Attribute::NeverExtractable(_)
            | Attribute::AlwaysSensitive(_)
            | Attribute::Modifiable(_)
            | Attribute::CopyAble(_)
            | Attribute::DestroyAble(_)
            | Attribute::AlwaysAuthenticate(_)
            | Attribute::WrapWithTrusted(_)
            | Attribute::OtpUserFriendlyMode(_)
            | Attribute::ResetOnInit(_)
            | Attribute::HasReset(_)
            | Attribute::Color(_) => std::mem::size_of::<bool>() as Ulong,

            // Ulong
            Attribute::ModulusBits(_)
            | Attribute::PrimeBits(_)
            | Attribute::SubPrimeBits(_)
            | Attribute::ValueBits(_)
            | Attribute::ValueLen(_)
            | Attribute::OtpFormat(_)
            | Attribute::OtpLength(_)
            | Attribute::OtpTimeInterval(_)
            | Attribute::OtpChallengeRequirement(_)
            | Attribute::OtpTimeRequirement(_)
            | Attribute::OtpCounterRequirement(_)
            | Attribute::OtpPinRequirement(_)
            | Attribute::PixelX(_)
            | Attribute::PixelY(_)
            | Attribute::Resolution(_)
            | Attribute::CharRows(_)
            | Attribute::CharColumns(_)
            | Attribute::BitsPerPixel(_) => std::mem::size_of::<Ulong>() as Ulong,

            // String
            Attribute::Label(s) | Attribute::Application(s) | Attribute::Url(s) => {
                s.len() as Ulong
            }

            // Vec<Byte>
            Attribute::Value(v)
            | Attribute::ObjectId(v)
            | Attribute::Issuer(v)
            | Attribute::SerialNumber(v)
            | Attribute::AcIssuer(v)
            | Attribute::Owner(v)
            | Attribute::AttrTypes(v)
            | Attribute::HashOfSubjectPublicKey(v)
            | Attribute::HashOfIssuerPublicKey(v)
            | Attribute::CheckValue(v)
            | Attribute::Subject(v)
            | Attribute::Id(v)
            | Attribute::Modulus(v)
            | Attribute::PublicExponent(v)
            | Attribute::PrivateExponent(v)
            | Attribute::Prime1(v)
            | Attribute::Prime2(v)
            | Attribute::Exponent1(v)
            | Attribute::Exponent2(v)
            | Attribute::Coefficient(v)
            | Attribute::PublicKeyInfo(v)
            | Attribute::Prime(v)
            | Attribute::SubPrime(v)
            | Attribute::Base(v)
            | Attribute::EcParams(v)
            | Attribute::EcPoint(v)
            | Attribute::OtpCounter(v)
            | Attribute::OtpTime(v)
            | Attribute::OtpUserIdentifier(v)
            | Attribute::OtpServiceIdentifier(v)
            | Attribute::OtpServiceLogo(v)
            | Attribute::OtpServiceLogoType(v)
            | Attribute::GostR3410(v)
            | Attribute::GostR3411(v)
            | Attribute::Gots28147(v)
            | Attribute::CharSets(v)
            | Attribute::EncodingMethods(v)
            | Attribute::MimeTypes(v)
            | Attribute::RequiredCmsAttributes(v)
            | Attribute::DefaultCmsAttributes(v)
            | Attribute::SupportedCmsAttributes(v) => {
                (std::mem::size_of::<Byte>() * v.len()) as Ulong
            }

            // Date
            Attribute::StartDate(_) | Attribute::EndDate(_) => {
                std::mem::size_of::<Date>() as Ulong
            }

            // MechanismType
            Attribute::NameHashAlgorithm(_)
            | Attribute::KeyGenMechanism(_)
            | Attribute::MechanismType(_) => {
                std::mem::size_of::<MechanismType>() as Ulong
            }

            //
            Attribute::Class(_) => std::mem::size_of::<ObjectClass>() as Ulong,
            Attribute::CertificateType(_) => {
                std::mem::size_of::<CertificateType>() as Ulong
            }
            Attribute::CertificateCategory(_) => {
                std::mem::size_of::<CertificateCategory>() as Ulong
            }
            Attribute::JavaMidpSecurityDomain(_) => {
                std::mem::size_of::<JavaMidpSecurityDomain>() as Ulong
            }
            Attribute::KeyType(_) => std::mem::size_of::<KeyType>() as Ulong,
            Attribute::HwFeatureType(_) => std::mem::size_of::<HwFeatureType>() as Ulong,

            //
            Attribute::AllowedMechanisms(v) => {
                (std::mem::size_of::<MechanismType>() * v.len()) as Ulong
            } // Attribute::WrapTemplate(attr)
            // | Attribute::UnwrapTemplate(attr) =>

            // Vendor defined
            Attribute::VendorDefined { value, .. } => {
                (std::mem::size_of::<Byte>() * value.len()) as Ulong
            }
        }
    }
}

impl From<&Attribute> for CK_ATTRIBUTE {
    fn from(attribute: &Attribute) -> Self {
        Self {
            attrType: attribute.attribute_type().into(),
            pValue: attribute.ptr(),
            ulValueLen: attribute.len(),
        }
    }
}

impl From<&CK_ATTRIBUTE> for bool {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let b: CK_BBOOL =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_BBOOL) };

        !matches!(b, 0)
    }
}

impl From<&CK_ATTRIBUTE> for String {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let value: &[u8] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const u8,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };
        String::from_utf8_lossy(value).into_owned()
    }
}

impl From<&CK_ATTRIBUTE> for Ulong {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let value: CK_ULONG =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_ULONG) };

        value
    }
}

impl From<&CK_ATTRIBUTE> for Vec<Byte> {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let value: &[Byte] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const Byte,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };
        value.to_vec()
    }
}

// Get rust byte vector from CK_ATTRIBUTE.
pub(crate) fn try_from_ck_attribute_for_vec_mechanism_type(
    ck_attribute: &CK_ATTRIBUTE,
) -> Result<Vec<MechanismType>> {
    let value: &[CK_MECHANISM_TYPE] = unsafe {
        std::slice::from_raw_parts(
            ck_attribute.pValue as *const CK_MECHANISM_TYPE,
            ck_attribute.ulValueLen as CK_ULONG as usize,
        )
    };

    let types: Vec<MechanismType> = value
        .iter()
        .copied()
        .map(|t| t.try_into())
        .collect::<Result<Vec<MechanismType>>>()?;
    Ok(types)
}

impl From<&CK_ATTRIBUTE> for Date {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let value: CK_DATE =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_DATE) };

        value
    }
}

/// Try convert CK_ATTRIBUTE to Attribute.
///
/// Note that pValue is a "void" pointer, facilitating the passing of arbitrary
/// values. Both the application and Cryptoki library MUST ensure that the
/// pointer can be safely cast to the expected type (i.e., without
/// word-alignment errors).
impl TryFrom<CK_ATTRIBUTE> for Attribute {
    type Error = Error;

    fn try_from(ck_attribute: CK_ATTRIBUTE) -> Result<Self> {
        let attr_type = AttributeType::try_from(ck_attribute.attrType)?;

        match attr_type {
            AttributeType::CLASS => {
                Ok(Attribute::Class(Ulong::from(&ck_attribute).try_into()?))
            }
            AttributeType::TOKEN => Ok(Attribute::Token(bool::from(&ck_attribute))),
            AttributeType::PRIVATE => Ok(Attribute::Private(bool::from(&ck_attribute))),
            AttributeType::LABEL => Ok(Attribute::Label(String::from(&ck_attribute))),
            AttributeType::APPLICATION => {
                Ok(Attribute::Application(String::from(&ck_attribute)))
            }
            AttributeType::VALUE => {
                Ok(Attribute::Value(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::OBJECT_ID => {
                Ok(Attribute::ObjectId(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::CERTIFICATE_TYPE => Ok(Attribute::CertificateType(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::ISSUER => {
                Ok(Attribute::Issuer(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::SERIAL_NUMBER => {
                Ok(Attribute::SerialNumber(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::AC_ISSUER => {
                Ok(Attribute::AcIssuer(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::OWNER => {
                Ok(Attribute::Owner(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::ATTR_TYPES => {
                Ok(Attribute::AttrTypes(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::TRUSTED => Ok(Attribute::Trusted(bool::from(&ck_attribute))),
            AttributeType::CERTIFICATE_CATEGORY => Ok(Attribute::CertificateCategory(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::JAVA_MIDP_SECURITY_DOMAIN => Ok(
                Attribute::JavaMidpSecurityDomain(Ulong::from(&ck_attribute).try_into()?),
            ),
            AttributeType::URL => Ok(Attribute::Url(String::from(&ck_attribute))),
            AttributeType::HASH_OF_SUBJECT_PUBLIC_KEY => Ok(
                Attribute::HashOfSubjectPublicKey(Vec::<Byte>::from(&ck_attribute)),
            ),
            AttributeType::HASH_OF_ISSUER_PUBLIC_KEY => Ok(
                Attribute::HashOfIssuerPublicKey(Vec::<Byte>::from(&ck_attribute)),
            ),
            AttributeType::NAME_HASH_ALGORITHM => Ok(Attribute::NameHashAlgorithm(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::CHECK_VALUE => {
                Ok(Attribute::CheckValue(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::KEY_TYPE => {
                Ok(Attribute::KeyType(Ulong::from(&ck_attribute).try_into()?))
            }
            AttributeType::SUBJECT => {
                Ok(Attribute::Subject(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::ID => Ok(Attribute::Id(Vec::<Byte>::from(&ck_attribute))),
            AttributeType::SENSITIVE => {
                Ok(Attribute::Sensitive(bool::from(&ck_attribute)))
            }
            AttributeType::ENCRYPT => Ok(Attribute::Encrypt(bool::from(&ck_attribute))),
            AttributeType::DECRYPT => Ok(Attribute::Decrypt(bool::from(&ck_attribute))),
            AttributeType::WRAP => Ok(Attribute::Wrap(bool::from(&ck_attribute))),
            AttributeType::UNWRAP => Ok(Attribute::Unwrap(bool::from(&ck_attribute))),
            AttributeType::SIGN => Ok(Attribute::Sign(bool::from(&ck_attribute))),
            AttributeType::SIGN_RECOVER => {
                Ok(Attribute::SignRecover(bool::from(&ck_attribute)))
            }
            AttributeType::VERIFY => Ok(Attribute::Verify(bool::from(&ck_attribute))),
            AttributeType::VERIFY_RECOVER => {
                Ok(Attribute::VerifyRecover(bool::from(&ck_attribute)))
            }
            AttributeType::DERIVE => Ok(Attribute::Derive(bool::from(&ck_attribute))),
            AttributeType::START_DATE => {
                Ok(Attribute::StartDate(Date::from(&ck_attribute)))
            }
            AttributeType::END_DATE => Ok(Attribute::EndDate(Date::from(&ck_attribute))),
            AttributeType::MODULUS => {
                Ok(Attribute::Modulus(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::MODULUS_BITS => {
                Ok(Attribute::ModulusBits(Ulong::from(&ck_attribute)))
            }
            AttributeType::PUBLIC_EXPONENT => {
                Ok(Attribute::PublicExponent(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::PRIVATE_EXPONENT => {
                Ok(Attribute::PrivateExponent(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::PRIME_1 => {
                Ok(Attribute::Prime1(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::PRIME_2 => {
                Ok(Attribute::Prime2(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::EXPONENT_1 => {
                Ok(Attribute::Exponent1(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::EXPONENT_2 => {
                Ok(Attribute::Exponent2(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::COEFFICIENT => {
                Ok(Attribute::Coefficient(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::PUBLIC_KEY_INFO => {
                Ok(Attribute::PublicKeyInfo(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::PRIME => {
                Ok(Attribute::Prime(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::SUBPRIME => {
                Ok(Attribute::SubPrime(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::BASE => Ok(Attribute::Base(Vec::<Byte>::from(&ck_attribute))),
            AttributeType::PRIME_BITS => {
                Ok(Attribute::PrimeBits(Ulong::from(&ck_attribute)))
            }
            AttributeType::SUB_PRIME_BITS => {
                Ok(Attribute::SubPrimeBits(Ulong::from(&ck_attribute)))
            }
            AttributeType::VALUE_BITS => {
                Ok(Attribute::ValueBits(Ulong::from(&ck_attribute)))
            }
            AttributeType::VALUE_LEN => {
                Ok(Attribute::ValueLen(Ulong::from(&ck_attribute)))
            }
            AttributeType::EXTRACTABLE => {
                Ok(Attribute::Extractable(bool::from(&ck_attribute)))
            }
            AttributeType::LOCAL => Ok(Attribute::Local(bool::from(&ck_attribute))),
            AttributeType::NEVER_EXTRACTABLE => {
                Ok(Attribute::NeverExtractable(bool::from(&ck_attribute)))
            }
            AttributeType::ALWAYS_SENSITIVE => {
                Ok(Attribute::AlwaysSensitive(bool::from(&ck_attribute)))
            }
            AttributeType::KEY_GEN_MECHANISM => Ok(Attribute::KeyGenMechanism(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::MODIFIABLE => {
                Ok(Attribute::Modifiable(bool::from(&ck_attribute)))
            }
            AttributeType::COPYABLE => Ok(Attribute::CopyAble(bool::from(&ck_attribute))),
            AttributeType::DESTROYABLE => {
                Ok(Attribute::DestroyAble(bool::from(&ck_attribute)))
            }
            AttributeType::EC_PARAMS => {
                Ok(Attribute::EcParams(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::EC_POINT => {
                Ok(Attribute::EcPoint(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::ALWAYS_AUTHENTICATE => {
                Ok(Attribute::AlwaysAuthenticate(bool::from(&ck_attribute)))
            }
            AttributeType::WRAP_WITH_TRUSTED => {
                Ok(Attribute::WrapWithTrusted(bool::from(&ck_attribute)))
            }
            // AttributeType::WRAP_TEMPLATE => Ok(Attribute::WrapTemplate(get_())),
            // AttributeType::UNWRAP_TEMPLATE => Ok(Attribute::UnwrapTemplate(get_())),
            AttributeType::OTP_FORMAT => {
                Ok(Attribute::OtpFormat(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_LENGTH => {
                Ok(Attribute::OtpLength(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_TIME_INTERVAL => {
                Ok(Attribute::OtpTimeInterval(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_USER_FRIENDLY_MODE => {
                Ok(Attribute::OtpUserFriendlyMode(bool::from(&ck_attribute)))
            }
            AttributeType::OTP_CHALLENGE_REQUIREMENT => Ok(
                Attribute::OtpChallengeRequirement(Ulong::from(&ck_attribute)),
            ),
            AttributeType::OTP_TIME_REQUIREMENT => {
                Ok(Attribute::OtpTimeRequirement(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_COUNTER_REQUIREMENT => {
                Ok(Attribute::OtpCounterRequirement(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_PIN_REQUIREMENT => {
                Ok(Attribute::OtpPinRequirement(Ulong::from(&ck_attribute)))
            }
            AttributeType::OTP_COUNTER => {
                Ok(Attribute::OtpCounter(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::OTP_TIME => {
                Ok(Attribute::OtpTime(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::OTP_USER_IDENTIFIER => Ok(Attribute::OtpUserIdentifier(
                Vec::<Byte>::from(&ck_attribute),
            )),
            AttributeType::OTP_SERVICE_IDENTIFIER => Ok(Attribute::OtpServiceIdentifier(
                Vec::<Byte>::from(&ck_attribute),
            )),
            AttributeType::OTP_SERVICE_LOGO => {
                Ok(Attribute::OtpServiceLogo(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::OTP_SERVICE_LOGO_TYPE => Ok(Attribute::OtpServiceLogoType(
                Vec::<Byte>::from(&ck_attribute),
            )),
            AttributeType::GOSTR3410_PARAMS => {
                Ok(Attribute::GostR3410(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::GOSTR3411_PARAMS => {
                Ok(Attribute::GostR3411(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::GOST28147_PARAMS => {
                Ok(Attribute::Gots28147(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::HW_FEATURE_TYPE => Ok(Attribute::HwFeatureType(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::RESET_ON_INIT => {
                Ok(Attribute::ResetOnInit(bool::from(&ck_attribute)))
            }
            AttributeType::HAS_RESET => {
                Ok(Attribute::HasReset(bool::from(&ck_attribute)))
            }
            AttributeType::PIXEL_X => Ok(Attribute::PixelX(Ulong::from(&ck_attribute))),
            AttributeType::PIXEL_Y => Ok(Attribute::PixelY(Ulong::from(&ck_attribute))),
            AttributeType::RESOLUTION => {
                Ok(Attribute::Resolution(Ulong::from(&ck_attribute)))
            }
            AttributeType::CHAR_ROWS => {
                Ok(Attribute::CharRows(Ulong::from(&ck_attribute)))
            }
            AttributeType::CHAR_COLUMNS => {
                Ok(Attribute::CharColumns(Ulong::from(&ck_attribute)))
            }
            AttributeType::COLOR => Ok(Attribute::Color(bool::from(&ck_attribute))),
            AttributeType::BITS_PER_PIXEL => {
                Ok(Attribute::BitsPerPixel(Ulong::from(&ck_attribute)))
            }
            AttributeType::CHAR_SETS => {
                Ok(Attribute::CharSets(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::ENCODING_METHODS => {
                Ok(Attribute::EncodingMethods(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::MIME_TYPES => {
                Ok(Attribute::MimeTypes(Vec::<Byte>::from(&ck_attribute)))
            }
            AttributeType::MECHANISM_TYPE => Ok(Attribute::MechanismType(
                Ulong::from(&ck_attribute).try_into()?,
            )),
            AttributeType::REQUIRED_CMS_ATTRIBUTES => Ok(
                Attribute::RequiredCmsAttributes(Vec::<Byte>::from(&ck_attribute)),
            ),
            AttributeType::DEFAULT_CMS_ATTRIBUTES => Ok(Attribute::DefaultCmsAttributes(
                Vec::<Byte>::from(&ck_attribute),
            )),
            AttributeType::SUPPORTED_CMS_ATTRIBUTES => Ok(
                Attribute::SupportedCmsAttributes(Vec::<Byte>::from(&ck_attribute)),
            ),
            AttributeType::ALLOWED_MECHANISMS => Ok(Attribute::AllowedMechanisms(
                try_from_ck_attribute_for_vec_mechanism_type(&ck_attribute)?,
            )),
            vendor_defined => Ok(Attribute::VendorDefined {
                attr_type: vendor_defined,
                value: Vec::<Byte>::from(&ck_attribute),
            }),
        }
    }
}
