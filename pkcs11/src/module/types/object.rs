use std::convert::TryFrom;

use pkcs11_macros::{
    AttributePodType, TryFromCkAttribute, pkcs11_attribute_type, pkcs11_type,
};

use crate::error::{Error, Result};

use super::{MechanismType, general::*};

pub type ObjectHandle = CK_OBJECT_HANDLE;

pkcs11_type!(
    /// Identifies the classes (or types) of objects that Cryptoki recognizes.
    ///
    /// Object classes are defined with the objects that use them. The type
    /// is specified on an object through the
    /// [`Attribute::Class`](crate::module::types::Attribute::Class)
    /// attribute of the object.
    #[derive(AttributePodType, TryFromCkAttribute)]
    ObjectClass: CK_OBJECT_CLASS, naming = ScreamingSnakeCase;
    [
        /// Data objects hold information defined by an application.
        CKO_DATA,
        /// Certificate objects hold public-key or attribute certificates.
        CKO_CERTIFICATE,
        /// Public key object.
        CKO_PUBLIC_KEY,
        /// Private key object.
        CKO_PRIVATE_KEY,
        /// Secret key object.
        CKO_SECRET_KEY,
        /// Hardware feature objects represent features of the device.
        CKO_HW_FEATURE,
        /// Domain parameter objects hold public domain parameters.
        CKO_DOMAIN_PARAMETERS,
        /// Mechanism objects provide information about mechanisms
        /// supported by a device beyond that given by
        /// the CK_MECHANISM_INFO structure.
        CKO_MECHANISM,
        /// OTP key object.
        CKO_OTP_KEY,
        /// Profile objects describe which PKCS #11 profiles the token
        /// implements. Profiles are defined in the OASIS PKCS #11
        /// Cryptographic Token Interface Profiles document. A given token
        /// can contain more than one profile ID.
        CKO_PROFILE,
        /// Validation objects describe which third party validations the
        /// module conforms to. Validation objects are read only, token
        /// objects.
        CKO_VALIDATION,
        /// Trust objects bind trusted usages to individual certificates.
        CKO_TRUST,

        CKO_VENDOR_DEFINED,
    ]
);

pkcs11_type!(
    /// Identifies a hardware feature type of a device.
    ///
    /// Hardware feature types are defined with the objects that use them.
    /// The type is specified on an object through the
    /// [`Attribute::HwFeatureType`](crate::module::types::Attribute::HwFeatureType)
    /// attribute of the object.
    #[derive(AttributePodType, TryFromCkAttribute)]
    HwFeatureType: CK_HW_FEATURE_TYPE, naming = ScreamingSnakeCase;
    [
        /// Monotonic counter objects represent hardware counters that exist on
        /// the device. The counter is guaranteed to increase each time its
        /// value is read, but not necessarily by one. This might be used by an
        /// application for generating serial numbers to get some assurance of
        /// uniqueness per token.
        CKH_MONOTONIC_COUNTER,

        /// Clock objects represent real-time clocks that exist on the device.
        /// This represents the same clock source as the utcTime field
        /// in the CK_TOKEN_INFO structure.
        CKH_CLOCK,

        /// User interface objects represent the presentation
        /// capabilities of the device.
        CKH_USER_INTERFACE,

        CKH_VENDOR_DEFINED,
    ]
);

pkcs11_type!(
    /// Identifies a key type.
    ///
    /// Key types are defined with the objects and mechanisms that use them.
    /// The key type is specified on an object through the
    /// [`Attribute::KeyType`](crate::module::types::Attribute::KeyType)
    /// attribute of the object.
    #[derive(AttributePodType, TryFromCkAttribute)]
    KeyType: CK_KEY_TYPE, naming = ScreamingSnakeCase;
    [
        CKK_RSA,
        CKK_DSA,
        CKK_DH,
        CKK_EC,
        CKK_X9_42_DH,
        /// Historical
        CKK_KEA,
        CKK_GENERIC_SECRET,
        /// Historical
        CKK_RC2,
        /// Historical
        CKK_RC4,
        /// Historical
        CKK_DES,
        CKK_DES2,
        CKK_DES3,

        /// Historical
        CKK_CAST,
        /// Historical
        CKK_CAST3,
        /// Historical
        CKK_CAST128,
        /// Historical
        CKK_RC5,
        /// Historical
        CKK_IDEA,
        /// Historical
        CKK_SKIPJACK,
        /// Historical
        CKK_BATON,
        /// Historical
        CKK_JUNIPER,
        /// Historical
        CKK_CDMF,
        CKK_AES,
        CKK_BLOWFISH,
        CKK_TWOFISH,
        CKK_SECURID,
        /// Historical
        CKK_HOTP,
        /// Historical
        CKK_ACTI,
        CKK_CAMELLIA,
        CKK_ARIA,

        // The following definitions were added in the 2.30 header file,
        // but never defined in the spec.

        /// Historical
        CKK_MD5_HMAC,
        CKK_SHA_1_HMAC,
        /// Historical
        CKK_RIPEMD128_HMAC,
        /// Historical
        CKK_RIPEMD160_HMAC,
        CKK_SHA256_HMAC,
        CKK_SHA384_HMAC,
        CKK_SHA512_HMAC,
        CKK_SHA224_HMAC,

        CKK_SEED,
        CKK_GOSTR3410,
        CKK_GOSTR3411,
        CKK_GOST28147,
        CKK_CHACHA20,
        CKK_POLY1305,
        CKK_AES_XTS,
        CKK_SHA3_224_HMAC,
        CKK_SHA3_256_HMAC,
        CKK_SHA3_384_HMAC,
        CKK_SHA3_512_HMAC,
        CKK_BLAKE2B_160_HMAC,
        CKK_BLAKE2B_256_HMAC,
        CKK_BLAKE2B_384_HMAC,
        CKK_BLAKE2B_512_HMAC,
        CKK_SALSA20,
        CKK_X2RATCHET,
        CKK_EC_EDWARDS,
        CKK_EC_MONTGOMERY,
        CKK_HKDF,

        CKK_SHA512_224_HMAC,
        CKK_SHA512_256_HMAC,
        CKK_SHA512_T_HMAC,
        CKK_HSS,

        CKK_XMSS,
        CKK_XMSSMT,
        CKK_ML_KEM,
        CKK_ML_DSA,
        CKK_SLH_DSA,

        CKK_VENDOR_DEFINED,
    ]
);

pkcs11_type!(
    /// Identifies a certificate type.
    ///
    /// Certificate types are defined with the objects and mechanisms that use
    /// them. The certificate type is specified on an object through the
    /// [`Attribute::CertificateType`](crate::module::types::Attribute::CertificateType)
    /// attribute of the object.
    #[derive(AttributePodType, TryFromCkAttribute)]
    CertificateType: CK_CERTIFICATE_TYPE, naming = ScreamingSnakeCase;
    [
        /// X.509 certificate objects hold X.509 public key certificates.
        CKC_X_509,
        /// X.509 attribute certificate objects hold X.509 attribute certificates.
        CKC_X_509_ATTR_CERT,
        /// WTLS certificate objects hold WTLS public key certificates.
        CKC_WTLS,

        CKC_VENDOR_DEFINED,
    ]
);

pkcs11_type!(
    /// Identifies a certificate category.
    #[derive(AttributePodType, TryFromCkAttribute)]
    CertificateCategory: CK_CERTIFICATE_CATEGORY, naming = ScreamingSnakeCase;
    [
        /// No category specified.
        CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
        /// Certificate belongs to owner of the token.
        CK_CERTIFICATE_CATEGORY_TOKEN_USER,
        /// Certificate belongs to a certificate authority.
        CK_CERTIFICATE_CATEGORY_AUTHORITY,
        /// Certificate belongs to an end entity (i.e.: not a CA).
        CK_CERTIFICATE_CATEGORY_OTHER_ENTITY,
    ]
);

pkcs11_type!(
    /// Identifies the Java MIDP security domain of a certificate.
    #[derive(AttributePodType, TryFromCkAttribute)]
    JavaMidpSecurityDomain: CK_JAVA_MIDP_SECURITY_DOMAIN, naming = ScreamingSnakeCase;
    [
        /// No domain specified.
        CK_SECURITY_DOMAIN_UNSPECIFIED,
        /// Manufacturer protection domain.
        CK_SECURITY_DOMAIN_MANUFACTURER,
        /// Operator protection domain.
        CK_SECURITY_DOMAIN_OPERATOR,
        /// Third party protection domain.
        CK_SECURITY_DOMAIN_THIRD_PARTY,
    ]
);

#[allow(clippy::len_without_is_empty)]
pub trait AttributeValue {
    fn as_ck_ptr(&self) -> CK_VOID_PTR;
    fn len(&self) -> Ulong;
}

pub trait CkPodType: Sized {}

macro_rules! impl_ck_pod_type {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CkPodType for $ty {}
        )+
    };
}

impl_ck_pod_type!(bool, Ulong, Date);

impl<T: CkPodType> AttributeValue for T {
    fn as_ck_ptr(&self) -> CK_VOID_PTR {
        self as *const T as CK_VOID_PTR
    }

    fn len(&self) -> Ulong {
        std::mem::size_of::<T>() as Ulong
    }
}

impl<T> AttributeValue for Vec<T> {
    fn as_ck_ptr(&self) -> CK_VOID_PTR {
        self.as_ptr() as CK_VOID_PTR
    }

    fn len(&self) -> Ulong {
        std::mem::size_of_val(self.as_slice()) as Ulong
    }
}

impl AttributeValue for String {
    fn as_ck_ptr(&self) -> CK_VOID_PTR {
        self.as_ptr() as CK_VOID_PTR
    }

    fn len(&self) -> Ulong {
        self.len() as Ulong
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorDefinedAttribute {
    pub attr_type: AttributeType,
    pub value: Vec<Byte>,
}

pub trait TryFromCkAttribute: Sized {
    fn try_from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Self>;
}

impl TryFromCkAttribute for bool {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        if ck_attribute.pValue.is_null() {
            return Ok(false);
        }
        let b: CK_BBOOL =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_BBOOL) };

        Ok(!matches!(b, 0))
    }
}

impl TryFromCkAttribute for Ulong {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        if ck_attribute.pValue.is_null() {
            return Ok(0);
        }
        let value: CK_ULONG =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_ULONG) };

        Ok(value)
    }
}

impl TryFromCkAttribute for Date {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        let value: CK_DATE =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_DATE) };

        value.try_into()
    }
}

impl TryFromCkAttribute for String {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return Ok(String::new());
        }
        let value: &[u8] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const u8,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };

        Ok(String::from_utf8_lossy(value).into_owned())
    }
}

impl TryFromCkAttribute for Vec<Byte> {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return Ok(Vec::new());
        }
        let value: &[Byte] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const Byte,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };

        Ok(value.to_vec())
    }
}

impl TryFromCkAttribute for Vec<MechanismType> {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return Ok(Vec::new());
        }
        let value: &[CK_MECHANISM_TYPE] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const CK_MECHANISM_TYPE,
                ck_attribute.ulValueLen as CK_ULONG as usize
                    / std::mem::size_of::<CK_MECHANISM_TYPE>(),
            )
        };

        value
            .iter()
            .copied()
            .map(|t| t.try_into())
            .collect::<Result<Vec<MechanismType>>>()
    }
}

impl TryFromCkAttribute for VendorDefinedAttribute {
    fn try_from_ck_attr(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
        let attr_type = AttributeType::try_from(ck_attribute.attrType)?;

        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return Ok(VendorDefinedAttribute {
                attr_type,
                value: Vec::new(),
            });
        }
        let value: &[Byte] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const Byte,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };

        Ok(VendorDefinedAttribute {
            attr_type,
            value: value.to_vec(),
        })
    }
}

// TODO: add missing attributes/types
pkcs11_attribute_type!(
    /// Identifies an attribute.
    ///
    /// An array of Attribute is called a "template" and is used for creating,
    /// manipulating and searching for objects.
    #[non_exhaustive]
    Attribute, naming = UpperCamelCase;
    [
        /// Object class type.
        CKA_CLASS: ObjectClass,
        /// Identifies whether the object is a token object or a session object.
        CKA_TOKEN: bool,
        /// Identifies whether the ojbect is private.
        CKA_PRIVATE: bool,
        /// Description of the object.
        CKA_LABEL: String,
        /// The unique identifier assigned to the object.
        CKA_UNIQUE_ID: String,
        /// Description of the application that manages the object.
        CKA_APPLICATION: String,
        /// Value of the object.
        CKA_VALUE: Vec<Byte>,
        /// DER-encoding of the object identifier indicating the data object type.
        CKA_OBJECT_ID: Vec<Byte>,
        /// Type of certificate.
        CKA_CERTIFICATE_TYPE: CertificateType,
        /// Certificate issuer name.
        CKA_ISSUER: Vec<Byte>,
        /// Serial number.
        CKA_SERIAL_NUMBER: Vec<Byte>,
        /// DER-encoding of the attribute certificate's issuer field. This is
        /// distinct from the `ISSUER` attribute contained in CKC_X_509
        /// certificates because the ASN.1 syntax and encoding are different.
        CKA_AC_ISSUER: Vec<Byte>,
        /// DER-encoding of the attribute certificate's subject field. This is
        /// distinct from the `SUBJECT`attribute contained in CKC_X_509
        /// certificates because the ASN.1 syntax and encoding are different.
        CKA_OWNER: Vec<Byte>,
        /// BER-encoding of a sequence of object identifier values corresponding
        /// to the attribute types contained in the certificate. When present,
        /// this field offers an opportunity for applications to search for a
        /// particular attribute certificate without fetching and parsing the
        /// certificate itself.
        CKA_ATTR_TYPES: Vec<Byte>,
        /// The object can be trusted for the application that it was created.
        CKA_TRUSTED: bool,
        /// Is used to indicate if a stored certificate is a user certificate
        /// for which the corresponding private key is available on the token
        /// ("token user"), a CA certificate ("authority"), or another end-entity
        /// certificate ("other entity"). This attribute may not be modified after
        /// an object is created.
        CKA_CERTIFICATE_CATEGORY: CertificateCategory,
        /// Associates a certificate with a Java MIDP security domain.
        CKA_JAVA_MIDP_SECURITY_DOMAIN: JavaMidpSecurityDomain,
        /// If not empty this attribute gives the URL where the object
        /// can be obtained.
        CKA_URL: String,
        /// Hash of the subject public key (default empty).
        /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
        CKA_HASH_OF_SUBJECT_PUBLIC_KEY: Vec<Byte>,
        /// Hash of the issuer public key (default empty).
        /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
        CKA_HASH_OF_ISSUER_PUBLIC_KEY: Vec<Byte>,
        /// Defines the mechanism used to calculate `HASH_OF_SUBJECT_PUBLIC_KEY`
        /// and `HASH_OF_ISSUER_PUBLIC_KEY`. If the attribute is not present then
        /// the type defaults to SHA-1.
        CKA_NAME_HASH_ALGORITHM: MechanismType,
        /// Object checksum.
        CKA_CHECK_VALUE: Vec<Byte>,
        /// Type of key.
        CKA_KEY_TYPE: KeyType,
        /// Object subject name.
        CKA_SUBJECT: Vec<Byte>,
        /// Key identifier.
        CKA_ID: Vec<Byte>,
        /// Identifies whether the object is sensitive.
        CKA_SENSITIVE: bool,
        /// Identifies whether the key supports encryption.
        CKA_ENCRYPT: bool,
        /// Identifies whether the key supports decryption.
        CKA_DECRYPT: bool,
        /// Identifies whether the key supports wrapping
        /// (i.e., can be used to wrap other keys).
        CKA_WRAP: bool,
        /// Identifies whether the key supports unwrapping
        /// (i.e., can be used to unwrap other keys).
        CKA_UNWRAP: bool,
        /// Identifies whether the key supports signatures.
        CKA_SIGN: bool,
        /// Identifies whether the key supports signatures where the data
        /// can be recovered from the signature.
        CKA_SIGN_RECOVER: bool,
        /// Identifies whether the key supports verification
        CKA_VERIFY: bool,
        /// Identifies whether the key supports verification where the data
        /// is recovered from the signature.
        CKA_VERIFY_RECOVER: bool,
        /// Identifies whether the key supports key derivation
        /// (i.e., if other keys can be derived from this one).
        CKA_DERIVE: bool,
        /// Start date for the object.
        CKA_START_DATE: Date,
        /// End date for the object.
        CKA_END_DATE: Date,
        /// Modulus n for an RSA private key.
        CKA_MODULUS: Vec<Byte>,
        /// Length in bits of the modulus of a key.
        CKA_MODULUS_BITS: Ulong,
        /// Public exponent e for an RSA private key.
        CKA_PUBLIC_EXPONENT: Vec<Byte>,
        /// Private exponent d for an RSA private key.
        CKA_PRIVATE_EXPONENT: Vec<Byte>,
        /// Prime p for an RSA private key.
        CKA_PRIME_1: Vec<Byte>,
        /// Prime q for an RSA private key.
        CKA_PRIME_2: Vec<Byte>,
        /// Private exponent d modulo p-1 for an RSA private key.
        CKA_EXPONENT_1: Vec<Byte>,
        /// Private exponent d modulo q-1 for an RSA private key.
        CKA_EXPONENT_2: Vec<Byte>,
        /// CRT coefficient q^{-1} mod p for an RSA private key.
        CKA_COEFFICIENT: Vec<Byte>,
        /// DER-encoding of the SubjectPublicKeyInfo for the public key.
        CKA_PUBLIC_KEY_INFO: Vec<Byte>,
        /// Prime number value of a key.
        CKA_PRIME: Vec<Byte>,
        /// Subprime number value of a key.
        CKA_SUBPRIME: Vec<Byte>,
        /// Base number value of a key.
        CKA_BASE: Vec<Byte>,
        /// Length in bits of the prime number of a key.
        CKA_PRIME_BITS: Ulong,
        /// Length in bits of the subprime number of a key.
        CKA_SUB_PRIME_BITS: Ulong,
        /// Length in bits of the object value.
        CKA_VALUE_BITS: Ulong,
        /// Object value lenght.
        CKA_VALUE_LEN: Ulong,
        /// Identifies whether the key is extractable and can be wrapped.
        CKA_EXTRACTABLE: bool,
        /// True only if object was either
        ///   * generated locally (i.e., on the token)
        ///     with a `generate_key` or generate_key_pair call
        ///   * created with a `copy_object` call as a copy of a key
        ///     which had its `LOCAL` attribute set to true
        CKA_LOCAL: bool,
        /// Indicates if the key has never had the `EXTRACTABLE` attribute set to true.
        CKA_NEVER_EXTRACTABLE: bool,
        /// Indicates if key has always had the `SENSITIVE` attribute set to true.
        CKA_ALWAYS_SENSITIVE: bool,
        /// Identifies the key generation mechanism used to generate the key material.
        CKA_KEY_GEN_MECHANISM: MechanismType,
        /// Identifies whether the object can be modified.
        CKA_MODIFIABLE: bool,
        /// Identifies whether the object can be copied.
        /// Can not be set to true once it is set to false.
        CKA_COPYABLE: bool,
        /// Identifies whether the object can be destroyed.
        CKA_DESTROYABLE: bool,
        /// Parameters that define an elliptic curve.
        CKA_EC_PARAMS: Vec<Byte>,
        /// Parameters that define an elliptic curve point.
        CKA_EC_POINT: Vec<Byte>,
        /// Can be used to force re-authentication (i.e. force the user
        /// to provide a PIN) for each use of a private key.
        CKA_ALWAYS_AUTHENTICATE: bool,
        /// Identifies whether the key can only be wrapped with a wrapping key
        /// CKA_TRUSTED,
        CKA_WRAP_WITH_TRUSTED: bool,
        /// For wrapping keys. The attribute template to match against any keys
        /// wrapped using this wrapping key. Keys that do not match cannot be
        /// wrapped. The number of attributes in the array is the ulValueLen
        /// component of the attribute divided by the size of `Attribute`.
        CKA_WRAP_TEMPLATE,
        /// For wrapping keys. The attribute template to apply to any keys
        /// unwrapped using this wrapping key. Any user supplied template
        /// is applied after this template as if the object has already been
        /// created. The number of attributes in the array is the ulValueLen
        /// component of the attribute divided by the size of `Attribute`.
        CKA_UNWRAP_TEMPLATE,
        /// For deriving keys. The attribute template to match against any keys
        /// derived using this derivation key. Any user supplied template is
        /// applied after this template as if the object has already been
        /// created. The number of attributes in the array is the ulValueLen
        /// component of the attribute divided by the size of `Attribute`.
        CKA_DERIVE_TEMPLATE,
        /// The format of the OTP value (e.g. decimal (default), hexadecimal, binary).
        CKA_OTP_FORMAT: Ulong,
        /// The length of the OTP value in digits or bytes, depending
        /// on `OTP_FORMAT`.
        CKA_OTP_LENGTH: Ulong,
        /// The time interval in seconds between OTP value refreshes.
        CKA_OTP_TIME_INTERVAL: Ulong,
        /// Identifies whether the token is capable of returning OTPs suitable for
        /// human consumption.
        CKA_OTP_USER_FRIENDLY_MODE: bool,
        /// Identifies challenge parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_CHALLENGE_REQUIREMENT: Ulong,
        /// Identifies time parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_TIME_REQUIREMENT: Ulong,
        /// Identifies counter parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_COUNTER_REQUIREMENT: Ulong,
        /// Identifies pin parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_PIN_REQUIREMENT: Ulong,
        /// Value of the associated internal counter.
        CKA_OTP_COUNTER: Vec<Byte>,
        /// Value of the associated internal UTC time in the form YYYYMMDDhhmmss.
        CKA_OTP_TIME: Vec<Byte>,
        /// Text string that identifies a user associated with the OTP key (may be
        /// used to enhance the user experience).
        CKA_OTP_USER_IDENTIFIER: Vec<Byte>,
        /// Text string that identifies a service that may validate OTPs
        /// generated by this key.
        CKA_OTP_SERVICE_IDENTIFIER: Vec<Byte>,
        /// Logotype image that identifies a service that may validate OTPs
        /// generated by this key.
        CKA_OTP_SERVICE_LOGO: Vec<Byte>,
        /// MIME type of the `OTP_SERVICE_LOGO` attribute value.
        CKA_OTP_SERVICE_LOGO_TYPE: Vec<Byte>,
        /// Parameters that define GOST R 34.10.
        CKA_GOSTR3410_PARAMS: Vec<Byte>,
        /// Parameters that define GOST R 34.11.
        CKA_GOSTR3411_PARAMS: Vec<Byte>,
        /// Parameters that define GOST 28147.
        CKA_GOST28147_PARAMS: Vec<Byte>,
        /// Identifies a hardware feature type of a device.
        CKA_HW_FEATURE_TYPE: HwFeatureType,
        /// The value of the counter will reset to a previously returned value if
        /// the token is initialized using C_InitToken.
        CKA_RESET_ON_INIT: bool,
        /// The value of the counter has been reset at least once at some point
        /// in time.
        CKA_HAS_RESET: bool,
        /// Screen resolution (in pixels) in X-axis (e.g. 1280).
        CKA_PIXEL_X: Ulong,
        /// Screen resolution (in pixels) in Y-axis (e.g. 1024).
        CKA_PIXEL_Y: Ulong,
        /// DPI, pixels per inch.
        CKA_RESOLUTION: Ulong,
        /// For character-oriented displays; number of character rows (e.g. 24).
        CKA_CHAR_ROWS: Ulong,
        /// For character-oriented displays: number of character columns (e.g. 80).
        /// If display is of proportional-font type, this is the width of the
        /// display in "em"-s (letter "M"), see CC/PP Struct.
        CKA_CHAR_COLUMNS: Ulong,
        /// Color support.
        CKA_COLOR: bool,
        /// The number of bits of color or grayscale information per pixel.
        CKA_BITS_PER_PIXEL: Ulong,
        /// String indicating supported character sets, as defined by IANA MIBenum
        /// sets (www.iana.org). Supported character sets are separated with ";".
        /// E.g. a token supporting iso-8859-1 and US-ASCII would set the attribute
        /// value to "4;3".
        CKA_CHAR_SETS: Vec<Byte>,
        /// String indicating supported content transfer encoding methods, as
        /// defined by IANA (www.iana.org). Supported methods are separated
        /// with ";". E.g. a token supporting 7bit, 8bit and base64 could set
        /// the attribute value to "7bit;8bit;base64".
        CKA_ENCODING_METHODS: Vec<Byte>,
        /// String indicating supported (presentable) MIME-types, as defined by
        /// IANA (www.iana.org). Supported types are separated with ";".
        /// E.g. a token supporting MIME types "a/b", "a/c" and "a/d" would set
        /// the attribute value to "a/b;a/c;a/d".
        CKA_MIME_TYPES: Vec<Byte>,
        /// The type of mechanism object.
        CKA_MECHANISM_TYPE: MechanismType,
        /// Attributes the token always will include in the set of CMS signed
        /// attributes.
        CKA_REQUIRED_CMS_ATTRIBUTES: Vec<Byte>,
        /// Attributes the token will include in the set of CMS signed attributes
        /// in the absence of any attributes specified by the application.
        CKA_DEFAULT_CMS_ATTRIBUTES: Vec<Byte>,
        /// Attributes the token may include in the set of CMS signed attributes
        /// upon request by the application.
        CKA_SUPPORTED_CMS_ATTRIBUTES: Vec<Byte>,
        /// A list of mechanisms allowed to be used with this key.
        CKA_ALLOWED_MECHANISMS: Vec<MechanismType>,
        CKA_PROFILE_ID,

        CKA_X2RATCHET_BAG,
        CKA_X2RATCHET_BAGSIZE,
        CKA_X2RATCHET_BOBS1STMSG,
        CKA_X2RATCHET_CKR,
        CKA_X2RATCHET_CKS,
        CKA_X2RATCHET_DHP,
        CKA_X2RATCHET_DHR,
        CKA_X2RATCHET_DHS,
        CKA_X2RATCHET_HKR,
        CKA_X2RATCHET_HKS,
        CKA_X2RATCHET_ISALICE,
        CKA_X2RATCHET_NHKR,
        CKA_X2RATCHET_NHKS,
        CKA_X2RATCHET_NR,
        CKA_X2RATCHET_NS,
        CKA_X2RATCHET_PNS,
        CKA_X2RATCHET_RK,

        // HSS
        CKA_HSS_LEVELS,
        CKA_HSS_LMS_TYPE,
        CKA_HSS_LMOTS_TYPE,
        CKA_HSS_LMS_TYPES,
        CKA_HSS_LMOTS_TYPES,
        CKA_HSS_KEYS_REMAINING,

        // new post-quantum (general)

        CKA_PARAMETER_SET,

        // validation objects

        CKA_OBJECT_VALIDATION_FLAGS,
        CKA_VALIDATION_TYPE,
        CKA_VALIDATION_VERSION,
        CKA_VALIDATION_LEVEL,
        CKA_VALIDATION_MODULE_ID,
        CKA_VALIDATION_FLAG,
        CKA_VALIDATION_AUTHORITY_TYPE,
        CKA_VALIDATION_COUNTRY,
        CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
        CKA_VALIDATION_CERTIFICATE_URI,
        CKA_VALIDATION_VENDOR_URI,
        CKA_VALIDATION_PROFILE,

        // KEM

        CKA_ENCAPSULATE_TEMPLATE,
        CKA_DECAPSULATE_TEMPLATE,

        // trust objects

        CKA_TRUST_SERVER_AUTH,
        CKA_TRUST_CLIENT_AUTH,
        CKA_TRUST_CODE_SIGNING,
        CKA_TRUST_EMAIL_PROTECTION,
        CKA_TRUST_IPSEC_IKE,
        CKA_TRUST_TIME_STAMPING,
        CKA_TRUST_OCSP_SIGNING,
        CKA_ENCAPSULATE,
        CKA_DECAPSULATE,
        CKA_HASH_OF_CERTIFICATE,

        // linking pubic and private keys
        CKA_PUBLIC_CRC64_VALUE,

        // new post-quantum (general)
        CKA_SEED,

        CKA_VENDOR_DEFINED,
    ]
);
