use std::convert::TryFrom;

use pkcs11_macros::{pkcs11_type, AttributePodType, TryFromCkAttribute};

use crate::error::{Error, Result};

use super::{general::*, MechanismType};

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

pkcs11_type!(
    /// Identifies an attribute type.
    AttributeType: CK_ATTRIBUTE_TYPE, naming = ScreamingSnakeCase;
    [
        /// Object class type.
        CKA_CLASS,
        /// Identifies whether the object is a token object or a session object.
        CKA_TOKEN,
        /// Identifies whether the ojbect is private.
        CKA_PRIVATE,
        /// Description of the object.
        CKA_LABEL,
        /// The unique identifier assigned to the object.
        CKA_UNIQUE_ID,
        /// Description of the application that manages the object.
        CKA_APPLICATION,
        /// Value of the object.
        CKA_VALUE,
        /// DER-encoding of the object identifier indicating the data object type.
        CKA_OBJECT_ID,
        /// Type of certificate.
        CKA_CERTIFICATE_TYPE,
        /// Certificate issuer name.
        CKA_ISSUER,
        /// Serial number.
        CKA_SERIAL_NUMBER,
        /// DER-encoding of the attribute certificate's issuer field. This is
        /// distinct from the `ISSUER` attribute contained in CKC_X_509
        /// certificates because the ASN.1 syntax and encoding are different.
        CKA_AC_ISSUER,
        /// DER-encoding of the attribute certificate's subject field. This is
        /// distinct from the `SUBJECT`attribute contained in CKC_X_509
        /// certificates because the ASN.1 syntax and encoding are different.
        CKA_OWNER,
        /// BER-encoding of a sequence of object identifier values corresponding
        /// to the attribute types contained in the certificate. When present,
        /// this field offers an opportunity for applications to search for a
        /// particular attribute certificate without fetching and parsing the
        /// certificate itself.
        CKA_ATTR_TYPES,
        /// The object can be trusted for the application that it was created.
        CKA_TRUSTED,
        /// Is used to indicate if a stored certificate is a user certificate
        /// for which the corresponding private key is available on the token
        /// ("token user"), a CA certificate ("authority"), or another end-entity
        /// certificate ("other entity"). This attribute may not be modified after
        /// an object is created.
        CKA_CERTIFICATE_CATEGORY,
        /// Associates a certificate with a Java MIDP security domain.
        CKA_JAVA_MIDP_SECURITY_DOMAIN,
        /// If not empty this attribute gives the URL where the object
        /// can be obtained.
        CKA_URL,
        /// Hash of the subject public key (default empty).
        /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
        CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
        /// Hash of the issuer public key (default empty).
        /// Hash algorithm is defined by `NAME_HASH_ALGORITHM`.
        CKA_HASH_OF_ISSUER_PUBLIC_KEY,
        /// Defines the mechanism used to calculate `HASH_OF_SUBJECT_PUBLIC_KEY`
        /// and `HASH_OF_ISSUER_PUBLIC_KEY`. If the attribute is not present then
        /// the type defaults to SHA-1.
        CKA_NAME_HASH_ALGORITHM,
        /// Object checksum.
        CKA_CHECK_VALUE,
        /// Type of key.
        CKA_KEY_TYPE,
        /// Object subject name.
        CKA_SUBJECT,
        /// Key identifier.
        CKA_ID,
        /// Identifies whether the object is sensitive.
        CKA_SENSITIVE,
        /// Identifies whether the key supports encryption.
        CKA_ENCRYPT,
        /// Identifies whether the key supports decryption.
        CKA_DECRYPT,
        /// Identifies whether the key supports wrapping
        /// (i.e., can be used to wrap other keys).
        CKA_WRAP,
        /// Identifies whether the key supports unwrapping
        /// (i.e., can be used to unwrap other keys).
        CKA_UNWRAP,
        /// Identifies whether the key supports signatures.
        CKA_SIGN,
        /// Identifies whether the key supports signatures where the data
        /// can be recovered from the signature.
        CKA_SIGN_RECOVER,
        /// Identifies whether the key supports verification
        CKA_VERIFY,
        /// Identifies whether the key supports verification where the data
        /// is recovered from the signature.
        CKA_VERIFY_RECOVER,
        /// Identifies whether the key supports key derivation
        /// (i.e., if other keys can be derived from this one).
        CKA_DERIVE,
        /// Start date for the object.
        CKA_START_DATE,
        /// End date for the object.
        CKA_END_DATE,
        /// Modulus n for an RSA private key.
        CKA_MODULUS,
        /// Length in bits of the modulus of a key.
        CKA_MODULUS_BITS,
        /// Public exponent e for an RSA private key.
        CKA_PUBLIC_EXPONENT,
        /// Private exponent d for an RSA private key.
        CKA_PRIVATE_EXPONENT,
        /// Prime p for an RSA private key.
        CKA_PRIME_1,
        /// Prime q for an RSA private key.
        CKA_PRIME_2,
        /// Private exponent d modulo p-1 for an RSA private key.
        CKA_EXPONENT_1,
        /// Private exponent d modulo q-1 for an RSA private key.
        CKA_EXPONENT_2,
        /// CRT coefficient q^{-1} mod p for an RSA private key.
        CKA_COEFFICIENT,
        /// DER-encoding of the SubjectPublicKeyInfo for the public key.
        CKA_PUBLIC_KEY_INFO,
        /// Prime number value of a key.
        CKA_PRIME,
        /// Subprime number value of a key.
        CKA_SUBPRIME,
        /// Base number value of a key.
        CKA_BASE,
        /// Length in bits of the prime number of a key.
        CKA_PRIME_BITS,
        /// Length in bits of the subprime number of a key.
        CKA_SUB_PRIME_BITS,
        /// Length in bits of the object value.
        CKA_VALUE_BITS,
        /// Object value lenght.
        CKA_VALUE_LEN,
        /// Identifies whether the key is extractable and can be wrapped.
        CKA_EXTRACTABLE,
        /// True only if object was either
        ///   * generated locally (i.e., on the token)
        ///     with a `generate_key` or generate_key_pair call
        ///   * created with a `copy_object` call as a copy of a key
        ///     which had its `LOCAL` attribute set to true
        CKA_LOCAL,
        /// Indicates if the key has never had the `EXTRACTABLE` attribute set to true.
        CKA_NEVER_EXTRACTABLE,
        /// Indicates if key has always had the `SENSITIVE` attribute set to true.
        CKA_ALWAYS_SENSITIVE,
        /// Identifies the key generation mechanism used to generate the key material.
        CKA_KEY_GEN_MECHANISM,
        /// Identifies whether the object can be modified.
        CKA_MODIFIABLE,
        /// Identifies whether the object can be copied.
        /// Can not be set to true once it is set to false.
        CKA_COPYABLE,
        /// Identifies whether the object can be destroyed.
        CKA_DESTROYABLE,
        /// Parameters that define an elliptic curve.
        CKA_EC_PARAMS,
        /// Parameters that define an elliptic curve point.
        CKA_EC_POINT,
        /// Can be used to force re-authentication (i.e. force the user
        /// to provide a PIN) for each use of a private key.
        CKA_ALWAYS_AUTHENTICATE,
        /// Identifies whether the key can only be wrapped with a wrapping key
        /// CKA_TRUSTED,
        CKA_WRAP_WITH_TRUSTED,
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
        CKA_OTP_FORMAT,
        /// The length of the OTP value in digits or bytes, depending
        /// on `OTP_FORMAT`.
        CKA_OTP_LENGTH,
        /// The time interval in seconds between OTP value refreshes.
        CKA_OTP_TIME_INTERVAL,
        /// Identifies whether the token is capable of returning OTPs suitable for
        /// human consumption.
        CKA_OTP_USER_FRIENDLY_MODE,
        /// Identifies challenge parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_CHALLENGE_REQUIREMENT,
        /// Identifies time parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_TIME_REQUIREMENT,
        /// Identifies counter parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_COUNTER_REQUIREMENT,
        /// Identifies pin parameter requirements when generating or verifying
        /// OTP values.
        CKA_OTP_PIN_REQUIREMENT,
        /// Value of the associated internal counter.
        CKA_OTP_COUNTER,
        /// Value of the associated internal UTC time in the form YYYYMMDDhhmmss.
        CKA_OTP_TIME,
        /// Text string that identifies a user associated with the OTP key (may be
        /// used to enhance the user experience).
        CKA_OTP_USER_IDENTIFIER,
        /// Text string that identifies a service that may validate OTPs
        /// generated by this key.
        CKA_OTP_SERVICE_IDENTIFIER,
        /// Logotype image that identifies a service that may validate OTPs
        /// generated by this key.
        CKA_OTP_SERVICE_LOGO,
        /// MIME type of the `OTP_SERVICE_LOGO` attribute value.
        CKA_OTP_SERVICE_LOGO_TYPE,
        /// Parameters that define GOST R 34.10.
        CKA_GOSTR3410_PARAMS,
        /// Parameters that define GOST R 34.11.
        CKA_GOSTR3411_PARAMS,
        /// Parameters that define GOST 28147.
        CKA_GOST28147_PARAMS,
        /// Identifies a hardware feature type of a device.
        CKA_HW_FEATURE_TYPE,
        /// The value of the counter will reset to a previously returned value if
        /// the token is initialized using C_InitToken.
        CKA_RESET_ON_INIT,
        /// The value of the counter has been reset at least once at some point
        /// in time.
        CKA_HAS_RESET,
        /// Screen resolution (in pixels) in X-axis (e.g. 1280).
        CKA_PIXEL_X,
        /// Screen resolution (in pixels) in Y-axis (e.g. 1024).
        CKA_PIXEL_Y,
        /// DPI, pixels per inch.
        CKA_RESOLUTION,
        /// For character-oriented displays; number of character rows (e.g. 24).
        CKA_CHAR_ROWS,
        /// For character-oriented displays: number of character columns (e.g. 80).
        /// If display is of proportional-font type, this is the width of the
        /// display in "em"-s (letter "M"), see CC/PP Struct.
        CKA_CHAR_COLUMNS,
        /// Color support.
        CKA_COLOR,
        /// The number of bits of color or grayscale information per pixel.
        CKA_BITS_PER_PIXEL,
        /// String indicating supported character sets, as defined by IANA MIBenum
        /// sets (www.iana.org). Supported character sets are separated with ";".
        /// E.g. a token supporting iso-8859-1 and US-ASCII would set the attribute
        /// value to "4;3".
        CKA_CHAR_SETS,
        /// String indicating supported content transfer encoding methods, as
        /// defined by IANA (www.iana.org). Supported methods are separated
        /// with ";". E.g. a token supporting 7bit, 8bit and base64 could set
        /// the attribute value to "7bit;8bit;base64".
        CKA_ENCODING_METHODS,
        /// String indicating supported (presentable) MIME-types, as defined by
        /// IANA (www.iana.org). Supported types are separated with ";".
        /// E.g. a token supporting MIME types "a/b", "a/c" and "a/d" would set
        /// the attribute value to "a/b;a/c;a/d".
        CKA_MIME_TYPES,
        /// The type of mechanism object.
        CKA_MECHANISM_TYPE,
        /// Attributes the token always will include in the set of CMS signed
        /// attributes.
        CKA_REQUIRED_CMS_ATTRIBUTES,
        /// Attributes the token will include in the set of CMS signed attributes
        /// in the absence of any attributes specified by the application.
        CKA_DEFAULT_CMS_ATTRIBUTES,
        /// Attributes the token may include in the set of CMS signed attributes
        /// upon request by the application.
        CKA_SUPPORTED_CMS_ATTRIBUTES,
        /// A list of mechanisms allowed to be used with this key.
        CKA_ALLOWED_MECHANISMS,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorDefinedAttribute {
    pub attr_type: AttributeType,
    pub value: Vec<Byte>,
}

// TODO: add missing attributes
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
    Gost28147(Vec<Byte>),
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
    VendorDefined(VendorDefinedAttribute),
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
            Attribute::Gost28147(_) => AttributeType::GOST28147_PARAMS,
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
            Attribute::VendorDefined(v) => v.attr_type,
        }
    }

    fn inner_value(&self) -> &dyn AttributeValue {
        match self {
            // bool
            Attribute::Token(v)
            | Attribute::Private(v)
            | Attribute::Trusted(v)
            | Attribute::Sensitive(v)
            | Attribute::Encrypt(v)
            | Attribute::Decrypt(v)
            | Attribute::Wrap(v)
            | Attribute::Unwrap(v)
            | Attribute::Sign(v)
            | Attribute::SignRecover(v)
            | Attribute::Verify(v)
            | Attribute::VerifyRecover(v)
            | Attribute::Derive(v)
            | Attribute::Extractable(v)
            | Attribute::Local(v)
            | Attribute::NeverExtractable(v)
            | Attribute::AlwaysSensitive(v)
            | Attribute::Modifiable(v)
            | Attribute::CopyAble(v)
            | Attribute::DestroyAble(v)
            | Attribute::AlwaysAuthenticate(v)
            | Attribute::WrapWithTrusted(v)
            | Attribute::OtpUserFriendlyMode(v)
            | Attribute::ResetOnInit(v)
            | Attribute::HasReset(v)
            | Attribute::Color(v) => v,

            // Ulong
            Attribute::ModulusBits(v)
            | Attribute::PrimeBits(v)
            | Attribute::SubPrimeBits(v)
            | Attribute::ValueBits(v)
            | Attribute::ValueLen(v)
            | Attribute::OtpFormat(v)
            | Attribute::OtpLength(v)
            | Attribute::OtpTimeInterval(v)
            | Attribute::OtpChallengeRequirement(v)
            | Attribute::OtpTimeRequirement(v)
            | Attribute::OtpCounterRequirement(v)
            | Attribute::OtpPinRequirement(v)
            | Attribute::PixelX(v)
            | Attribute::PixelY(v)
            | Attribute::Resolution(v)
            | Attribute::CharRows(v)
            | Attribute::CharColumns(v)
            | Attribute::BitsPerPixel(v) => v,

            // String
            Attribute::Label(v) | Attribute::Application(v) | Attribute::Url(v) => v,

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
            | Attribute::Gost28147(v)
            | Attribute::CharSets(v)
            | Attribute::EncodingMethods(v)
            | Attribute::MimeTypes(v)
            | Attribute::RequiredCmsAttributes(v)
            | Attribute::DefaultCmsAttributes(v)
            | Attribute::SupportedCmsAttributes(v) => v,

            // Date
            Attribute::StartDate(v) | Attribute::EndDate(v) => v,

            // MechanismType
            Attribute::NameHashAlgorithm(v)
            | Attribute::KeyGenMechanism(v)
            | Attribute::MechanismType(v) => v,

            //
            Attribute::Class(v) => v,
            Attribute::CertificateType(v) => v,
            Attribute::CertificateCategory(v) => v,
            Attribute::JavaMidpSecurityDomain(v) => v,
            Attribute::KeyType(v) => v,
            Attribute::HwFeatureType(v) => v,

            //
            Attribute::AllowedMechanisms(v) => v, // Attribute::WrapTemplate(attr)
            // | Attribute::UnwrapTemplate(attr) =>

            // Vendor defined
            Attribute::VendorDefined(v) => &v.value,
        }
    }

    fn ptr(&self) -> CK_VOID_PTR {
        self.inner_value().as_ck_ptr()
    }

    fn len(&self) -> Ulong {
        self.inner_value().len()
    }
}

pub trait TryFromCkAttribute: Sized {
    fn try_from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Self>;
}

impl From<&CK_ATTRIBUTE> for bool {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        if ck_attribute.pValue.is_null() {
            return false;
        }
        let b: CK_BBOOL =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_BBOOL) };
        !matches!(b, 0)
    }
}

impl From<&CK_ATTRIBUTE> for Ulong {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        if ck_attribute.pValue.is_null() {
            return 0;
        }
        unsafe { std::ptr::read(ck_attribute.pValue as *const CK_ULONG) }
    }
}

impl From<&CK_ATTRIBUTE> for Date {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        let value: CK_DATE =
            unsafe { std::ptr::read(ck_attribute.pValue as *const CK_DATE) };

        value
    }
}

impl From<&CK_ATTRIBUTE> for String {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return String::new();
        }
        let value: &[u8] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const u8,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };
        String::from_utf8_lossy(value).into_owned()
    }
}

impl From<&CK_ATTRIBUTE> for Vec<Byte> {
    fn from(ck_attribute: &CK_ATTRIBUTE) -> Self {
        if ck_attribute.pValue.is_null() || ck_attribute.ulValueLen == 0 {
            return Vec::new();
        }
        let value: &[Byte] = unsafe {
            std::slice::from_raw_parts(
                ck_attribute.pValue as *const Byte,
                ck_attribute.ulValueLen as CK_ULONG as usize,
            )
        };
        value.to_vec()
    }
}

macro_rules! impl_from_ck_attr {
    ($($t:ty),* $(,)?) => {
        $(impl TryFromCkAttribute for $t {
            fn try_from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Self> {
                Ok(<$t>::from(attr))
            }
        })*
    };
}

impl_from_ck_attr!(bool, Ulong, Date, String, Vec<Byte>);

impl TryFrom<&CK_ATTRIBUTE> for Vec<MechanismType> {
    type Error = Error;

    fn try_from(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
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

impl TryFrom<&CK_ATTRIBUTE> for VendorDefinedAttribute {
    type Error = Error;

    fn try_from(ck_attribute: &CK_ATTRIBUTE) -> Result<Self> {
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

macro_rules! impl_try_from_ck_attr {
    ($($t:ty),* $(,)?) => {
        $(impl TryFromCkAttribute for $t {
            fn try_from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Self> {
                <$t>::try_from(attr)
            }
        })*
    };
}

impl_try_from_ck_attr!(Vec<MechanismType>, VendorDefinedAttribute);

impl From<&Attribute> for CK_ATTRIBUTE {
    fn from(attribute: &Attribute) -> Self {
        Self {
            attrType: attribute.attribute_type().into(),
            pValue: attribute.ptr(),
            ulValueLen: attribute.len(),
        }
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
            AttributeType::CLASS => Ok(Attribute::Class(ObjectClass::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::TOKEN => {
                Ok(Attribute::Token(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::PRIVATE => {
                Ok(Attribute::Private(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::LABEL => {
                Ok(Attribute::Label(String::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::APPLICATION => Ok(Attribute::Application(
                String::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::VALUE => Ok(Attribute::Value(Vec::<Byte>::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::OBJECT_ID => Ok(Attribute::ObjectId(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::CERTIFICATE_TYPE => Ok(Attribute::CertificateType(
                CertificateType::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::ISSUER => Ok(Attribute::Issuer(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::SERIAL_NUMBER => Ok(Attribute::SerialNumber(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::AC_ISSUER => Ok(Attribute::AcIssuer(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OWNER => Ok(Attribute::Owner(Vec::<Byte>::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::ATTR_TYPES => Ok(Attribute::AttrTypes(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::TRUSTED => {
                Ok(Attribute::Trusted(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::CERTIFICATE_CATEGORY => Ok(Attribute::CertificateCategory(
                CertificateCategory::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::JAVA_MIDP_SECURITY_DOMAIN => {
                Ok(Attribute::JavaMidpSecurityDomain(
                    JavaMidpSecurityDomain::try_from_ck_attr(&ck_attribute)?,
                ))
            }
            AttributeType::URL => {
                Ok(Attribute::Url(String::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::HASH_OF_SUBJECT_PUBLIC_KEY => {
                Ok(Attribute::HashOfSubjectPublicKey(
                    Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
                ))
            }
            AttributeType::HASH_OF_ISSUER_PUBLIC_KEY => {
                Ok(Attribute::HashOfIssuerPublicKey(
                    Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
                ))
            }
            AttributeType::NAME_HASH_ALGORITHM => Ok(Attribute::NameHashAlgorithm(
                MechanismType::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::CHECK_VALUE => Ok(Attribute::CheckValue(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::KEY_TYPE => Ok(Attribute::KeyType(KeyType::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::SUBJECT => Ok(Attribute::Subject(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::ID => {
                Ok(Attribute::Id(Vec::<Byte>::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::SENSITIVE => {
                Ok(Attribute::Sensitive(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::ENCRYPT => {
                Ok(Attribute::Encrypt(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::DECRYPT => {
                Ok(Attribute::Decrypt(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::WRAP => {
                Ok(Attribute::Wrap(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::UNWRAP => {
                Ok(Attribute::Unwrap(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::SIGN => {
                Ok(Attribute::Sign(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::SIGN_RECOVER => Ok(Attribute::SignRecover(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::VERIFY => {
                Ok(Attribute::Verify(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::VERIFY_RECOVER => Ok(Attribute::VerifyRecover(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::DERIVE => {
                Ok(Attribute::Derive(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::START_DATE => {
                Ok(Attribute::StartDate(Date::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::END_DATE => {
                Ok(Attribute::EndDate(Date::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::MODULUS => Ok(Attribute::Modulus(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::MODULUS_BITS => {
                Ok(Attribute::ModulusBits(Ulong::from(&ck_attribute)))
            }
            AttributeType::PUBLIC_EXPONENT => Ok(Attribute::PublicExponent(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::PRIVATE_EXPONENT => Ok(Attribute::PrivateExponent(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::PRIME_1 => Ok(Attribute::Prime1(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::PRIME_2 => Ok(Attribute::Prime2(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::EXPONENT_1 => Ok(Attribute::Exponent1(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::EXPONENT_2 => Ok(Attribute::Exponent2(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::COEFFICIENT => Ok(Attribute::Coefficient(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::PUBLIC_KEY_INFO => Ok(Attribute::PublicKeyInfo(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::PRIME => Ok(Attribute::Prime(Vec::<Byte>::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::SUBPRIME => Ok(Attribute::SubPrime(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::BASE => Ok(Attribute::Base(Vec::<Byte>::try_from_ck_attr(
                &ck_attribute,
            )?)),
            AttributeType::PRIME_BITS => Ok(Attribute::PrimeBits(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::SUB_PRIME_BITS => Ok(Attribute::SubPrimeBits(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::VALUE_BITS => Ok(Attribute::ValueBits(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::VALUE_LEN => {
                Ok(Attribute::ValueLen(Ulong::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::EXTRACTABLE => Ok(Attribute::Extractable(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::LOCAL => {
                Ok(Attribute::Local(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::NEVER_EXTRACTABLE => Ok(Attribute::NeverExtractable(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::ALWAYS_SENSITIVE => Ok(Attribute::AlwaysSensitive(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::KEY_GEN_MECHANISM => Ok(Attribute::KeyGenMechanism(
                MechanismType::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::MODIFIABLE => Ok(Attribute::Modifiable(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::COPYABLE => {
                Ok(Attribute::CopyAble(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::DESTROYABLE => Ok(Attribute::DestroyAble(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::EC_PARAMS => Ok(Attribute::EcParams(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::EC_POINT => Ok(Attribute::EcPoint(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::ALWAYS_AUTHENTICATE => Ok(Attribute::AlwaysAuthenticate(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::WRAP_WITH_TRUSTED => Ok(Attribute::WrapWithTrusted(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            // AttributeType::WRAP_TEMPLATE => Ok(Attribute::WrapTemplate(get_())),
            // AttributeType::UNWRAP_TEMPLATE => Ok(Attribute::UnwrapTemplate(get_())),
            AttributeType::OTP_FORMAT => Ok(Attribute::OtpFormat(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_LENGTH => Ok(Attribute::OtpLength(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_TIME_INTERVAL => Ok(Attribute::OtpTimeInterval(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_USER_FRIENDLY_MODE => Ok(Attribute::OtpUserFriendlyMode(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_CHALLENGE_REQUIREMENT => {
                Ok(Attribute::OtpChallengeRequirement(Ulong::try_from_ck_attr(
                    &ck_attribute,
                )?))
            }
            AttributeType::OTP_TIME_REQUIREMENT => Ok(Attribute::OtpTimeRequirement(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_COUNTER_REQUIREMENT => Ok(
                Attribute::OtpCounterRequirement(Ulong::try_from_ck_attr(&ck_attribute)?),
            ),
            AttributeType::OTP_PIN_REQUIREMENT => Ok(Attribute::OtpPinRequirement(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_COUNTER => Ok(Attribute::OtpCounter(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_TIME => Ok(Attribute::OtpTime(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_USER_IDENTIFIER => Ok(Attribute::OtpUserIdentifier(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_SERVICE_IDENTIFIER => Ok(Attribute::OtpServiceIdentifier(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_SERVICE_LOGO => Ok(Attribute::OtpServiceLogo(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::OTP_SERVICE_LOGO_TYPE => Ok(Attribute::OtpServiceLogoType(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::GOSTR3410_PARAMS => Ok(Attribute::GostR3410(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::GOSTR3411_PARAMS => Ok(Attribute::GostR3411(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::GOST28147_PARAMS => Ok(Attribute::Gost28147(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::HW_FEATURE_TYPE => Ok(Attribute::HwFeatureType(
                HwFeatureType::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::RESET_ON_INIT => Ok(Attribute::ResetOnInit(
                bool::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::HAS_RESET => {
                Ok(Attribute::HasReset(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::PIXEL_X => {
                Ok(Attribute::PixelX(Ulong::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::PIXEL_Y => {
                Ok(Attribute::PixelY(Ulong::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::RESOLUTION => Ok(Attribute::Resolution(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::CHAR_ROWS => {
                Ok(Attribute::CharRows(Ulong::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::CHAR_COLUMNS => Ok(Attribute::CharColumns(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::COLOR => {
                Ok(Attribute::Color(bool::try_from_ck_attr(&ck_attribute)?))
            }
            AttributeType::BITS_PER_PIXEL => Ok(Attribute::BitsPerPixel(
                Ulong::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::CHAR_SETS => Ok(Attribute::CharSets(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::ENCODING_METHODS => Ok(Attribute::EncodingMethods(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::MIME_TYPES => Ok(Attribute::MimeTypes(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::MECHANISM_TYPE => Ok(Attribute::MechanismType(
                MechanismType::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::REQUIRED_CMS_ATTRIBUTES => {
                Ok(Attribute::RequiredCmsAttributes(
                    Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
                ))
            }
            AttributeType::DEFAULT_CMS_ATTRIBUTES => Ok(Attribute::DefaultCmsAttributes(
                Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
            )),
            AttributeType::SUPPORTED_CMS_ATTRIBUTES => {
                Ok(Attribute::SupportedCmsAttributes(
                    Vec::<Byte>::try_from_ck_attr(&ck_attribute)?,
                ))
            }
            AttributeType::ALLOWED_MECHANISMS => Ok(Attribute::AllowedMechanisms(
                Vec::<MechanismType>::try_from_ck_attr(&ck_attribute)?,
            )),
            _ => Ok(Attribute::VendorDefined(
                VendorDefinedAttribute::try_from_ck_attr(&ck_attribute)?,
            )),
        }
    }
}
