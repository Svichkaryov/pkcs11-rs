use proc_macro::TokenStream;

mod naming;
mod types;

#[proc_macro_derive(AttributePodType)]
pub fn derive_attribute_value(input: TokenStream) -> TokenStream {
    types::derive_attribute_pod_type_impl(input)
}

#[proc_macro_derive(TryFromCkAttribute)]
pub fn derive_try_from_ck_attribute_impl(input: TokenStream) -> TokenStream {
    types::derive_try_from_ck_attribute_impl(input)
}

/// Generate rust newtype and traits for a PKCS#11 type based on a list of
/// C-style constants.
///
/// /// # Example:
///
/// ```rust
/// pkcs11_type!(
///     /// PKCS#11 object classes.
///     ObjectClass: u64, naming = ScreamingSnakeCase;
///     [
///         /// Certificate objects hold public-key or attribute certificates.
///         CKO_CERTIFICATE,
///
///         /// Public key object.
///         CKO_PUBLIC_KEY,
///
///         /// Private key object.
///         CKO_PRIVATE_KEY,
///     ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_type(input: TokenStream) -> TokenStream {
    types::pkcs11_type_impl(input)
}

/// Generate rust newtype and traits for a PKCS#11 attribute type based on a
/// list of C-style constants with type.
///
/// /// # Example:
///
/// ```rust
/// pkcs11_attribute_type!(
///     /// Identifies an attribute.
///     ///
///     /// An array of Attribute is called a "template" and is used for creating,
///     /// manipulating and searching for objects.
///     Attribute, naming = UpperCamelCase;
///     [
///         /// Object class type.
///         CKA_CLASS: ObjectClass,
///         /// Identifies whether the object is a token object or a session object.
///         CKA_TOKEN: bool,
///         /// Identifies whether the ojbect is private.
///         CKA_PRIVATE: bool,
///         /// Description of the object.
///         CKA_LABEL: String,
///
///         CKA_VENDOR_DEFINED,
///     ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_attribute_type(input: TokenStream) -> TokenStream {
    types::pkcs11_attribute_type_impl(input)
}

/// Generate rust newtype and traits for a PKCS#11 mechanism type based on a
/// list of C-style constants with parameter.
///
/// /// # Example:
///
/// ```rust
/// pkcs11_mechanism_type!(
///     /// Specifies a particular mechanism and any parameters it requires.
///     #[non_exhaustive]
///     Mechanism, naming = UpperCamelCase;
///     [
///         CKM_DH_PKCS_KEY_PAIR_GEN,
///         CKM_DH_PKCS_DERIVE: Vec<Byte>,
///
///         CKM_SHA224_RSA_PKCS,
///         CKM_SHA224_RSA_PKCS_PSS: RsaPkcsPssParams,
///
///         CKM_AES_KEY_GEN,
///         CKM_AES_ECB,
///         CKM_AES_CBC: [u8; 16],
///         CKM_AES_MAC,
///         CKM_AES_MAC_GENERAL: Ulong,
///         CKM_AES_CBC_PAD: [u8; 16],
///
///         CKM_VENDOR_DEFINED,
///     ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_mechanism_type(input: TokenStream) -> TokenStream {
    types::pkcs11_mechanism_type_impl(input)
}
