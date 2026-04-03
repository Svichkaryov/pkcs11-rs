use proc_macro::TokenStream;

mod attributes;
mod types;

#[proc_macro_derive(AttributePodType)]
pub fn derive_attribute_value(input: TokenStream) -> TokenStream {
    attributes::derive_attribute_pod_type_impl(input)
}

#[proc_macro_derive(TryFromCkAttribute)]
pub fn derive_try_from_ck_attribute_impl(input: TokenStream) -> TokenStream {
    attributes::derive_try_from_ck_attribute_impl(input)
}

/// Generate rust newtype and traits for a PKCS#11 type based on a list of
/// C-style constants.
///
/// /// # Example:
///
/// ```rust
/// pkcs11_type!(
///    /// PKCS#11 object classes.
///    ObjectClass: u64, naming = ScreamingSnakeCase;
///    [
///        /// Certificate objects hold public-key or attribute certificates.
///        CKO_CERTIFICATE,
///
///        /// Public key object.
///        CKO_PUBLIC_KEY,
///
///        /// Private key object.
///        CKO_PRIVATE_KEY,
///    ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_type(input: TokenStream) -> TokenStream {
    types::pkcs11_type_impl(input)
}
