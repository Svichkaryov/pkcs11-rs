use proc_macro::TokenStream;

mod naming;
mod types;

/// Derives the `CkPodType` marker trait for a type.
///
/// The type must have a valid `#[repr(...)]` attribute:
/// `C`, `transparent` or any primitive integer repr.
///
/// # Example
///
/// ```ignore
/// #[derive(AttributePodType)]
/// #[repr(C)]
/// pub struct ObjectClass(CK_OBJECT_CLASS);
/// ```
#[proc_macro_derive(AttributePodType)]
pub fn derive_attribute_value(input: TokenStream) -> TokenStream {
    types::derive_attribute_pod_type_impl(input)
}

/// Derives the `TryFromCkAttribute` impl for a type, allowing it to be
/// deserialized from a raw `CK_ATTRIBUTE`.
///
/// The type must be a struct with exactly one unnamed field, where the field
/// type implements `TryFromCkAttribute`. It must also have a valid
/// `#[repr(...)]` attribute: `C`, `transparent` or any primitive integer repr.
///
/// # Example
///
/// ```ignore
/// #[derive(TryFromCkAttribute)]
/// #[repr(transparent)]
/// pub struct ObjectClass(CK_OBJECT_CLASS);
/// ```
#[proc_macro_derive(TryFromCkAttribute)]
pub fn derive_try_from_ck_attribute_impl(input: TokenStream) -> TokenStream {
    types::derive_try_from_ck_attribute_impl(input)
}

/// Generate rust newtype and traits for a PKCS#11 type based on a list of
/// C-style constants.
///
/// # Example:
///
/// ```ignore
/// use pkcs11_macros::pkcs11_type;
///
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
/// # Example:
///
/// ```ignore
/// use pkcs11_macros::pkcs11_type;
///
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
/// # Example:
///
/// ```ignore
/// use pkcs11_macros::pkcs11_mechanism_type;
///
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

/// Generate rust newtype and traits for a PKCS#11 return value type based on
/// a list of C-style constants.
///
/// # Example:
///
/// ```ignore
/// use pkcs11_macros::pkcs11_rv_type;
///
/// pkcs11_rv_type!(
///     /// Cryptoki function return values.
///     #[derive(Debug, Copy, Clone, PartialEq, Eq)]
///     CryptokiRetVal, naming = UpperCamelCase;
///     [
///         /// The function executed successfully.
///         /// Technically, [`Ok`] is not quite a "universal" return value;
///         /// in particular, the legacy functions C_GetFunctionStatus and
///         /// C_CancelFunction (see [`Section 5.20`]) cannot return [`Ok`].
///         ///
///         /// [`Ok`]: Self::Ok
///         /// [`Section 5.20`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693242
///         CKR_OK,
///
///         /// Some horrible, unrecoverable error has occurred. In the worst case,
///         /// it is possible that the function only partially succeeded, and that
///         /// the computer and/or token is in an inconsistent state.
///         CKR_GENERAL_ERROR,
///
///         /// The computer that the Cryptoki library is running on has insufficient
///         /// memory to perform the requested function.
///         CKR_HOST_MEMORY,
///
///         /// The requested function could not be performed, but detailed information
///         /// about why not is not available in this error return. If the failed
///         /// function uses a session, it is possible that the [`SessionInfo`]
///         /// structure that can be obtained by calling [`get_session_info`] will
///         /// hold useful information about what happened via [`device_error`]
///         /// function. In any event, although the function call failed, the
///         /// situation is not necessarily totally hopeless, as it is likely to be
///         /// when [`GeneralError`] is returned. Depending on what the root cause
///         /// of the error actually was, it is possible that an attempt to make the
///         /// exact same function call again would succeed.
///         ///
///         /// [`SessionInfo`]: crate::types::SessionInfo
///         /// [`get_session_info`]: crate::session::Session::get_session_info
///         /// [`device_error`]: crate::types::SessionInfo::device_error
///         ///[`GeneralError`]: Self::GeneralError
///         CKR_FUNCTION_FAILED,
///
///         /// This value are permanently reserved for token vendors.
///         /// For interoperability, vendors should register their return values
///         /// through the PKCS process.
///         CKR_VENDOR_DEFINED: CK_RV,
///     ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_rv_type(input: TokenStream) -> TokenStream {
    types::pkcs11_rv_type_impl(input)
}
