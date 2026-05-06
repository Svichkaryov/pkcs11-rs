use pkcs11_sys::*;

use crate::{
    error::{CryptokiRetVal, Result},
    module::invoke_pkcs11,
    types::{Attribute, Mechanism, ObjectHandle},
};

use super::Session;

impl Session {
    /// Generates a secret key or set of domain parameters, creating a new
    /// object.
    ///
    /// If the generation `mechanism` is for domain parameter generation, the
    /// [`Class`] attribute will have the value [`DOMAIN_PARAMETERS`];
    /// otherwise, it will have the value [`SECRET_KEY`].
    ///
    /// Since the type of key or domain parameters to be generated is implicit
    /// in the generation `mechanism`, the `template` does not need to supply a
    /// key type. If it does supply a key type which is inconsistent with the
    /// generation `mechanism`, it fails and returns the error code
    /// [`TemplateInconsistent`]. The [`Class`] attribute is treated similarly.
    ///
    /// If a call to it cannot support the precise `template` supplied to it,
    /// it will fail and return without creating an object.
    ///
    /// The object created by a successful call to it will have its [`Local`]
    /// attribute set to `true`. In addition, the object created will have a
    /// value for [`UniqueId`] generated and assigned (See [`Section 4.4.1`]).
    ///
    /// [`Class`]: crate::types::Attribute::Class
    /// [`DOMAIN_PARAMETERS`]: crate::types::ObjectClass::DOMAIN_PARAMETERS
    /// [`SECRET_KEY`]: crate::types::ObjectClass::SECRET_KEY
    /// [`TemplateInconsistent`]: crate::error::CryptokiRetVal::TemplateInconsistent
    /// [`Local`]: crate::types::Attribute::Local
    /// [`UniqueId`]: crate::types::Attribute::UniqueId
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn generate_key(
        &self,
        mechanism: &Mechanism,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateKey,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle.into())
    }

    /// Generates a public/private key pair, creating new key objects.
    ///
    /// Since the types of keys to be generated are implicit in the key pair
    /// generation `mechanism`, the templates do not need to supply key types.
    /// If one of the templates does supply a key type which is inconsistent
    /// with the key generation `mechanism`, it fails and returns the error
    /// code [`TemplateInconsistent`](CryptokiRetVal::TemplateInconsistent).
    /// The [`Class`](Attribute::Class) attribute is treated similarly.
    ///
    /// If a call to it cannot support the precise templates supplied to it,
    /// it will fail and return without creating any key objects.
    ///
    /// A call to it will never create just one key and return. A call can
    /// fail, and create no keys; or it can succeed, and create a matching
    /// public/private key pair.
    ///
    /// The key objects created by a successful call to it will have their
    /// [`Local`](Attribute::Local) attributes set to `true`. In addition,
    /// the key objects created will both have values for
    /// [`UniqueId`](Attribute::UniqueId) generated and assigned
    /// (See [`Section 4.4.1`]).
    ///
    /// Note carefully the order of the arguments to it. The last two arguments
    /// do not have the same order as they did in the original Cryptoki
    /// Version 1.0 document. The order of these two arguments has caused some
    /// unfortunate confusion.
    ///
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn generate_key_pair(
        &self,
        mechanism: &Mechanism,
        public_key_template: &[Attribute],
        private_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let pub_key_tmpl: Vec<CK_ATTRIBUTE> =
            public_key_template.iter().map(|attr| attr.into()).collect();
        let pr_key_tmpl: Vec<CK_ATTRIBUTE> = private_key_template
            .iter()
            .map(|attr| attr.into())
            .collect();

        let mut pub_key_obj_handle: CK_OBJECT_HANDLE = 0;
        let mut pr_key_obj_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateKeyPair,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            pub_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            pub_key_tmpl.len() as CK_ULONG,
            pr_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            pr_key_tmpl.len() as CK_ULONG,
            &mut pub_key_obj_handle,
            &mut pr_key_obj_handle
        ))
        .into_result()?;

        Ok((pub_key_obj_handle.into(), pr_key_obj_handle.into()))
    }

    /// Wraps (i.e., encrypts) a private or secret `key`.
    ///
    /// The [`Wrap`](Attribute::Wrap) attribute of the `wrapping_key`, which
    /// indicates whether the key supports wrapping, MUST be `true`. The
    /// [`Extractable`](Attribute::Extractable) attribute of the `key` to be
    /// wrapped MUST also be `true`.
    ///
    /// If the `key` to be wrapped cannot be wrapped for some token-specific
    /// reason, despite it having its [`Extractable`](Attribute::Extractable)
    /// attribute set to `true`, then it fails with error code
    /// [`KeyNotWrappable`](CryptokiRetVal::KeyNotWrappable). If it cannot be
    /// wrapped with the specified `wrapping_key` and `mechanism` solely
    /// because of its length, then it fails with error code
    /// [`KeySizeRange`](CryptokiRetVal::KeySizeRange).
    ///
    /// It can be used in the following situations:
    ///   - To wrap any secret key with a public key that supports encryption
    ///     and decryption.
    ///   - To wrap any secret key with any other secret key. Consideration
    ///     MUST be given to key size and mechanism strength or the token may
    ///     not allow the operation.
    ///   - To wrap a private key with any secret key.
    ///
    /// Of course, tokens vary in which types of keys can actually be wrapped
    /// with which mechanisms.
    pub fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        let mut wrapped_key_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_WrapKey,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            wrapping_key.into(),
            key.into(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut wrapped_key_len
        ))
        .into_result()?;

        let mut wrapped_key: Vec<u8> = vec![0; wrapped_key_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_WrapKey,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            wrapping_key.into(),
            key.into(),
            wrapped_key.as_mut_ptr() as CK_BYTE_PTR,
            &mut wrapped_key_len
        ))
        .into_result()?;

        wrapped_key.truncate(wrapped_key_len as usize);

        Ok(wrapped_key)
    }

    /// Unwraps (i.e. decrypts) a `wrapped_key`, creating a new private key
    /// or secret key object.
    ///
    /// The [`Unwrap`](Attribute::Unwrap) attribute of the `unwrapping_key`,
    /// which indicates whether the key supports unwrapping, MUST be `true`.
    ///
    /// The `template` for the new key SHALL specify
    /// [`ValueLen`](Attribute::ValueLen) when neither the key type of the
    /// unwrapped key nor the unwrapping `mechanism` unambiguously determine
    /// the length of the unwrapped key; otherwise, the function SHALL return
    /// [`TemplateIncomplete`](CryptokiRetVal::TemplateIncomplete).
    ///
    /// The `template` for the new key MAY specify
    /// [`ValueLen`](Attribute::ValueLen) when the key type of the unwrapped
    /// key or the unwrapping `mechanism` unambiguously determine the length of
    /// the unwrapped key. If any length conflict occurs between the key type
    /// of the unwrapped key, the output from the unwrapping `mechanism`, or
    /// the specified [`ValueLen`](Attribute::ValueLen), then the function
    /// SHALL return [`WrappedKeyLenRange`](CryptokiRetVal::WrappedKeyLenRange).
    ///
    /// The new key will have the
    /// [`AlwaysSensitive`](Attribute::AlwaysSensitive) attribute set to
    /// `false`, and the [`NeverExtractable`](Attribute::NeverExtractable)
    /// attribute set to `false`. The [`Extractable`](Attribute::Extractable)
    /// attribute is by default set to `true`.
    ///
    /// If a call to it cannot support the precise `template` supplied to it,
    /// it will fail and return without creating any key object.
    ///
    /// The key object created by a successful call to it will have its
    /// [`Local`](Attribute::Local) attribute set to `false`. In addition, the
    /// object created will have a value for [`UniqueId`](Attribute::UniqueId)
    /// generated and assigned (See [`Section 4.4.1`]).
    ///
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn unwrap_key(
        &self,
        mechanism: &Mechanism,
        unwrapping_key: ObjectHandle,
        wrapped_key: &[u8],
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let new_key_tmpl: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_UnwrapKey,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            unwrapping_key.into(),
            wrapped_key.as_ptr() as CK_BYTE_PTR,
            wrapped_key.len() as CK_ULONG,
            new_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            new_key_tmpl.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle.into())
    }

    /// Derives a key from a `base_key`, creating a new key object.
    ///
    /// The values of the [`Sensitive`](Attribute::Sensitive),
    /// [`AlwaysSensitive`](Attribute::AlwaysSensitive),
    /// [`Extractable`](Attribute::Extractable), and
    /// [`NeverExtractable`](Attribute::NeverExtractable) attributes for the
    /// `base_key` affect the values that these attributes can hold for the
    /// newly-derived key. See the description of each particular
    /// key-derivation `mechanism` in [`Section 6.42`] and [`Section 6.43`] for
    /// any constraints of this type.
    ///
    /// If a call to it cannot support the precise `template` supplied to it,
    /// it will fail and return without creating any key object.
    ///
    /// The key object created by a successful call to it will have its
    /// [`Local`](Attribute::Local) attribute set to `false`. In addition, the
    /// object created will have a value for [`UniqueId`](Attribute::UniqueId)
    /// generated and assigned (See [`Section 4.4.1`]).
    ///
    /// [`Section 6.42`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693562
    /// [`Section 6.43`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693575
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn derive_key(
        &self,
        mechanism: &Mechanism,
        base_key: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DeriveKey,
            self.handle().into(),
            &mut ck_mech as CK_MECHANISM_PTR,
            base_key.into(),
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle.into())
    }
}
