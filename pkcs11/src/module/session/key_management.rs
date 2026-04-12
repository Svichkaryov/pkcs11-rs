use crate::{
    error::{CryptokiRetVal, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    /// Generates a secret key or set of domain parameters, creating a new
    /// object.
    pub fn generate_key(
        &self,
        mechanism: &Mechanism,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateKey,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle)
    }

    /// Generates a public/private key pair, creating new key objects.
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

        let mut pub_key_obj_handle: ObjectHandle = ObjectHandle::default();
        let mut pr_key_obj_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateKeyPair,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            pub_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            pub_key_tmpl.len() as CK_ULONG,
            pr_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            pr_key_tmpl.len() as CK_ULONG,
            &mut pub_key_obj_handle,
            &mut pr_key_obj_handle
        ))
        .into_result()?;

        Ok((pub_key_obj_handle, pr_key_obj_handle))
    }

    /// Wraps (i.e., encrypts) a private or secret key.
    pub fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<Byte>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        let mut wrapped_key_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_WrapKey,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            wrapping_key as CK_OBJECT_HANDLE,
            key as CK_OBJECT_HANDLE,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut wrapped_key_len
        ))
        .into_result()?;

        let mut wrapped_key: Vec<Byte> = vec![0; wrapped_key_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_WrapKey,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            wrapping_key as CK_OBJECT_HANDLE,
            key as CK_OBJECT_HANDLE,
            wrapped_key.as_mut_ptr() as CK_BYTE_PTR,
            &mut wrapped_key_len
        ))
        .into_result()?;

        wrapped_key.truncate(wrapped_key_len as usize);

        Ok(wrapped_key)
    }

    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key
    /// or secret key object.
    pub fn unwrap_key(
        &self,
        mechanism: &Mechanism,
        unwrapping_key: ObjectHandle,
        wrapped_key: &[Byte],
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let new_key_tmpl: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_UnwrapKey,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            unwrapping_key as CK_OBJECT_HANDLE,
            wrapped_key.as_ptr() as CK_BYTE_PTR,
            wrapped_key.len() as CK_ULONG,
            new_key_tmpl.as_ptr() as CK_ATTRIBUTE_PTR,
            new_key_tmpl.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle)
    }

    /// Derives a key from a base key, creating a new key object.
    pub fn derive_key(
        &self,
        mechanism: &Mechanism,
        base_key: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DeriveKey,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            base_key as CK_OBJECT_HANDLE,
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle
        ))
        .into_result()?;

        Ok(object_handle)
    }
}
