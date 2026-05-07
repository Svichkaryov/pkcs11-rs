use pkcs11_sys::*;

use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::invoke_pkcs11,
    types::{Attribute, AttributeType, ObjectHandle},
};

use super::Session;

impl Session {
    /// Creates a new object.
    ///
    /// If a call to [`create_object`] cannot support the precise `template`
    /// supplied to it, it will fail and return without creating any object.
    ///
    /// If [`create_object`] is used to create a key object, pass
    /// [`Attribute::Local(true)`] in the `template`. If that key object is a
    /// secret or private key then pass [`Attribute::AlwaysSensitive(false)`]
    /// and [`Attribute::NeverExtractable(false)`].
    ///
    /// Only session objects can be created during a read-only session. Only
    /// public objects can be created unless the normal user is logged in.
    ///
    /// Whenever an object is created, a value for [`Attribute::UniqueId`] is
    /// generated and assigned to the new object (See [`Section 4.4.1`]).
    ///
    /// [`create_object`]: Self::create_object
    /// [`Attribute::Local(true)`]: crate::doc_links::Attribute::Local
    /// [`Attribute::AlwaysSensitive(false)`]: crate::doc_links::Attribute::AlwaysSensitive
    /// [`Attribute::NeverExtractable(false)`]: crate::doc_links::Attribute::NeverExtractable
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_CreateObject,
            self.handle().into(),
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle as CK_OBJECT_HANDLE_PTR
        ))
        .into_result()?;

        Ok(object_handle.into())
    }

    /// Copies an `object`, creating a new object for the copy.
    ///
    /// The `template` may specify new values for any attributes of the
    /// `object` that can ordinarily be modified (e.g., in the course of
    /// copying a secret key, a key's [`Extractable`] attribute may be changed
    /// from `true` to `false`, but not the other way around. If this change is
    /// made, the new key's [`NeverExtractable`] attribute will have the value
    /// `false`. Similarly, the `template` may specify that the new key's
    /// [`Sensitive`] attribute be `true`; the new key will have the same value
    /// for its [`AlwaysSensitive`] attribute as the original key). It may also
    /// specify new values of the [`Token`] and [`Private`] attributes (e.g.,
    /// to copy a session object to a token object). If the `template`
    /// specifies a value of an attribute which is incompatible with other
    /// existing attributes of the object, the call fails with the return
    /// code [`TemplateInconsistent`].
    ///
    /// If a call to [`copy_object`] cannot support the precise `template`
    /// supplied to it, it will fail and return without creating any object.
    /// If the object indicated by `object` has its [`Copyable`] attribute set
    /// to `false`, [`copy_object`] will return [`ActionProhibited`].
    ///
    /// Whenever an object is copied, a new value for [`UniqueId`] is generated
    /// and assigned to the new object (See [`Section 4.4.1`]).
    ///
    /// Only session objects can be created during a read-only session. Only
    /// public objects can be created unless the normal user is logged in.
    ///
    /// [`Extractable`]: crate::doc_links::Attribute::Extractable
    /// [`NeverExtractable`]: crate::doc_links::Attribute::NeverExtractable
    /// [`Sensitive`]: crate::doc_links::Attribute::Sensitive
    /// [`AlwaysSensitive`]: crate::doc_links::Attribute::AlwaysSensitive
    /// [`Token`]: crate::doc_links::Attribute::Token
    /// [`Private`]: crate::doc_links::Attribute::Private
    /// [`TemplateInconsistent`]: crate::doc_links::CryptokiRetVal::TemplateInconsistent
    /// [`copy_object`]: Self::copy_object
    /// [`Copyable`]: crate::doc_links::Attribute::Copyable
    /// [`ActionProhibited`]: crate::doc_links::CryptokiRetVal::ActionProhibited
    /// [`UniqueId`]: crate::doc_links::Attribute::UniqueId
    /// [`Section 4.4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693081
    pub fn copy_object(
        &self,
        object: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut new_object_handle: CK_OBJECT_HANDLE = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_CopyObject,
            self.handle().into(),
            object.into(),
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut new_object_handle as CK_OBJECT_HANDLE_PTR
        ))
        .into_result()?;

        Ok(new_object_handle.into())
    }

    /// Destroys an `object`.
    ///
    /// Only session objects can be destroyed during a read-only session. Only
    /// public objects can be destroyed unless the normal user is logged in.
    ///
    /// Certain objects may not be destroyed. Calling it on such objects will
    /// result in the [`ActionProhibited`](CryptokiRetVal::ActionProhibited)
    /// error code. An application can consult the object's
    /// [`Destroyable`](Attribute::Destroyable) attribute to determine if an
    /// object may be destroyed or not.
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DestroyObject,
            self.handle().into(),
            object.into()
        ))
        .into_result()
    }

    /// Gets the size of an `object` in bytes.
    ///
    /// Cryptoki does not specify what the precise meaning of an object's size
    /// is. Intuitively, it is some measure of how much token memory the object
    /// takes up. If an application deletes (say) a private object of size S,
    /// it might be reasonable to assume that the `ulFreePrivateMemory` field
    /// (returned by [`free_private_memory`]) of the token's [`TokenInfo`]
    /// structure increases by approximately S.
    ///
    /// [`free_private_memory`]: crate::doc_links::TokenInfo::free_private_memory
    /// [`TokenInfo`]: crate::doc_links::TokenInfo
    pub fn get_object_size(&self, object: ObjectHandle) -> Result<usize> {
        let mut object_size: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GetObjectSize,
            self.handle().into(),
            object.into(),
            &mut object_size as CK_ULONG_PTR
        ))
        .into_result()?;

        Ok(object_size as usize)
    }

    /// Obtains the value of one or more attributes of an `object`.
    ///
    /// If a value is unavailable for any `attribute type`, then that attribute
    /// is skipped. So you have to manually check if that an attribute was
    /// missing in the resulting vector.
    pub fn get_attributes(
        &self,
        object: ObjectHandle,
        attribute_types: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();

        for attr_type in attribute_types.iter() {
            template.push(CK_ATTRIBUTE {
                attrType: (*attr_type).into(),
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
        }

        // Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
        // CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote
        // true errors for C_GetAttributeValue. If a call to C_GetAttributeValue
        // returns any of these three values, then the call MUST nonetheless
        // have processed every attribute in the template supplied
        // to C_GetAttributeValue. Each attribute in the template whose value can
        // be returned by the call to C_GetAttributeValue will be returned by
        // the call to C_GetAttributeValue.
        let ck_rv: CK_RV = invoke_pkcs11!(
            self.module(),
            C_GetAttributeValue,
            self.handle().into(),
            object.into(),
            template.as_mut_ptr(),
            template.len() as CK_ULONG
        );
        if ck_rv != CKR_OK
            && ck_rv != CKR_ATTRIBUTE_SENSITIVE
            && ck_rv != CKR_ATTRIBUTE_TYPE_INVALID
            && ck_rv != CKR_BUFFER_TOO_SMALL
        {
            return Err(Error::Pkcs11(CryptokiRetVal::from(ck_rv)));
        }

        // Allocating a buffers for template.
        let attrs_buffers: Vec<Vec<u8>> = template
            .iter()
            .filter_map(|attr| {
                if attr.ulValueLen != CK_UNAVAILABLE_INFORMATION {
                    Some(vec![0; attr.ulValueLen as usize])
                } else {
                    None
                }
            })
            .collect();

        let mut template: Vec<CK_ATTRIBUTE> = template
            .iter()
            .zip(attrs_buffers.iter())
            .map(|(attr, buf)| {
                Ok(CK_ATTRIBUTE {
                    attrType: attr.attrType,
                    pValue: buf.as_ptr() as *mut std::ffi::c_void,
                    ulValueLen: buf.len() as CK_ULONG,
                })
            })
            .collect::<Result<Vec<CK_ATTRIBUTE>>>()?;

        let ck_rv: CK_RV = invoke_pkcs11!(
            self.module(),
            C_GetAttributeValue,
            self.handle().into(),
            object.into(),
            template.as_mut_ptr(),
            template.len() as CK_ULONG
        );
        if ck_rv != CKR_OK
            && ck_rv != CKR_ATTRIBUTE_SENSITIVE
            && ck_rv != CKR_ATTRIBUTE_TYPE_INVALID
            && ck_rv != CKR_BUFFER_TOO_SMALL
        {
            return Err(Error::Pkcs11(CryptokiRetVal::from(ck_rv)));
        }

        template.into_iter().map(Attribute::try_from).collect()
    }

    /// Modifies the value of one or more attributes of an `object`.
    ///
    /// Certain objects may not be modified. Calling it on such objects will
    /// result in the [`ActionProhibited`] error code. An application can
    /// consult the object's [`Modifiable`] attribute to determine if an
    /// object may be modified or not.
    ///
    /// Only session objects can be modified during a read-only session.
    ///
    /// The `template` may specify new values for any attributes of the
    /// `object` that can be modified. If the `template` specifies a value of
    /// an attribute which is incompatible with other existing attributes of
    /// the `object`, the call fails with the return code
    /// [`TemplateInconsistent`].
    ///
    /// Not all attributes can be modified; see [`Section 4.1.2`] for more
    /// details.
    ///
    /// [`ActionProhibited`]: crate::doc_links::CryptokiRetVal::ActionProhibited
    /// [`Modifiable`]: crate::doc_links::Attribute::Modifiable
    /// [`TemplateInconsistent`]: crate::doc_links::CryptokiRetVal::TemplateInconsistent
    /// [`Section 4.1.2`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693065
    pub fn set_attribute_value(
        &self,
        object: ObjectHandle,
        template: &[Attribute],
    ) -> Result<()> {
        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SetAttributeValue,
            self.handle().into(),
            object.into(),
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG
        ))
        .into_result()?;

        Ok(())
    }

    /// Search for token and session objects that match a `template`.
    ///
    /// The matching criterion is an exact byte-for-byte match with all
    /// attributes in the `template`. To find all objects pass an empty
    /// `template`.
    ///
    /// The object search operation will only find objects that the session can
    /// view. For example, an object search in an "R/W Public Session" will not
    /// find any private objects (even if one of the attributes in the search
    /// template specifies that the search is for private objects).
    ///
    /// If a search operation is active, and objects are created or destroyed
    /// which fit the search `template` for the active search operation, then
    /// those objects may or may not be found by the search operation. Note
    /// that this means that, under these circumstances, the search operation
    /// may return invalid object handles.
    ///
    /// If the [`UniqueId`](Attribute::UniqueId) attribute is present in the
    /// search `template`, either zero or one objects will be found, since at
    /// most one object can have any particular
    /// [`UniqueId`](Attribute::UniqueId) value.
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let mut template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_FindObjectsInit,
            self.handle().into(),
            template.as_mut_ptr(),
            template.len() as CK_ULONG
        ))
        .into_result()?;

        let mut object_handle: CK_OBJECT_HANDLE = 0;
        let mut object_count: CK_ULONG = 0;
        let mut ck_ret: CK_RV;
        let mut object_list: Vec<ObjectHandle> = Vec::new();

        loop {
            // A race condition may occur. If someone calls the C_FindObjects
            // function with NULL pSlotList that executes at this location
            // and returned before the next code is called,
            // the list of slots will update and may get larger.
            ck_ret = invoke_pkcs11!(
                self.module(),
                C_FindObjects,
                self.handle().into(),
                &mut object_handle as CK_OBJECT_HANDLE_PTR,
                1,
                &mut object_count as CK_ULONG_PTR
            );

            if ck_ret != CKR_OK || object_count == 0 {
                break;
            }

            object_list.push(object_handle.into());
        }

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_FindObjectsFinal,
            self.handle().into()
        ))
        .into_result()?;

        if ck_ret != CKR_OK {
            // from C_FindObjects function loop call
            CryptokiRetVal::from(ck_ret).into_result()?;
        }

        Ok(object_list)
    }
}
