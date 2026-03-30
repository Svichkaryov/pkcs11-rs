use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    /// Creates a new object.
    pub fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        self.module().initialized()?;

        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut object_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_CreateObject,
            self.handle(),
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut object_handle as CK_OBJECT_HANDLE_PTR
        ))
        .into_result()?;

        Ok(object_handle)
    }

    /// Copies an object, creating a new object for the copy.
    ///
    /// The template may specify new values for any attributes of the
    /// object that can ordinarily be modified.
    pub fn copy_object(
        &self,
        object: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        self.module().initialized()?;

        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        let mut new_object_handle: ObjectHandle = ObjectHandle::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_CopyObject,
            self.handle(),
            object as CK_OBJECT_HANDLE,
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG,
            &mut new_object_handle as CK_OBJECT_HANDLE_PTR
        ))
        .into_result()?;

        Ok(new_object_handle)
    }

    /// Destroys an object.
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DestroyObject,
            self.handle(),
            object as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Gets the size of an object in bytes.
    pub fn get_object_size(&self, object: ObjectHandle) -> Result<Ulong> {
        self.module().initialized()?;

        let mut object_size: Ulong = Ulong::default();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GetObjectSize,
            self.handle(),
            object as CK_OBJECT_HANDLE,
            &mut object_size as CK_ULONG_PTR
        ))
        .into_result()?;

        Ok(object_size)
    }

    /// Obtains the value of one or more attributes of an object.
    ///
    /// If a value is unavailable (CK_UNAVAILABLE_INFORMATION) for any attribute
    /// type, then that attribute is skipped. So you have to manually check
    /// if that an attribute was missing in the resulting vector.
    pub fn get_attributes(
        &self,
        object: ObjectHandle,
        attribute_types: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        self.module().initialized()?;

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
            self.handle(),
            object,
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
            self.handle(),
            object,
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

    /// Modifies the value of one or more attributes of an object.
    pub fn set_attribute_value(
        &self,
        object: ObjectHandle,
        template: &[Attribute],
    ) -> Result<()> {
        self.module().initialized()?;

        let template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SetAttributeValue,
            self.handle(),
            object,
            template.as_ptr() as CK_ATTRIBUTE_PTR,
            template.len() as CK_ULONG
        ))
        .into_result()?;

        Ok(())
    }

    /// Search for token and session objects that match a template.
    ///
    /// At most one search operation may be active at a given time
    /// in a given session.
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let mut template: Vec<CK_ATTRIBUTE> =
            template.iter().map(|attr| attr.into()).collect();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_FindObjectsInit,
            self.handle(),
            template.as_mut_ptr(),
            template.len() as CK_ULONG
        ))
        .into_result()?;

        let mut object_handle: ObjectHandle = ObjectHandle::default();
        let mut object_count: Ulong = Ulong::default();
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
                self.handle(),
                &mut object_handle as CK_OBJECT_HANDLE_PTR,
                1,
                &mut object_count as CK_ULONG_PTR
            );

            if ck_ret != CKR_OK || object_count == 0 {
                break;
            }

            object_list.push(object_handle);
        }

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_FindObjectsFinal,
            self.handle()
        ))
        .into_result()?;

        if ck_ret != CKR_OK {
            // from C_FindObjects function loop call
            CryptokiRetVal::from(ck_ret).into_result()?;
        }

        Ok(object_list)
    }
}
