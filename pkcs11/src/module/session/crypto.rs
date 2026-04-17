use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    // Encryption functions

    /// Encrypts single-part data.
    pub fn encrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        let mut encrypted_data_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Encrypt,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut encrypted_data_len
        ))
        .into_result()?;

        let mut encrypted_data: Vec<u8> = vec![0; encrypted_data_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Encrypt,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            encrypted_data.as_mut_ptr() as CK_BYTE_PTR,
            &mut encrypted_data_len
        ))
        .into_result()?;

        encrypted_data.truncate(encrypted_data_len as usize);

        Ok(encrypted_data)
    }

    // Decryption functions

    /// Decrypts encrypted data in a single part.
    pub fn decrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        let mut decrypted_data_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Decrypt,
            self.handle(),
            encrypted_data.as_ptr() as CK_BYTE_PTR,
            encrypted_data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut decrypted_data_len
        ))
        .into_result()?;

        let mut decrypted_data = vec![0; decrypted_data_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Decrypt,
            self.handle(),
            encrypted_data.as_ptr() as CK_BYTE_PTR,
            encrypted_data.len() as CK_ULONG,
            decrypted_data.as_mut_ptr() as CK_BYTE_PTR,
            &mut decrypted_data_len
        ))
        .into_result()?;

        decrypted_data.truncate(decrypted_data_len as usize);

        Ok(decrypted_data)
    }

    // Message digesting functions

    /// Digests data in a single part.
    pub fn digest(&self, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DigestInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR
        ))
        .into_result()?;

        let mut digest_data_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Digest,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut digest_data_len
        ))
        .into_result()?;

        let mut digest_data: Vec<u8> = vec![0; digest_data_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Digest,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            digest_data.as_mut_ptr() as CK_BYTE_PTR,
            &mut digest_data_len
        ))
        .into_result()?;

        digest_data.truncate(digest_data_len as usize);

        Ok(digest_data)
    }

    // Signing and MACing functions

    /// Signs data in a single part, where the signature is an appendix to the
    /// data.
    pub fn sign(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        let mut signature_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Sign,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        let mut signature: Vec<u8> = vec![0; signature_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Sign,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_mut_ptr() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        signature.truncate(signature_len as usize);

        Ok(signature)
    }

    /// Signs data in a single operation, where the data can be recovered from
    /// the signature.
    pub fn sign_recover(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignRecoverInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        let mut signature_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignRecover,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        let mut signature: Vec<u8> = vec![0; signature_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignRecover,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_mut_ptr() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        signature.truncate(signature_len as usize);

        Ok(signature)
    }

    /// verifies a signature in a single-part operation, where the signature is
    /// an appendix to the data.
    pub fn verify(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        match invoke_pkcs11!(
            self.module(),
            C_Verify,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG
        ) {
            CKR_OK => Ok(true),
            CKR_SIGNATURE_INVALID => Ok(false),
            err => Err(Error::Pkcs11(CryptokiRetVal::from(err))),
        }
    }

    /// Verifies a signature in a single-part operation, where the data
    /// is recovered from the signature.
    pub fn verify_recover(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyRecoverInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()?;

        let mut data_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyRecover,
            self.handle(),
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut data_len
        ))
        .into_result()?;

        let mut data: Vec<u8> = vec![0; data_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyRecover,
            self.handle(),
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG,
            data.as_mut_ptr() as CK_BYTE_PTR,
            &mut data_len
        ))
        .into_result()?;

        data.truncate(data_len as usize);

        Ok(data)
    }
}
