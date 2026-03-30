use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    // Encryption functions

    /// Initializes an encryption operation.
    pub fn encrypt_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Continues a multiple-part encryption operation, processing another data
    /// part.
    pub fn encrypt_update(&self, data: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut encrypted_data_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptUpdate,
            self.handle(),
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut encrypted_data_len
        ))
        .into_result()?;

        let mut encrypted_data: Vec<Byte> = vec![0; encrypted_data_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptUpdate,
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

    /// Finishes a multiple-part encryption operation.
    pub fn encrypt_final(&self) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut last_encrypted_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptFinal,
            self.handle(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut last_encrypted_part_len
        ))
        .into_result()?;

        let mut last_encrypted_part: Vec<Byte> =
            vec![0; last_encrypted_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_EncryptFinal,
            self.handle(),
            last_encrypted_part.as_mut_ptr() as CK_BYTE_PTR,
            &mut last_encrypted_part_len
        ))
        .into_result()?;

        last_encrypted_part.truncate(last_encrypted_part_len as usize);

        Ok(last_encrypted_part)
    }

    // Decryption functions

    /// Initializes a decryption operation.
    pub fn decrypt_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Continues a multiple-part decryption operation, processing another
    /// encrypted data part.
    pub fn decrypt_update(&self, encrypted_part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut decrypted_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut decrypted_part_len
        ))
        .into_result()?;

        let mut decrypted_data: Vec<Byte> = vec![0; decrypted_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            decrypted_data.as_mut_ptr() as CK_BYTE_PTR,
            &mut decrypted_part_len
        ))
        .into_result()?;

        decrypted_data.truncate(decrypted_part_len as usize);

        Ok(decrypted_data)
    }

    /// Finishes a multiple-part decryption operation.
    pub fn decrypt_final(&self) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut last_decrypted_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptFinal,
            self.handle(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut last_decrypted_part_len
        ))
        .into_result()?;

        let mut last_decrypted_part: Vec<Byte> =
            vec![0; last_decrypted_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptFinal,
            self.handle(),
            last_decrypted_part.as_mut_ptr() as CK_BYTE_PTR,
            &mut last_decrypted_part_len
        ))
        .into_result()?;

        last_decrypted_part.truncate(last_decrypted_part_len as usize);

        Ok(last_decrypted_part)
    }

    // Message digesting functions

    /// Initializes a message-digesting operation.
    pub fn digest_init(&self, mechanism: &Mechanism) -> Result<()> {
        self.module().initialized()?;

        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DigestInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR
        ))
        .into_result()
    }

    /// Continues a multiple-part message-digesting operation, processing
    /// another data part.
    pub fn digest_update(&self, part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut digest_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut digest_part_len
        ))
        .into_result()?;

        let mut digest_part: Vec<Byte> = vec![0; digest_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            digest_part.as_mut_ptr() as CK_BYTE_PTR,
            &mut digest_part_len
        ))
        .into_result()?;

        digest_part.truncate(digest_part_len as usize);

        Ok(digest_part)
    }

    /// Continues a multiple-part message-digesting operation by digesting the
    /// value of a secret key.
    pub fn digest_key(&self, key: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DigestKey,
            self.handle(),
            key as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Finishes a multiple-part message-digesting operation, returning the
    /// message digest.
    pub fn digest_final(&self) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut digest_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptFinal,
            self.handle(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut digest_len
        ))
        .into_result()?;

        let mut digest: Vec<Byte> = vec![0; digest_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptFinal,
            self.handle(),
            digest.as_mut_ptr() as CK_BYTE_PTR,
            &mut digest_len
        ))
        .into_result()?;

        digest.truncate(digest_len as usize);

        Ok(digest)
    }

    // Signing and MACing functions

    /// Initializes a signature operation, where the signature is an appendix
    /// to the data.
    pub fn sign_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Continues a multiple-part signature operation, processing another data
    /// part.
    pub fn sign_update(&self, part: &[Byte]) -> Result<()> {
        self.module().initialized()?;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG
        ))
        .into_result()
    }

    /// Finishes a multiple-part signature operation, returning the signature.
    pub fn sign_final(&self) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut signature_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignFinal,
            self.handle(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        let mut signature: Vec<Byte> = vec![0; signature_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignFinal,
            self.handle(),
            signature.as_mut_ptr() as CK_BYTE_PTR,
            &mut signature_len
        ))
        .into_result()?;

        signature.truncate(signature_len as usize);

        Ok(signature)
    }

    /// Initializes a verification operation, where the signature is an appendix
    /// to the data.
    pub fn verify_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        self.module().initialized()?;

        let mut ck_mech: CK_MECHANISM = mechanism.into();

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyInit,
            self.handle(),
            &mut ck_mech as CK_MECHANISM_PTR,
            key as CK_OBJECT_HANDLE
        ))
        .into_result()
    }

    /// Continues a multiple-part verification operation, processing another
    /// data part.
    pub fn verify_update(&self, part: &[Byte]) -> Result<()> {
        self.module().initialized()?;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_VerifyUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG
        ))
        .into_result()
    }

    /// Finishes a multiple-part verification operation, checking the signature.
    pub fn verify_final(&self, signature: &[Byte]) -> Result<bool> {
        self.module().initialized()?;

        match invoke_pkcs11!(
            self.module(),
            C_VerifyFinal,
            self.handle(),
            signature.as_ptr() as CK_BYTE_PTR,
            signature.len() as CK_ULONG
        ) {
            CKR_OK => Ok(true),
            CKR_SIGNATURE_INVALID => Ok(false),
            err => Err(Error::Pkcs11(CryptokiRetVal::from(err))),
        }
    }

    // Dual-function cryptographic functions

    /// Continues multiple-part digest and encryption operations, processing
    /// another data part.
    pub fn digest_encrypt_update(&self, part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut encrypted_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DigestEncryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut encrypted_part_len
        ))
        .into_result()?;

        let mut encrypted_part: Vec<Byte> = vec![0; encrypted_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DigestEncryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            encrypted_part.as_mut_ptr() as CK_BYTE_PTR,
            &mut encrypted_part_len
        ))
        .into_result()?;

        encrypted_part.truncate(encrypted_part_len as usize);

        Ok(encrypted_part)
    }

    /// Continues a multiple-part combined decryption and digest operation,
    /// processing another data part.
    pub fn decrypt_digest_update(&self, encrypted_part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptDigestUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut part_len
        ))
        .into_result()?;

        let mut part: Vec<Byte> = vec![0; part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptDigestUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            part.as_mut_ptr() as CK_BYTE_PTR,
            &mut part_len
        ))
        .into_result()?;

        part.truncate(part_len as usize);

        Ok(part)
    }

    /// Continues a multiple-part combined signature and encryption operation,
    /// processing another data part.
    pub fn sign_encrypt_update(&self, part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut encrypted_part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignEncryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut encrypted_part_len
        ))
        .into_result()?;

        let mut encrypted_part: Vec<Byte> = vec![0; encrypted_part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SignEncryptUpdate,
            self.handle(),
            part.as_ptr() as CK_BYTE_PTR,
            part.len() as CK_ULONG,
            encrypted_part.as_mut_ptr() as CK_BYTE_PTR,
            &mut encrypted_part_len
        ))
        .into_result()?;

        encrypted_part.truncate(encrypted_part_len as usize);

        Ok(encrypted_part)
    }

    /// Continues a multiple-part combined decryption and verification
    /// operation, processing another data part.
    pub fn decrypt_verify_update(&self, encrypted_part: &[Byte]) -> Result<Vec<Byte>> {
        self.module().initialized()?;

        let mut part_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptVerifyUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut part_len
        ))
        .into_result()?;

        let mut part: Vec<Byte> = vec![0; part_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_DecryptVerifyUpdate,
            self.handle(),
            encrypted_part.as_ptr() as CK_BYTE_PTR,
            encrypted_part.len() as CK_ULONG,
            part.as_mut_ptr() as CK_BYTE_PTR,
            &mut part_len
        ))
        .into_result()?;

        part.truncate(part_len as usize);

        Ok(part)
    }
}
