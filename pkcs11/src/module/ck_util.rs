use crate::{
    bindings::*,
    error::{Error, Result}
};

macro_rules! check_ck_func {
    ($fl:expr, [ $( $func_name:ident),* ] ) => {
        $(
            if $fl.$func_name.is_none() {
                return Err(Error::Module(format!(
                    "{} has no entry point defined in Cryptoki library",
                    stringify!($func_name)
                )));
            }
        )*
    };
}

// Every function in the Cryptoki API MUST have an entry point defined in the
// Cryptoki library's CK_FUNCTION_LIST structure.
pub(crate) fn check_ck_functional_list_valid(
    ck_func_list_ptr: *const CK_FUNCTION_LIST
) -> Result<()> {
    // Implementation via iteration over a pointer starting from
    // the C_Initialize field is not suitable due to the lack of retrieve
    // a function name.
    unsafe {
        let fl = *ck_func_list_ptr;
        check_ck_func!(fl,
            [
                C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList,
                C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList,
                C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN,
                C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo,
                C_GetOperationState, C_SetOperationState, C_Login, C_Logout,
                C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
                C_GetAttributeValue, C_SetAttributeValue,
                C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,
                C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal,
                C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal,
                C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal,
                C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
                C_SignRecoverInit, C_SignRecover,
                C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal,
                C_VerifyRecoverInit, C_VerifyRecover,
                C_DigestEncryptUpdate, C_DecryptDigestUpdate,
                C_SignEncryptUpdate, C_DecryptVerifyUpdate,
                C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey,
                C_DeriveKey, C_SeedRandom, C_GenerateRandom, C_GetFunctionStatus,
                C_CancelFunction, C_WaitForSlotEvent
            ]
        );
    }
    Ok(())
}

pub(crate) fn string_from_blank_padded(field: &[CK_UTF8CHAR]) -> String {
    let decoded_str = String::from_utf8_lossy(field);
    decoded_str.trim_end_matches(' ').to_string()
}

// Convert rust string to pkcs11 C label. Label points to the 32-byte label
// of the token (which MUST be padded with blank characters, and which
// MUST not be null-terminated).
pub(crate) fn c_label_from_str(label: &str) -> Result<[u8; 32]> {
    let mut c_label: [u8; 32] = [b' '; 32];

    let mut i = 0;
    for c in label.chars() {
        if c == '\0' {
            return Err(Error::InvalidInput);
        }
        if i + c.len_utf8() > 32 {
            break;
        }
        let mut buf = [0u8; 4];
        let bytes = c.encode_utf8(&mut buf).as_bytes();
        c_label[i..i + bytes.len()].copy_from_slice(bytes);
        i += bytes.len();
    }

    Ok(c_label)
}
