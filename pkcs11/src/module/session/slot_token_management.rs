use secrecy::ExposeSecret;

use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    /// Initializes the normal user's PIN.
    ///
    /// Can only be called in the [`SessionState::RwSecurityOfficer`] state.
    /// An attempt to call it from a session in any other state fails with
    /// error [`CryptokiRetVal::UserNotLoggedIn`].
    ///
    /// If the token has a [`protected authentication path`], then that means
    /// that there is some way for a user to be authenticated to the token
    /// without having to send a PIN through the Cryptoki library. One such
    /// possibility is that the user enters a PIN on a PIN pad on the token
    /// itself, or on the slot device. To initialize the normal user's PIN on
    /// a token with such a protected authentication path, the `pin` parameter
    /// to this function should be `None`. During the execution of this, the SO
    /// will enter the new PIN through the protected authentication path.
    ///
    /// If the token has a protected authentication path other than a PIN pad,
    /// then it is token-dependent whether or not this function can be used to
    /// initialize the normal user's token access.
    ///
    /// [`protected authentication path`]: TokenInfo::protected_authentication_path
    pub fn init_pin(&self, pin: Option<&SecretPin>) -> Result<()> {
        let (pin_ptr, pin_len) = match pin {
            Some(pin) => (
                pin.expose_secret().as_ptr() as CK_UTF8CHAR_PTR,
                pin.expose_secret().len() as CK_ULONG,
            ),
            None => (std::ptr::null_mut(), 0),
        };

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_InitPIN,
            self.handle().into(),
            pin_ptr,
            pin_len
        ))
        .into_result()
    }

    /// Modifies the PIN of the user that is currently logged in, or the
    /// [`UserType::User`] PIN if the session is not logged in.
    ///
    /// Can only be called in the [`SessionState::RwPublic`] state,
    /// [`SessionState::RwSecurityOfficer`] state, or [`SessionState::RwUser`]
    /// state. An attempt to call it from a session in any other state fails
    /// with error [`CryptokiRetVal::SessionReadOnly`].
    ///
    /// If the token has a [`protected authentication path`], then that means
    /// that there is some way for a user to be authenticated to the token
    /// without having to send a PIN through the Cryptoki library. One such
    /// possibility is that the user enters a PIN on a PIN pad on the token
    /// itself, or on the slot device. To modify the current user's PIN on a
    /// token with such a protected authentication path, the `old_pin` and
    /// `new_pin` parameters to this function should be `None`. During the
    /// execution of this function, the current user will enter the old PIN and
    /// the new PIN through the protected authentication path. It is not
    /// specified how the PIN pad should be used to enter two PINs; this varies.
    ///
    /// If the token has a protected authentication path other than a PIN pad,
    /// then it is token-dependent whether or not this function can be used to
    /// modify the current user's PIN.
    ///
    /// [`protected authentication path`]: TokenInfo::protected_authentication_path
    pub fn set_pin(
        &self,
        old_pin: Option<&SecretPin>,
        new_pin: Option<&SecretPin>,
    ) -> Result<()> {
        let (old_pin_ptr, old_pin_len, new_pin_ptr, new_pin_len) =
            match (old_pin, new_pin) {
                (Some(old_pin), Some(new_pin)) => (
                    old_pin.expose_secret().as_ptr() as CK_UTF8CHAR_PTR,
                    old_pin.expose_secret().len() as CK_ULONG,
                    new_pin.expose_secret().as_ptr() as CK_UTF8CHAR_PTR,
                    new_pin.expose_secret().len() as CK_ULONG,
                ),
                (None, None) => (std::ptr::null_mut(), 0, std::ptr::null_mut(), 0),
                _ => return Err(Error::InvalidInput),
            };

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SetPIN,
            self.handle().into(),
            old_pin_ptr,
            old_pin_len,
            new_pin_ptr,
            new_pin_len
        ))
        .into_result()
    }
}
