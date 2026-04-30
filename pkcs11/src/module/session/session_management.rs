use secrecy::ExposeSecret;

use crate::{
    error::{CryptokiRetVal, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Pkcs11Module<Initialized> {
    /// Opens a session between an application and a token in a particular slot.
    ///
    /// There may be a limit on the number of concurrent sessions an
    /// application may have with the token, which may depend on whether the
    /// session is "read-only" or "read/write".
    ///
    /// If the token is [`write-protected`], then only read-only sessions may
    /// be opened with it.
    ///
    /// If the application calling this function already has a R/W SO session
    /// open with the token, then any attempt to open a R/O session with the
    /// token fails with error code [`CryptokiRetVal::SessionReadWriteSoExists`]
    /// (see [`PKCS11-UG`] for further details).
    ///
    /// [`write-protected`]: TokenInfo::write_protected
    /// [`PKCS11-UG`]: http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html
    pub fn open_session(&self, slot: Slot, rw: bool) -> Result<Session> {
        let mut session_handle = CK_SESSION_HANDLE::default();
        let mut flags = SessionInfoFlags::SERIAL_SESSION;
        if rw {
            flags |= SessionInfoFlags::RW_SESSION;
        }

        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_OpenSession,
            slot.into(),
            flags.bits(),
            std::ptr::null_mut(),
            None,
            &mut session_handle
        ))
        .into_result()?;

        Ok(Session::new(self.clone(), session_handle.into()))
    }

    /// Opens a read/write session between an application and a token in
    /// a particular slot.
    pub fn open_rw_session(&self, slot: Slot) -> Result<Session> {
        self.open_session(slot, true)
    }

    /// Opens a read-only session session between an application and a token in
    /// a particular slot.
    pub fn open_ro_session(&self, slot: Slot) -> Result<Session> {
        self.open_session(slot, false)
    }

    /// Closes all sessions an application has with a token.
    pub fn close_all_session(&self, slot: Slot) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(self, C_CloseAllSessions, slot.into()))
            .into_result()
    }
}

impl Session {
    /// Obtains information about a session.
    pub fn get_session_info(&self) -> Result<SessionInfo> {
        let mut info = CK_SESSION_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GetSessionInfo,
            self.handle().into(),
            &mut info
        ))
        .into_result()?;

        SessionInfo::try_from(info)
    }

    /// Obtains a copy of the cryptographic operations state of a session,
    /// encoded as a string of bytes.
    pub fn get_operation_state(&self) -> Result<Vec<u8>> {
        let mut op_state_len: CK_ULONG = 0;

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GetOperationState,
            self.handle().into(),
            std::ptr::null_mut() as CK_BYTE_PTR,
            &mut op_state_len
        ))
        .into_result()?;

        let mut op_state: Vec<u8> = vec![0; op_state_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GetOperationState,
            self.handle().into(),
            op_state.as_mut_ptr() as CK_BYTE_PTR,
            &mut op_state_len
        ))
        .into_result()?;

        op_state.truncate(op_state_len as usize);

        Ok(op_state)
    }

    /// Restores the cryptographic operations state of a session
    /// from a string of bytes obtained with
    /// [`get_operation_state`](Session::get_operation_state).
    pub fn set_operation_state(
        &self,
        operation_state: Vec<u8>,
        encryption_key: Option<ObjectHandle>,
        authentication_key: Option<ObjectHandle>,
    ) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SetOperationState,
            self.handle().into(),
            operation_state.as_ptr() as CK_BYTE_PTR,
            operation_state.len() as CK_ULONG,
            encryption_key.map(ObjectHandle::into).unwrap_or(0),
            authentication_key.map(ObjectHandle::into).unwrap_or(0)
        ))
        .into_result()
    }

    /// Logs a user into a token.
    ///
    /// When the `user_type` is either [`So`] or [`User`], if the call
    /// succeeds, each of the application's sessions will enter either the
    /// [`SessionState::RwSecurityOfficer`] state, the [`SessionState::RwUser`]
    /// state, or the [`SessionState::RoUser`] state. If the `user_type` is
    /// [`UserType::ContextSpecific`], the behavior of this function depends on
    /// the context in which it is called. Improper use of this `user type`
    /// will result in a return value [`CryptokiRetVal::OperationNotInitialized`].
    ///
    /// If the token has a [`protected authentication path`], then that means
    /// that there is some way for a user to be authenticated to the token
    /// without having to send a PIN through the Cryptoki library. One such
    /// possibility is that the user enters a PIN on a PIN pad on the token
    /// itself, or on the slot device. Or the user might not even use a
    /// PIN—authentication could be achieved by some fingerprint-reading
    /// device,for example. To log into a token with a
    /// [`protected authentication path`] the `pin` parameter should be `None`.
    /// When this function returns, whatever authentication method supported by
    /// the token will have been performed; a return value `Ok(())` means that
    /// the user was successfully authenticated, and a return value of
    /// [`CryptokiRetVal::PinIncorrect`] means that the user was denied access.
    ///
    /// If there are any active cryptographic or object finding operations in
    /// an application's session, and then this function is successfully
    /// executed by that application, it may or may not be the case that those
    /// operations are still active. Therefore, before logging in, any active
    /// operations should be finished.
    ///
    /// If the application calling this function has a R/O session open with
    /// the token, then it will be unable to log the SO into a session (see
    /// [`PKCS11-UG`] for further details). An attempt to do this will result in
    /// the error code [`CryptokiRetVal::SessionReadOnlyExists`].
    ///
    /// This function may be called repeatedly, without intervening [`logout`]
    /// calls, if (and only if) a key with the [`ALWAYS_AUTHENTICATE`]
    /// attribute set to true exists, and the user needs to do cryptographic
    /// operation on this key. See further Section 4.9.
    ///
    /// [`So`]: UserType::So
    /// [`User`]: `UserType::User`
    /// [`protected authentication path`]: TokenInfo::protected_authentication_path
    /// [`PKCS11-UG`]: http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html
    /// [`logout`]: Self::logout
    /// [`ALWAYS_AUTHENTICATE`]: AttributeType::ALWAYS_AUTHENTICATE
    pub fn login(&self, user_type: UserType, pin: Option<&SecretPin>) -> Result<()> {
        let (pin_ptr, pin_len) = match pin {
            Some(pin) => (
                pin.expose_secret().as_ptr() as CK_UTF8CHAR_PTR,
                pin.expose_secret().len() as CK_ULONG,
            ),
            None => (std::ptr::null_mut(), 0),
        };

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Login,
            self.handle().into(),
            user_type.into(),
            pin_ptr,
            pin_len
        ))
        .into_result()
    }

    /// Logs a user out from a token.
    ///
    /// Depending on the current user type, if the call succeeds, each of the
    /// application's sessions will enter either the [`SessionState::RwPublic`]
    /// state or the [`SessionState::RoPublic`] state.
    ///
    /// When this function successfully executes, any of the application's
    /// handles to private objects become invalid (even if a user is later
    /// logged back into the token, those handles remain invalid). In addition,
    /// all private session objects from sessions belonging to the application
    /// are destroyed.
    ///
    /// If there are any active cryptographic or object-finding operations in
    /// an application's session, and then this function is successfully
    /// executed by that application, it may or may not be the case that those
    /// operations are still active. Therefore, before logging out, any active
    /// operations should be finished.
    pub fn logout(&self) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_Logout,
            self.handle().into()
        ))
        .into_result()
    }
}
