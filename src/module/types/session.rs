use bitflags::bitflags;
use std::convert::TryFrom;

use crate::error::{Error, Result};

use super::general::*;

pub type SessionHandle = CK_SESSION_HANDLE;

// CK_SESSION_INFO

bitflags! {
    /// Session Information Flags for [`CK_SESSION_INFO`]
    #[derive(Debug, Clone)]
    pub struct SessionInfoFlags: CK_FLAGS {
        const RW_SESSION = CKF_RW_SESSION;
        const SERIAL_SESSION = CKF_SERIAL_SESSION;
    }
}

/// Holds the session state, as described in
/// [`PKCS11-UG`](http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// The application has opened a read-only session. The application has
    /// read-only access to public token objects and read/write access
    /// to public session objects.
    RoPublic,
    /// The normal user has been authenticated to the token. The application
    /// has read-only access to all token objects (public or private) and
    /// read/write access to all session objects (public or private).
    RoUser,
    /// The application has opened a read/write session. The application has
    /// read/write access to all public objects.
    RwPublic,
    /// The normal user has been authenticated to the token. The application
    /// has read/write access to all objects.
    RwUser,
    /// The Security Officer has been authenticated to the token. The
    /// application has read/write access only to public objects on the token,
    /// not to private objects. The SO can set the normal user's PIN.
    RwSecurityOfficer,
}

impl TryFrom<CK_STATE> for SessionState {
    type Error = Error;

    fn try_from(value: CK_STATE) -> Result<Self> {
        match value {
            CKS_RO_PUBLIC_SESSION => Ok(Self::RoPublic),
            CKS_RO_USER_FUNCTIONS => Ok(Self::RoUser),
            CKS_RW_PUBLIC_SESSION => Ok(Self::RwPublic),
            CKS_RW_USER_FUNCTIONS => Ok(Self::RwUser),
            CKS_RW_SO_FUNCTIONS => Ok(Self::RwSecurityOfficer),
            _ => Err(Error::InvalidValue),
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::RoPublic => write!(f, "Ro public"),
            SessionState::RoUser => write!(f, "Ro user"),
            SessionState::RwPublic => write!(f, "Rw public"),
            SessionState::RwUser => write!(f, "Rw user"),
            SessionState::RwSecurityOfficer => write!(f, "Rw security officer"),
            // _ => write!(f, "Unknown session state")
        }
    }
}

pub type DeviceError = u64;

// Provides information about a session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// ID of the slot that interfaces with the token
    pub slot_id: Slot,
    /// The state of the session
    pub state: SessionState,
    /// Bit flags that define the type of session
    pub flags: SessionInfoFlags,
    /// An error code defined by the cryptographic device. Used for errors
    /// not covered by Cryptoki.
    pub device_error: DeviceError,
}

impl SessionInfo {
    /// True if the session is read/write; false if the
    /// session is read-only
    pub fn rw_session(&self) -> bool {
        self.flags.contains(SessionInfoFlags::RW_SESSION)
    }

    /// This value is provided for backward compatibility,
    /// and should always be set to true
    pub fn serial_session(&self) -> bool {
        self.flags.contains(SessionInfoFlags::SERIAL_SESSION)
    }
}

impl TryFrom<CK_SESSION_INFO> for SessionInfo {
    type Error = Error;

    fn try_from(session_info: CK_SESSION_INFO) -> Result<Self> {
        Ok(Self {
            slot_id: session_info.slotID,
            state: SessionState::try_from(session_info.state)?,
            flags: SessionInfoFlags::from_bits_truncate(session_info.flags),
            device_error: session_info.ulDeviceError,
        })
    }
}

// CK_USER_TYPE

/// Holds the types of Cryptoki users
#[derive(Debug, Copy, Clone)]
pub enum UserType {
    /// Security Officer
    So,
    /// Normal user
    User,
    /// Context Specific
    ContextSpecific,
}

#[doc(hidden)]
impl From<UserType> for CK_USER_TYPE {
    fn from(value: UserType) -> Self {
        match value {
            UserType::So => CKU_SO,
            UserType::User => CKU_USER,
            UserType::ContextSpecific => CKU_CONTEXT_SPECIFIC,
        }
    }
}
