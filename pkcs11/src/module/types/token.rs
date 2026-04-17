use {bitflags::bitflags, std::convert::TryFrom};

use crate::{
    error::{Error, Result},
    module::ck_util::{from_byte_slice_to_num, string_from_blank_padded},
};

use super::general::*;

bitflags! {
    /// Token information flags for [`TokenInfo`].
    #[derive(Debug, Clone)]
    pub struct TokenInfoFlags: CK_FLAGS {
        const RNG = CKF_RNG;
        const WRITE_PROTECTED = CKF_WRITE_PROTECTED;
        const LOGIN_REQUIRED = CKF_LOGIN_REQUIRED;
        const USER_PIN_INITIALIZED = CKF_USER_PIN_INITIALIZED;
        const RESTORE_KEY_NOT_NEEDED = CKF_RESTORE_KEY_NOT_NEEDED;
        const CLOCK_ON_TOKEN = CKF_CLOCK_ON_TOKEN;
        const PROTECTED_AUTHENTICATION_PATH = CKF_PROTECTED_AUTHENTICATION_PATH;
        const DUAL_CRYPTO_OPERATIONS = CKF_DUAL_CRYPTO_OPERATIONS;
        const TOKEN_INITIALIZED = CKF_TOKEN_INITIALIZED;
        const SECONDARY_AUTHENTICATION = CKF_SECONDARY_AUTHENTICATION;
        const USER_PIN_COUNT_LOW = CKF_USER_PIN_COUNT_LOW;
        const USER_PIN_FINAL_TRY = CKF_USER_PIN_FINAL_TRY;
        const USER_PIN_LOCKED = CKF_USER_PIN_LOCKED;
        const USER_PIN_TO_BE_CHANGED = CKF_USER_PIN_TO_BE_CHANGED;
        const SO_PIN_COUNT_LOW = CKF_SO_PIN_COUNT_LOW;
        const SO_PIN_FINAL_TRY = CKF_SO_PIN_FINAL_TRY;
        const SO_PIN_LOCKED = CKF_SO_PIN_LOCKED;
        const SO_PIN_TO_BE_CHANGED = CKF_SO_PIN_TO_BE_CHANGED;
        const ERROR_STATE = CKF_ERROR_STATE;
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UtcTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl UtcTime {
    /// Convert utc time to a iso8601 string representing in the
    /// format YYYY-MM-DDThh:mm:ssTZD.
    pub fn as_iso8601_string(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

pub(crate) fn convert_utc_time(orig: [u8; 16]) -> Result<UtcTime> {
    Ok(UtcTime {
        year: from_byte_slice_to_num!(&orig[0..4])?,
        month: from_byte_slice_to_num!(&orig[4..6])?,
        day: from_byte_slice_to_num!(&orig[6..8])?,
        hour: from_byte_slice_to_num!(&orig[8..10])?,
        minute: from_byte_slice_to_num!(&orig[10..12])?,
        second: from_byte_slice_to_num!(&orig[12..14])?,
        // orig[14..16] are additional reserved ‘0' characters
    })
}

/// Limit on the number of sessions that can be opened with the token.
#[derive(Debug, Clone, Copy)]
pub enum SessionLimit {
    /// An explicit maximum number of sessions.
    Max(u64),
    /// Means that there is no practical limit on the number of sessions
    /// (resp. R/W sessions) an application can have open with the token.
    Infinite,
}

/// Information about a token.
///
/// If the Option fields contains None, this means that
/// the information is not available.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// Application-defined label, assigned during token initialization.
    /// Max length is 32 bytes.
    pub label: String,
    /// ID of the device manufacturer. Max length is 32 bytes.
    pub manufacturer_id: String,
    /// Model of the device. Max length is 16 bytes.
    pub model: String,
    /// Character-string serial number of the device. Max length is 16 bytes.
    pub serial_number: String,
    /// Bit flags indicating capabilities and status of the device.
    pub flags: TokenInfoFlags,
    /// Maximum number of sessions that can be opened with the token at
    /// one time by a single application.
    pub max_session_count: Option<SessionLimit>,
    /// Number of sessions that this application currently has open with the
    /// token.
    pub session_count: Option<u64>,
    /// Maximum number of read/write sessions that can be opened with
    /// the token at one time by a single application.
    pub max_rw_session_count: Option<SessionLimit>,
    /// Number of read/write sessions that this application currently has
    /// open with the token.
    pub rw_session_count: Option<u64>,
    /// Maximum length in bytes of the PIN.
    pub max_pin_len: u64,
    /// Minimum length in bytes of the PIN.
    pub min_pin_len: u64,
    /// The total amount of memory on the token in bytes in which public
    /// objects may be stored.
    pub total_public_memory: Option<u64>,
    /// The amount of free (unused) memory on the token in bytes for public
    /// objects.
    pub free_public_memory: Option<u64>,
    /// The total amount of memory on the token in bytes in which private
    /// objects may be stored.
    pub total_private_memory: Option<u64>,
    /// The amount of free (unused) memory on the token in bytes for
    /// private objects.
    pub free_private_memory: Option<u64>,
    /// Version number of hardware.
    pub hardware_version: Version,
    /// Version number of firmware.
    pub firmware_version: Version,
    /// The value of this field only makes sense for tokens equipped with
    /// a clock, as indicated in the token information flags.
    pub utc_time: Option<UtcTime>,
}

fn maybe_unavailable(value: CK_ULONG) -> Option<u64> {
    match value {
        CK_UNAVAILABLE_INFORMATION => None,
        _ => Some(value),
    }
}

impl SessionLimit {
    fn from_ck_ulong(value: CK_ULONG) -> Option<SessionLimit> {
        match value {
            CK_UNAVAILABLE_INFORMATION => None,
            CK_EFFECTIVELY_INFINITE => Some(SessionLimit::Infinite),
            _ => Some(SessionLimit::Max(value)),
        }
    }
}

impl TokenInfo {
    /// True if the token has its own random number generator.
    pub fn rng(&self) -> bool {
        self.flags.contains(TokenInfoFlags::RNG)
    }

    /// True if the token is write-protected.
    ///
    /// Exactly what this flag means is not specified in Cryptoki.
    /// An application may be unable to perform certain actions on
    /// a write-protected token; these actions can include any of the
    /// following, among others:
    /// * Creating/modifying/deleting any object on the token.
    /// * Creating/modifying/deleting a token object on the token.
    /// * Changing the SO's PIN.
    /// * Changing the normal user's PIN.
    ///
    /// The token may change the value of the [`TokenInfoFlags::WRITE_PROTECTED`]
    /// flag depending on the session state to implement its object management
    /// policy. For instance, the token may set the
    /// [`TokenInfoFlags::WRITE_PROTECTED`] flag unless the session state is
    /// R/W SO or R/W User to implement a policy that does not allow any
    /// objects, public or private, to be created, modified, or deleted unless
    /// the user has successfully called
    /// [`Session::login`](crate::module::session::Session::login).
    pub fn write_protected(&self) -> bool {
        self.flags.contains(TokenInfoFlags::WRITE_PROTECTED)
    }

    /// True if there are some cryptographic functions that a user MUST be
    /// logged in to perform.
    pub fn login_required(&self) -> bool {
        self.flags.contains(TokenInfoFlags::LOGIN_REQUIRED)
    }

    /// True if the normal user's PIN has been initialized.
    pub fn user_pin_initialized(&self) -> bool {
        self.flags.contains(TokenInfoFlags::USER_PIN_INITIALIZED)
    }

    /// True if a successful save of a session's cryptographic operations state
    /// *always* contains all keys needed to restore the state of the session.
    pub fn restore_key_not_needed(&self) -> bool {
        self.flags.contains(TokenInfoFlags::RESTORE_KEY_NOT_NEEDED)
    }

    /// True if the token has its own hardware clock.
    pub fn clock_on_token(&self) -> bool {
        self.flags.contains(TokenInfoFlags::CLOCK_ON_TOKEN)
    }

    /// True if token has a "protected authentication path", whereby a user can
    /// log into the token without passing a PIN through the Cryptoki library.
    pub fn protected_authentication_path(&self) -> bool {
        self.flags
            .contains(TokenInfoFlags::PROTECTED_AUTHENTICATION_PATH)
    }

    /// True if a single session with the token can perform dual cryptographic
    /// operations (see Section 5.12).
    pub fn dual_crypto_operations(&self) -> bool {
        self.flags.contains(TokenInfoFlags::DUAL_CRYPTO_OPERATIONS)
    }

    /// True if the token has been initialized with [`Pkcs11Module::init_token`]
    /// or an equivalent mechanism outside the scope of the PKCS#11 standard.
    /// Calling [`Pkcs11Module::init_token`] when this flag is set will cause
    /// the token to be reinitialized.
    ///
    /// [`Pkcs11Module::init_token`]: crate::module::Pkcs11Module::init_token
    pub fn token_initialized(&self) -> bool {
        self.flags.contains(TokenInfoFlags::TOKEN_INITIALIZED)
    }

    /// True if the token supports secondary authentication for private key
    /// objects. (Deprecated; new implementations MUST NOT set this flag).
    pub fn secondary_authentication(&self) -> bool {
        self.flags
            .contains(TokenInfoFlags::SECONDARY_AUTHENTICATION)
    }

    /// True if an incorrect user login PIN has been entered at least once
    /// since the last successful authentication.
    ///
    /// This flags may always be set to false if the token does not support
    /// the functionality or will not reveal the information because of
    /// its security policy.
    pub fn user_pin_count_low(&self) -> bool {
        self.flags.contains(TokenInfoFlags::USER_PIN_COUNT_LOW)
    }

    /// True if supplying an incorrect user PIN will cause it to become locked.
    ///
    /// This flags may always be set to false if the token does not support the
    /// functionality or will not reveal the information because of its
    /// security policy.
    pub fn user_pin_final_try(&self) -> bool {
        self.flags.contains(TokenInfoFlags::USER_PIN_FINAL_TRY)
    }

    /// True if the user PIN has been locked. User login to the token is not
    /// possible.
    pub fn user_pin_locked(&self) -> bool {
        self.flags.contains(TokenInfoFlags::USER_PIN_LOCKED)
    }

    /// True if the user PIN value is the default value set by token
    /// initialization or manufacturing, or the PIN has been expired
    /// by the card.
    ///
    /// This may be always false if the token either does not support the
    /// functionality.
    ///
    /// If a PIN is set to the default value or has expired, this function
    /// returns `true`. When true, logging in with the corresponding PIN will
    /// succeed, but only the [`Session::set_pin`] function can be called.
    /// Calling any other function that required the user to be logged in will
    /// cause [`PinExpired`] to be returned until [`Session::set_pin`] is
    /// called successfully.
    ///
    /// [`Session::set_pin`]: crate::module::session::Session::set_pin
    /// [`PinExpired`]: crate::error::CryptokiRetVal::PinExpired
    pub fn user_pin_to_be_changed(&self) -> bool {
        self.flags.contains(TokenInfoFlags::USER_PIN_TO_BE_CHANGED)
    }

    /// Same behavior as [`user_pin_count_low`] but for the SO PIN.
    ///
    /// [`user_pin_count_low`]: Self::user_pin_count_low
    pub fn so_pin_count_low(&self) -> bool {
        self.flags.contains(TokenInfoFlags::SO_PIN_COUNT_LOW)
    }

    /// Same behavior as [`user_pin_final_try`] but for the SO PIN.
    ///
    /// [`user_pin_final_try`]: Self::user_pin_final_try
    pub fn so_pin_final_try(&self) -> bool {
        self.flags.contains(TokenInfoFlags::SO_PIN_FINAL_TRY)
    }

    /// True if the SO PIN has been locked. SO login to the token is not
    /// possible.
    pub fn so_pin_locked(&self) -> bool {
        self.flags.contains(TokenInfoFlags::SO_PIN_LOCKED)
    }

    /// Same behavior as [`user_pin_to_be_changed`] but for the SO PIN.
    ///
    /// [`user_pin_to_be_changed`]: Self::user_pin_to_be_changed
    pub fn so_pin_to_be_changed(&self) -> bool {
        self.flags.contains(TokenInfoFlags::SO_PIN_TO_BE_CHANGED)
    }

    /// True if the token failed a FIPS 140-2 self-test and entered an error
    /// state.
    pub fn error_state(&self) -> bool {
        self.flags.contains(TokenInfoFlags::ERROR_STATE)
    }
}

impl TryFrom<CK_TOKEN_INFO> for TokenInfo {
    type Error = Error;

    fn try_from(ck_toke_info: CK_TOKEN_INFO) -> Result<Self> {
        let flags = TokenInfoFlags::from_bits_truncate(ck_toke_info.flags);
        let utc_time = if flags.contains(TokenInfoFlags::CLOCK_ON_TOKEN) {
            Some(convert_utc_time(ck_toke_info.utcTime)?)
        } else {
            None
        };

        Ok(Self {
            label: string_from_blank_padded(&ck_toke_info.label),
            manufacturer_id: string_from_blank_padded(&ck_toke_info.manufacturerID),
            model: string_from_blank_padded(&ck_toke_info.model),
            serial_number: string_from_blank_padded(&ck_toke_info.serialNumber),
            flags,
            max_session_count: SessionLimit::from_ck_ulong(
                ck_toke_info.ulMaxSessionCount,
            ),
            session_count: maybe_unavailable(ck_toke_info.ulSessionCount),
            max_rw_session_count: SessionLimit::from_ck_ulong(
                ck_toke_info.ulMaxRwSessionCount,
            ),
            rw_session_count: maybe_unavailable(ck_toke_info.ulRwSessionCount),
            max_pin_len: ck_toke_info.ulMaxPinLen,
            min_pin_len: ck_toke_info.ulMinPinLen,
            total_public_memory: maybe_unavailable(ck_toke_info.ulTotalPublicMemory),
            free_public_memory: maybe_unavailable(ck_toke_info.ulFreePublicMemory),
            total_private_memory: maybe_unavailable(ck_toke_info.ulTotalPrivateMemory),
            free_private_memory: maybe_unavailable(ck_toke_info.ulFreePrivateMemory),
            hardware_version: ck_toke_info.hardwareVersion.into(),
            firmware_version: ck_toke_info.firmwareVersion.into(),
            utc_time,
        })
    }
}
