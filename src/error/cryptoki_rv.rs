use crate::bindings::*;

use super::Error;

/// Cryptoki function return values.
/// The values are divided into groups. The sequence order is not equal to
/// the 'CKR_*" sequence order defined in the pkcs11 standard.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CryptokiRetVal {
    /*
     * Universal Cryptoki function return values
     *
     * Any Cryptoki function can return any of the below values:
     */

    /// The function executed successfully.
    /// Technically, CKR_OK is not quite a "universal" return value;
    /// in particular, the legacy functions C_GetFunctionStatus and
    /// C_CancelFunction (see Section 5.15) cannot return CKR_OK.
    Ok,

    /// Some horrible, unrecoverable error has occurred. In the worst case,
    /// it is possible that the function only partially succeeded, and that
    /// the computer and/or token is in an inconsistent state.
    GeneralError,

    /// The computer that the Cryptoki library is running on has insufficient
    /// memory to perform the requested function.
    HostMemory,

    /// The requested function could not be performed, but detailed information
    /// about why not is not available in this error return. If the failed
    /// function uses a session, it is possible that the CK_SESSION_INFO
    /// structure that can be obtained by calling C_GetSessionInfo will hold
    /// useful information about what happened in its ulDeviceError field.
    /// In any event, although the function call failed, the situation is not
    /// necessarily totally hopeless, as it is likely to be when
    /// CKR_GENERAL_ERROR is returned. Depending on what the root cause of the
    /// error actually was, it is possible that an attempt to make the exact
    /// same function call again would succeed.
    FunctionFailed,


    /*
     * Cryptoki function return values for functions that use a session handle
     *
     * Any Cryptoki function that takes a session handle as one of its
     * arguments (i.e., any Cryptoki function except for C_Initialize,
     * C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo,
     * C_GetTokenInfo, C_WaitForSlotEvent, C_GetMechanismList,
     * C_GetMechanismInfo, C_InitToken, C_OpenSession, and C_CloseAllSessions)
     * can return the below values:
     */

    /// The specified session handle was invalid at the time that the
    /// function was invoked. Note that this can happen if the session's token
    /// is removed before the function invocation, since removing a token
    /// closes all sessions with it.
    SessionHandleInvalid,

    /// The token was removed from its slot during the execution of the
    /// function.
    DeviceRemoved,

    /// The session was closed during the execution of the function. Note that,
    /// as stated in [`PKCS11-UG`],
    /// the behavior of Cryptoki is undefined if multiple threads of an
    /// application attempt to access a common Cryptoki session simultaneously.
    /// Therefore, there is actually no guarantee that a function invocation
    /// could ever return the value CKR_SESSION_CLOSED. An example of multiple
    /// threads accessing a common session simultaneously is where one thread
    /// is using a session when another thread closes that same session.
    ///
    /// [`PKCS11-UG`]: http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html
    SessionClosed,


    /*
     * Cryptoki function return values for functions that use a token
     *
     * Any Cryptoki function that uses a particular token (i.e., any Cryptoki
     * function except for C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList,
     * C_GetSlotList, C_GetSlotInfo, or C_WaitForSlotEvent) can return any of
     * the below values:
     */

    /// The token does not have sufficient memory to perform the requested
    /// function.
    DeviceMemory,

    /// Some problem has occurred with the token and/or slot. This error code
    /// can be returned by more than just the functions mentioned above;
    /// in particular, it is possible for C_GetSlotInfo to
    /// return CKR_DEVICE_ERROR.
    DeviceError,

    /// The token was not present in its slot at the time that the function was
    /// invoked.
    TokenNotPresent,

    // Defined in above section with functions that use a session handle.
    // DeviceRemoved,


    /*
     * Special return value for application-supplied callbacks
     *
     * There is a special-purpose return value which is not returned by any
     * function in the actual Cryptoki API, but which may be returned by an
     * application-supplied callback function. It is:
     */

    /// When a function executing in serial with an application decides
    /// to give the application a chance to do some work, it calls
    /// an application-supplied function with a CKN_SURRENDER
    /// callback (see Section 5.16). If the callback returns
    /// the value CKR_CANCEL, then the function aborts and
    /// returns CKR_FUNCTION_CANCELED.
    Cancel,


    /*
     * Special return values for mutex-handling functions
     *
     * There are two other special-purpose return values which are not returned
     * by any actual Cryptoki functions. These values may be returned
     * by application-supplied mutex-handling functions, and they may safely
     * be ignored by application developers who are not using their own
     * threading model. They are:
     */

    /// This error code can be returned by mutex-handling functions that are
    /// passed a bad mutex object as an argument. Unfortunately, it is
    /// possible for such a function not to recognize a bad mutex object.
    /// There is therefore no guarantee that such a function will successfully
    /// detect bad mutex objects and return this value.
    MutexBad,

    /// This error code can be returned by mutex-unlocking functions.
    /// It indicates that the mutex supplied to the mutex-unlocking function
    /// was not locked.
    MutexNotLocked,


    /*
     * All other Cryptoki function return values
     *
     * Descriptions of the other Cryptoki function return values follow.
     * Except as mentioned in the descriptions of particular error codes,
     * there are in general no particular priorities among the errors listed
     * below, i.e., if more than one error code might apply to an execution
     * of a function, then the function may return any applicable error code.
     */

    /// This value can only be returned by C_CopyObject, C_SetAttributeValue
    /// and C_DestroyObject. It denotes that the action may not be taken,
    /// either because of underlying policy restrictions on the token, or
    /// because the object has the the relevant CKA_COPYABLE, CKA_MODIFIABLE
    /// or CKA_DESTROYABLE policy attribute set to CK_FALSE.
    ActionProhibited,

    /// This is a rather generic error code which indicates that the arguments
    /// supplied to the Cryptoki function were in some way not appropriate.
    ArgumentsBad,

    /// An attempt was made to set a value for an attribute which may not be
    /// set by the application, or which may not be modified by
    /// the application. See Section 4.1 for more information.
    AttributeReadOnly,

    /// An attempt was made to obtain the value of an attribute of an object
    /// which cannot be satisfied because the object is either sensitive
    /// or un-extractable.
    AttributeSensitive,

    /// An invalid attribute type was specified in a template.
    /// See Section 4.1 for more information.
    AttributeTypeInvalid,

    /// An invalid value was specified for a particular attribute in
    /// a template. See Section 4.1 for more information.
    AttributeValueInvalid,

    /// The output of the function is too large to fit in the supplied buffer.
    BufferTooSmall,

    /// This value can only be returned by C_Initialize. It means that
    /// the type of locking requested by the application for thread-safety
    /// is not available in this library, and so the application cannot
    /// make use of this library in the specified fashion.
    CantLock,

    /// This value can only be returned by C_Initialize. It means that
    /// the Cryptoki library has already been initialized (by a previous
    /// call to C_Initialize which did not have a matching C_Finalize call).
    CryptokiAlreadyInitialized,

    /// This value can be returned by any function other than C_Initialize
    /// and C_GetFunctionList. It indicates that the function
    /// cannot be executed because the Cryptoki library has not yet been
    /// initialized by a call to C_Initialize.
    CryptokiNotInitialized,

    /// This curve is not supported by this token.
    /// Used with Elliptic Curve mechanisms.
    CurveNotSupported,

    /// The plaintext input data to a cryptographic operation is invalid.
    /// This return value has lower priority than CKR_DATA_LEN_RANGE.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    /// Depending on the operation's mechanism, this could mean that
    /// the plaintext data is too short, too long, or is not a multiple of some
    /// particular block size. This return value has higher priority
    /// than CKR_DATA_INVALID.
    DataLenRange,

    /// Invalid or unsupported domain parameters were supplied to the function.
    /// Which representation methods of domain parameters are supported
    /// by a given mechanism can vary from token to token.
    DomainParamsInvalid,

    /// The encrypted input to a decryption operation has been determined
    /// to be invalid ciphertext. This return value has lower priority
    /// than CKR_ENCRYPTED_DATA_LEN_RANGE.
    EncryptedDataInvalid,

    /// The ciphertext input to a decryption operation has been determined
    /// to be invalid ciphertext solely on the basis of its length.
    /// Depending on the operation's mechanism, this could mean that
    /// the ciphertext is too short, too long, or is not a multiple of some
    /// particular block size. This return value has higher priority
    /// than CKR_ENCRYPTED_DATA_INVALID.
    EncryptedDataLenRange,

    /// An iterative algorithm (for key pair generation, domain parameter
    /// generation etc.) failed because we have exceeded the maximum
    /// number of iterations. This error code has precedence
    /// over CKR_FUNCTION_FAILED. Examples of iterative algorithms include
    /// DSA signature generation (retry if either r = 0 or s = 0) and
    /// generation of DSA primes p and q specified in FIPS 186-4.
    ExceededMaxIterations,

    /// A FIPS 140-2 power-up self-test or conditional self-test failed.
    /// The token entered an error state. Future calls to cryptographic
    /// functions on the token will return CKR_GENERAL_ERROR.
    /// CKR_FIPS_SELF_TEST_FAILED has a higher precedence
    /// over CKR_GENERAL_ERROR. This error may be returned by C_Initialize,
    /// if a power-up self-test failed, by C_GenerateRandom or C_SeedRandom,
    /// if the continuous random number generator test failed, or
    /// by C_GenerateKeyPair, if the pair-wise consistency test failed.
    FipsSelfTestFailed,

    /// The function was canceled in mid-execution. This happens to a
    /// cryptographic function if the function makes a CKN_SURRENDER
    /// application callback which returns CKR_CANCEL (see CKR_CANCEL).
    /// It also happens to a function that performs PIN entry through
    /// a protected path. The method used to cancel
    /// a protected path PIN entry operation is device dependent.
    FunctionCanceled,

    /// There is currently no function executing in parallel in the specified
    /// session. This is a legacy error code which is only returned by
    /// the legacy functions C_GetFunctionStatus and C_CancelFunction.
    FunctionNotParallel,

    /// The requested function is not supported by this Cryptoki library.
    /// Even unsupported functions in the Cryptoki API should
    /// have a "stub" in the library; this stub should simply return
    /// the value CKR_FUNCTION_NOT_SUPPORTED.
    FunctionNotSupported,

    /// The signature request is rejected by the user.
    FunctionRejected,

    /// The information requested could not be obtained because the token
    /// considers it sensitive, and is not able or willing to reveal it.
    InformationSensitive,

    /// This value is only returned by C_SetOperationState. It indicates
    /// that one of the keys specified is not the same key that was being used
    /// in the original saved session.
    KeyChanged,

    /// An attempt has been made to use a key for a cryptographic purpose that
    /// the key's attributes are not set to allow it to do. For example, to
    /// use a key for performing encryption, that key MUST have
    /// its CKA_ENCRYPT attribute set to CK_TRUE (the fact that the key MUST
    /// have a CKA_ENCRYPT attribute implies that the key cannot be
    /// a private key). This return value has lower priority
    /// than CKR_KEY_TYPE_INCONSISTENT.
    KeyFunctionNotPermitted,

    /// The specified key handle is not valid. It may be the case that
    /// the specified handle is a valid handle for an object which is not
    /// a key. We reiterate here that 0 is never a valid key handle.
    KeyHandleInvalid,

    /// This error code can only be returned by C_DigestKey. It indicates that
    /// the value of the specified key cannot be digested for some reason
    /// (perhaps the key isn't a secret key, or perhaps the token simply can't
    /// digest this kind of key).
    KeyIndigestible,

    /// This value is only returned by C_SetOperationState. It indicates that
    /// the session state cannot be restored because C_SetOperationState needs
    /// to be supplied with one or more keys that were being used in
    /// the original saved session.
    KeyNeeded,

    /// An extraneous key was supplied to C_SetOperationState. For example,
    /// an attempt was made to restore a session that had been performing
    /// a message digesting operation, and an encryption key was supplied.
    KeyNotNeeded,

    /// Although the specified private or secret key does not have
    /// its CKA_EXTRACTABLE attribute set to CK_FALSE, Cryptoki (or the token)
    /// is unable to wrap the key as requested (possibly the token can only
    /// wrap a given key with certain types of keys, and the wrapping key
    /// specified is not one of these types).
    /// Compare with CKR_KEY_UNEXTRACTABLE.
    KeyNotWrappable,

    /// Although the requested keyed cryptographic operation could in principle
    /// be carried out, this Cryptoki library (or the token) is unable to
    /// actually do it because the supplied key‘s size is outside
    /// the range of key sizes that it can handle.
    KeySizeRange,

    /// The specified key is not the correct type of key to use with
    /// the specified mechanism. This return value has a higher priority
    /// than CKR_KEY_FUNCTION_NOT_PERMITTED.
    KeyTypeInconsistent,

    /// The specified private or secret key can't be wrapped because
    /// its CKA_EXTRACTABLE attribute is set to CK_FALSE.
    /// Compare with CKR_KEY_NOT_WRAPPABLE.
    KeyUnextractable,

    /// The Cryptoki library could not load a dependent shared library.
    LibraryLoadFailed,

    /// An invalid mechanism was specified to the cryptographic operation.
    /// This error code is an appropriate return value if an unknown mechanism
    /// was specified or if the mechanism specified cannot be used in
    /// the selected token with the selected function.
    MechanismInvalid,

    /// Invalid parameters were supplied to the mechanism specified to
    /// the cryptographic operation. Which parameter values are supported
    /// by a given mechanism can vary from token to token.
    MechanismParamInvalid,

    /// This value can only be returned by C_Initialize. It is returned
    /// when two conditions hold:
    /// 1. The application called C_Initialize in a way which tells
    ///    the Cryptoki library that application threads executing calls
    ///    to the library cannot use native operating system methods
    ///    to spawn new threads.
    /// 2. The library cannot function properly without being able
    ///    to spawn new threads in the above fashion.
    NeedToCreateThreads,

    /// This value can only be returned by C_GetSlotEvent. It is returned
    /// when C_GetSlotEvent is called in non-blocking mode and there are no new
    /// slot events to return.
    NoEvent,

    /// The specified object handle is not valid. We reiterate here
    /// that 0 is never a valid object handle.
    ObjectHandleInvalid,

    /// There is already an active operation (or combination of active
    /// operations) which prevents Cryptoki from activating the specified
    /// operation. For example, an active object-searching operation would
    /// prevent Cryptoki from activating an encryption operation
    /// with C_EncryptInit. Or, an active digesting operation and an active
    /// encryption operation would prevent Cryptoki from activating a signature
    /// operation. Or, on a token which doesn't support simultaneous dual
    /// cryptographic operations in a session (see the description of the
    /// CKF_DUAL_CRYPTO_OPERATIONS flag in the CK_TOKEN_INFO structure),
    /// an active signature operation would prevent Cryptoki from
    /// activating an encryption operation.
    OperationActive,

    /// There is no active operation of an appropriate type in the specified
    /// session. For example, an application cannot call C_Encrypt in
    /// a session without having called C_EncryptInit first to activate
    /// an encryption operation.
    OperationNotInitialized,

    /// The specified PIN has expired, and the requested operation cannot
    /// be carried out unless C_SetPIN is called to change the PIN value.
    /// Whether or not the normal user's PIN on a token ever expires varies
    /// from token to token.
    PinExpired,

    /// The specified PIN is incorrect, i.e., does not match the PIN stored
    /// on the token. More generally-- when authentication to the token
    /// involves something other than a PIN-- the attempt to authenticate
    /// the user has failed.
    PinIncorrect,

    /// The specified PIN has invalid characters in it. This return code
    /// only applies to functions which attempt to set a PIN.
    PinInvalid,

    /// The specified PIN is too long or too short. This return code
    /// only applies to functions which attempt to set a PIN.
    PinLenRange,

    /// The specified PIN is "locked", and cannot be used. That is, because
    /// some particular number of failed authentication attempts
    /// has been reached, the token is unwilling to permit further attempts
    /// at authentication. Depending on the token, the specified PIN may or
    /// may not remain locked indefinitely.
    PinLocked,

    /// The specified PIN is too weak so that it could be easy to guess.
    /// If the PIN is too short, CKR_PIN_LEN_RANGE should be returned instead.
    /// This return code only applies to functions which attempt to set a PIN.
    PinTooWeak,

    /// The public key fails a public key validation. For example,
    /// an EC public key fails the public key validation specified
    /// in Section 5.2.2 of ANSI X9.62. This error code may be returned
    /// by C_CreateObject, when the public key is created, or
    /// by C_VerifyInit or C_VerifyRecoverInit, when the public key is used.
    /// It may also be returned by C_DeriveKey, in preference
    /// to CKR_MECHANISM_PARAM_INVALID, if the other party's public key
    /// specified in the mechanism's parameters is invalid.
    PublicKeyInvalid,

    /// This value can be returned by C_SeedRandom and C_GenerateRandom.
    /// It indicates that the specified token doesn't have a random number
    /// generator. This return value has higher priority
    /// than CKR_RANDOM_SEED_NOT_SUPPORTED.
    RandomNoRng,

    /// This value can only be returned by C_SeedRandom. It indicates that
    /// the token's random number generator does not accept seeding from
    /// an application. This return value has lower priority
    /// than CKR_RANDOM_NO_RNG.
    RandomSeedNotSupported,

    /// This value can only be returned by C_SetOperationState. It indicates
    /// that the supplied saved cryptographic operations state is invalid,
    /// and so it cannot be restored to the specified session.
    SavedStateInvalid,

    /// This value can only be returned by C_OpenSession. It indicates
    /// that the attempt to open a session failed, either because the token
    /// has too many sessions already open, or because the token has too many
    /// read/write sessions already open.
    SessionCount,

    /// This value can only be returned by C_InitToken. It indicates that a
    /// session with the token is already open, and so the token
    /// cannot be initialized.
    SessionExists,

    /// The specified token does not support parallel sessions.
    /// This is a legacy error code—in Cryptoki Version 2.01 and up,
    /// no token supports parallel sessions. CKR_SESSION_PARALLEL_NOT_SUPPORTED
    /// can only be returned by C_OpenSession, and it is only returned
    /// when C_OpenSession is called in a particular deprecated way.
    SessionParallelNotSupported,

    /// The specified session was unable to accomplish the desired action
    /// because it is a read-only session. This return value has lower priority
    /// than CKR_TOKEN_WRITE_PROTECTED.
    SessionReadOnly,

    /// A read-only session already exists, and so the SO cannot be logged in.
    SessionReadOnlyExists,

    /// A read/write SO session already exists, and so a read-only
    /// session cannot be opened.
    SessionReadWriteSoExists,

    /// The provided signature/MAC can be seen to be invalid solely on
    /// the basis of its length. This return value has higher priority
    /// than CKR_SIGNATURE_INVALID.
    SignatureLenRange,

    /// The provided signature/MAC is invalid. This return value
    /// has lower priority than CKR_SIGNATURE_LEN_RANGE.
    SignatureInvalid,

    /// The specified slot ID is not valid.
    SlotIdInvalid,

    /// The cryptographic operations state of the specified session cannot
    /// be saved for some reason (possibly the token is simply unable to save
    /// the current state). This return value has lower priority
    /// than CKR_OPERATION_NOT_INITIALIZED.
    StateUnsaveable,

    /// The template specified for creating an object is incomplete, and lacks
    /// some necessary attributes. See Section 4.1 for more information.
    TemplateIncomplete,

    /// The template specified for creating an object has conflicting
    /// attributes. See Section 4.1 for more information.
    TemplateInconsistent,

    /// The Cryptoki library and/or slot does not recognize
    /// the token in the slot.
    TokenNotRecognized,

    /// The requested action could not be performed because the token
    /// is write-protected. This return value has higher priority
    /// than CKR_SESSION_READ_ONLY.
    TokenWriteProtected,

    /// This value can only be returned by C_UnwrapKey. It indicates that
    /// the key handle specified to be used to unwrap another key is not valid.
    UnwrappingKeyHandleInvalid,

    /// This value can only be returned by C_UnwrapKey. It indicates that
    /// although the requested unwrapping operation could
    /// in principle be carried out, this Cryptoki library (or the token) is
    /// unable to actually do it because the supplied key's size is outside
    /// the range of key sizes that it can handle.
    UnwrappingKeySizeRange,

    /// This value can only be returned by C_UnwrapKey. It indicates that
    /// the type of the key specified to unwrap another key is not consistent
    /// with the mechanism specified for unwrapping.
    UnwrappingKeyTypeInconsistent,

    /// This value can only be returned by C_Login. It indicates that
    /// the specified user cannot be logged into the session, because it is
    /// already logged into the session. For example, if an application has
    /// an open SO session, and it attempts to log the SO into it, it will
    /// receive this error code.
    UserAlreadyLoggedIn,

    /// This value can only be returned by C_Login. It indicates that
    /// the specified user cannot be logged into the session, because another
    /// user is already logged into the session. For example, if an application
    /// has an open SO session, and it attempts to log the normal user into it,
    /// it will receive this error code.
    UserAnotherAlreadyLoggedIn,

    /// The desired action cannot be performed because the appropriate
    /// user (or an appropriate user) is not logged in. One example is that
    /// a session cannot be logged out unless it is logged in.
    /// Another example is that a private object cannot be created on a token
    /// unless the session attempting to create it is logged in as
    /// the normal user. A final example is that cryptographic operations on
    /// certain tokens cannot be performed unless the normal user is logged in.
    UserNotLoggedIn,

    /// This value can only be returned by C_Login. It indicates
    /// that the normal user's PIN has not yet been initialized with C_InitPIN.
    UserPinNotInitialized,

    /// An attempt was made to have more distinct users simultaneously logged
    /// into the token than the token and/or library permits. For example,
    /// if some application has an open SO session, and another application
    /// attempts to log the normal user into a session, the attempt may return
    /// this error. It is not required to, however. Only if the simultaneous
    /// distinct users cannot be supported does C_Login have to return
    /// this value. Note that this error code generalizes to
    /// true multi-user tokens.
    UserTooManyTypes,

    /// An invalid value was specified as a CK_USER_TYPE.
    /// Valid types are CKU_SO, CKU_USER, and CKU_CONTEXT_SPECIFIC.
    UserTypeInvalid,

    /// This value can only be returned by C_UnwrapKey. It indicates
    /// that the provided wrapped key is not valid. If a call is
    /// made to C_UnwrapKey to unwrap a particular type of key (i.e., some
    /// particular key type is specified in the template
    /// provided to C_UnwrapKey), and the wrapped key provided to C_UnwrapKey
    /// is recognizably not a wrapped key of the proper type, then C_UnwrapKey
    /// should return CKR_WRAPPED_KEY_INVALID. This return value
    /// has lower priority than CKR_WRAPPED_KEY_LEN_RANGE.
    WrappedKeyInvalid,

    /// This value can only be returned by C_UnwrapKey. It indicates that
    /// the provided wrapped key can be seen to be invalid solely on
    /// the basis of its length. This return value has higher priority
    /// than CKR_WRAPPED_KEY_INVALID.
    WrappedKeyLenRange,

    /// This value can only be returned by C_WrapKey. It indicates that
    /// the key handle specified to be used to wrap another key is not valid.
    WrappingKeyHandleInvalid,

    /// This value can only be returned by C_WrapKey. It indicates
    /// that although the requested wrapping operation could in principle
    /// be carried out, this Cryptoki library (or the token) is unable
    /// to actually do it because the supplied wrapping key's size is outside
    /// the range of key sizes that it can handle.
    WrappingKeySizeRange,

    /// This value can only be returned by C_WrapKey. It indicates that
    /// the type of the key specified to wrap another key is not consistent
    /// with the mechanism specified for wrapping.
    WrappingKeyTypeInconsistent,

    /// The supplied OTP was not accepted and the library requests a new OTP
    /// computed using a new PIN. The new PIN is set through means
    /// out of scope for this document.
    NewPinMode,

    /// The supplied OTP was correct but indicated a larger than normal drift
    /// in the token's internal state (e.g. clock, counter). To ensure
    /// this was not due to a temporary problem, the application should provide
    /// the next one-time password to the library for verification.
    NextOtp,

    /// This value are permanently reserved for token vendors.
    /// For interoperability, vendors should register their return values
    /// through the PKCS process.
    VendorDefined(CK_RV),

    /// Undefine value.
    Undefined(CK_RV),
}

impl std::fmt::Display for CryptokiRetVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptokiRetVal::Ok => write!(f, "Identifier: {self:?}. Description: The function executed successfully."),
            CryptokiRetVal::GeneralError => write!(f, "Identifier: {self:?}. Description: Some horrible, unrecoverable error has occurred. In the worst case, it is possible that the function only partially succeeded, and that the computer and/or token is in an inconsistent state."),
            CryptokiRetVal::HostMemory => write!(f, "Identifier: {self:?}. Description: The computer that the Cryptoki library is running on has insufficient memory to perform the requested function."),
            CryptokiRetVal::FunctionFailed => write!(f, "Identifier: {self:?}. Description: The requested function could not be performed, but detailed information about why not is not available in this error return. If the failed function uses a session, it is possible that the CK_SESSION_INFO structure that can be obtained by calling C_GetSessionInfo will hold useful information about what happened in its ulDeviceError field. In any event, although the function call failed, the situation is not necessarily totally hopeless, as it is likely to be when CKR_GENERAL_ERROR is returned. Depending on what the root cause of the error actually was, it is possible that an attempt to make the exact same function call again would succeed."),
            CryptokiRetVal::SessionHandleInvalid => write!(f, "Identifier: {self:?}. Description: The specified session handle was invalid at the time that the function was invoked. Note that this can happen if the session's token is removed before the function invocation, since removing a token closes all sessions with it."),
            CryptokiRetVal::DeviceRemoved => write!(f, "Identifier: {self:?}. Description: The token was removed from its slot during the execution of the function."),
            CryptokiRetVal::SessionClosed => write!(f, "Identifier: {self:?}. Description: The session was closed during the execution of the function. Note that, as stated in [PKCS11-UG], the behavior of Cryptoki is undefined if multiple threads of an application attempt to access a common Cryptoki session simultaneously. Therefore, there is actually no guarantee that a function invocation could ever return the value CKR_SESSION_CLOSED. An example of multiple threads accessing a common session simultaneously is where one thread is using a session when another thread closes that same session."),
            CryptokiRetVal::DeviceMemory => write!(f, "Identifier: {self:?}. Description: The token does not have sufficient memory to perform the requested function."),
            CryptokiRetVal::DeviceError => write!(f, "Identifier: {self:?}. Description: Some problem has occurred with the token and/or slot. This error code can be returned by more than just the functions mentioned above; in particular, it is possible for C_GetSlotInfo to return CKR_DEVICE_ERROR."),
            CryptokiRetVal::TokenNotPresent => write!(f, "Identifier: {self:?}. Description: The token was not present in its slot at the time that the function was invoked."),
            CryptokiRetVal::Cancel => write!(f, "Identifier: {self:?}. Description: When a function executing in serial with an application decides to give the application a chance to do some work, it calls an application-supplied function with a CKN_SURRENDER callback (see Section 5.16). If the callback returns the value CKR_CANCEL, then the function aborts and returns CKR_FUNCTION_CANCELED."),
            CryptokiRetVal::MutexBad => write!(f, "Identifier: {self:?}. Description: This error code can be returned by mutex-handling functions that are passed a bad mutex object as an argument. Unfortunately, it is possible for such a function not to recognize a bad mutex object. There is therefore no guarantee that such a function will successfully detect bad mutex objects and return this value."),
            CryptokiRetVal::MutexNotLocked => write!(f, "Identifier: {self:?}. Description: This error code can be returned by mutex-unlocking functions. It indicates that the mutex supplied to the mutex-unlocking function was not locked."),
            CryptokiRetVal::ActionProhibited => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_CopyObject, C_SetAttributeValue and C_DestroyObject. It denotes that the action may not be taken, either because of underlying policy restrictions on the token, or because the object has the the relevant CKA_COPYABLE, CKA_MODIFIABLE or CKA_DESTROYABLE policy attribute set to CK_FALSE."),
            CryptokiRetVal::ArgumentsBad => write!(f, "Identifier: {self:?}. Description: This is a rather generic error code which indicates that the arguments supplied to the Cryptoki function were in some way not appropriate."),
            CryptokiRetVal::AttributeReadOnly => write!(f, "Identifier: {self:?}. Description: An attempt was made to set a value for an attribute which may not be set by the application, or which may not be modified by the application. See Section 4.1 for more information."),
            CryptokiRetVal::AttributeSensitive => write!(f, "Identifier: {self:?}. Description: An attempt was made to obtain the value of an attribute of an object which cannot be satisfied because the object is either sensitive or un-extractable."),
            CryptokiRetVal::AttributeTypeInvalid => write!(f, "Identifier: {self:?}. Description: An invalid attribute type was specified in a template. See Section 4.1 for more information."),
            CryptokiRetVal::AttributeValueInvalid => write!(f, "Identifier: {self:?}. Description: An invalid value was specified for a particular attribute in a template. See Section 4.1 for more information."),
            CryptokiRetVal::BufferTooSmall => write!(f, "Identifier: {self:?}. Description: The output of the function is too large to fit in the supplied buffer."),
            CryptokiRetVal::CantLock => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Initialize. It means that the type of locking requested by the application for thread-safety is not available in this library, and so the application cannot make use of this library in the specified fashion."),
            CryptokiRetVal::CryptokiAlreadyInitialized => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Initialize. It means that the Cryptoki library has already been initialized (by a previous call to C_Initialize which did not have a matching C_Finalize call)."),
            CryptokiRetVal::CryptokiNotInitialized => write!(f, "Identifier: {self:?}. Description: This value can be returned by any function other than C_Initialize and C_GetFunctionList. It indicates that the function cannot be executed because the Cryptoki library has not yet been initialized by a call to C_Initialize."),
            CryptokiRetVal::CurveNotSupported => write!(f, "Identifier: {self:?}. Description: This curve is not supported by this token. Used with Elliptic Curve mechanisms."),
            CryptokiRetVal::DataInvalid => write!(f, "Identifier: {self:?}. Description: The plaintext input data to a cryptographic operation is invalid. This return value has lower priority than CKR_DATA_LEN_RANGE."),
            CryptokiRetVal::DataLenRange => write!(f, "Identifier: {self:?}. Description: The plaintext input data to a cryptographic operation has a bad length. Depending on the operation's mechanism, this could mean that the plaintext data is too short, too long, or is not a multiple of some particular block size. This return value has higher priority than CKR_DATA_INVALID."),
            CryptokiRetVal::DomainParamsInvalid => write!(f, "Identifier: {self:?}. Description: Invalid or unsupported domain parameters were supplied to the function. Which representation methods of domain parameters are supported by a given mechanism can vary from token to token."),
            CryptokiRetVal::EncryptedDataInvalid => write!(f, "Identifier: {self:?}. Description: The encrypted input to a decryption operation has been determined to be invalid ciphertext. This return value has lower priority than CKR_ENCRYPTED_DATA_LEN_RANGE."),
            CryptokiRetVal::EncryptedDataLenRange => write!(f, "Identifier: {self:?}. Description: The ciphertext input to a decryption operation has been determined to be invalid ciphertext solely on the basis of its length. Depending on the operation's mechanism, this could mean that the ciphertext is too short, too long, or is not a multiple of some particular block size. This return value has higher priority than CKR_ENCRYPTED_DATA_INVALID."),
            CryptokiRetVal::ExceededMaxIterations => write!(f, "Identifier: {self:?}. Description: An iterative algorithm (for key pair generation, domain parameter generation etc.) failed because we have exceeded the maximum number of iterations. This error code has precedence over CKR_FUNCTION_FAILED. Examples of iterative algorithms include DSA signature generation (retry if either r = 0 or s = 0) and generation of DSA primes p and q specified in FIPS 186-4."),
            CryptokiRetVal::FipsSelfTestFailed => write!(f, "Identifier: {self:?}. Description: A FIPS 140-2 power-up self-test or conditional self-test failed. The token entered an error state. Future calls to cryptographic functions on the token will return CKR_GENERAL_ERROR. CKR_FIPS_SELF_TEST_FAILED has a higher precedence over CKR_GENERAL_ERROR. This error may be returned by C_Initialize, if a power-up self-test failed, by C_GenerateRandom or C_SeedRandom, if the continuous random number generator test failed, or by C_GenerateKeyPair, if the pair-wise consistency test failed."),
            CryptokiRetVal::FunctionCanceled => write!(f, "Identifier: {self:?}. Description: The function was canceled in mid-execution. This happens to a cryptographic function if the function makes a CKN_SURRENDER application callback which returns CKR_CANCEL (see CKR_CANCEL). It also happens to a function that performs PIN entry through a protected path. The method used to cancel a protected path PIN entry operation is device dependent."),
            CryptokiRetVal::FunctionNotParallel => write!(f, "Identifier: {self:?}. Description: There is currently no function executing in parallel in the specified session. This is a legacy error code which is only returned by the legacy functions C_GetFunctionStatus and C_CancelFunction."),
            CryptokiRetVal::FunctionNotSupported => write!(f, "Identifier: {self:?}. Description: The requested function is not supported by this Cryptoki library. Even unsupported functions in the Cryptoki API should have a \"stub\" in the library; this stub should simply return the value CKR_FUNCTION_NOT_SUPPORTED."),
            CryptokiRetVal::FunctionRejected => write!(f, "Identifier: {self:?}. Description: The signature request is rejected by the user."),
            CryptokiRetVal::InformationSensitive => write!(f, "Identifier: {self:?}. Description: The information requested could not be obtained because the token considers it sensitive, and is not able or willing to reveal it."),
            CryptokiRetVal::KeyChanged => write!(f, "Identifier: {self:?}. Description: This value is only returned by C_SetOperationState. It indicates that one of the keys specified is not the same key that was being used in the original saved session."),
            CryptokiRetVal::KeyFunctionNotPermitted => write!(f, "Identifier: {self:?}. Description: An attempt has been made to use a key for a cryptographic purpose that the key's attributes are not set to allow it to do. For example, to use a key for performing encryption, that key MUST have its CKA_ENCRYPT attribute set to CK_TRUE (the fact that the key MUST have a CKA_ENCRYPT attribute implies that the key cannot be a private key). This return value has lower priority than CKR_KEY_TYPE_INCONSISTENT."),
            CryptokiRetVal::KeyHandleInvalid => write!(f, "Identifier: {self:?}. Description: The specified key handle is not valid. It may be the case that the specified handle is a valid handle for an object which is not a key. We reiterate here that 0 is never a valid key handle."),
            CryptokiRetVal::KeyIndigestible => write!(f, "Identifier: {self:?}. Description: This error code can only be returned by C_DigestKey. It indicates that the value of the specified key cannot be digested for some reason (perhaps the key isn't a secret key, or perhaps the token simply can't digest this kind of key)."),
            CryptokiRetVal::KeyNeeded => write!(f, "Identifier: {self:?}. Description: This value is only returned by C_SetOperationState. It indicates that the session state cannot be restored because C_SetOperationState needs to be supplied with one or more keys that were being used in the original saved session."),
            CryptokiRetVal::KeyNotNeeded => write!(f, "Identifier: {self:?}. Description: An extraneous key was supplied to C_SetOperationState. For example, an attempt was made to restore a session that had been performing a message digesting operation, and an encryption key was supplied."),
            CryptokiRetVal::KeyNotWrappable => write!(f, "Identifier: {self:?}. Description: Although the specified private or secret key does not have its CKA_EXTRACTABLE attribute set to CK_FALSE, Cryptoki (or the token) is unable to wrap the key as requested (possibly the token can only wrap a given key with certain types of keys, and the wrapping key specified is not one of these types). Compare with CKR_KEY_UNEXTRACTABLE."),
            CryptokiRetVal::KeySizeRange => write!(f, "Identifier: {self:?}. Description: Although the requested keyed cryptographic operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key‘s size is outside the range of key sizes that it can handle."),
            CryptokiRetVal::KeyTypeInconsistent => write!(f, "Identifier: {self:?}. Description: The specified key is not the correct type of key to use with the specified mechanism. This return value has a higher priority than CKR_KEY_FUNCTION_NOT_PERMITTED."),
            CryptokiRetVal::KeyUnextractable => write!(f, "Identifier: {self:?}. Description: The specified private or secret key can't be wrapped because its CKA_EXTRACTABLE attribute is set to CK_FALSE. Compare with CKR_KEY_NOT_WRAPPABLE."),
            CryptokiRetVal::LibraryLoadFailed => write!(f, "Identifier: {self:?}. Description: The Cryptoki library could not load a dependent shared library."),
            CryptokiRetVal::MechanismInvalid => write!(f, "Identifier: {self:?}. Description: An invalid mechanism was specified to the cryptographic operation. This error code is an appropriate return value if an unknown mechanism was specified or if the mechanism specified cannot be used in the selected token with the selected function."),
            CryptokiRetVal::MechanismParamInvalid => write!(f, "Identifier: {self:?}. Description: Invalid parameters were supplied to the mechanism specified to the cryptographic operation. Which parameter values are supported by a given mechanism can vary from token to token."),
            CryptokiRetVal::NeedToCreateThreads => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Initialize. It is returned when two conditions hold: 1. The application called C_Initialize in a way which tells the Cryptoki library that application threads executing calls to the library cannot use native operating system methods to spawn new threads. 2. The library cannot function properly without being able to spawn new threads in the above fashion."),
            CryptokiRetVal::NoEvent => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_GetSlotEvent. It is returned when C_GetSlotEvent is called in non-blocking mode and there are no new slot events to return."),
            CryptokiRetVal::ObjectHandleInvalid => write!(f, "Identifier: {self:?}. Description: The specified object handle is not valid. We reiterate here that 0 is never a valid object handle."),
            CryptokiRetVal::OperationActive => write!(f, "Identifier: {self:?}. Description: There is already an active operation (or combination of active operations) which prevents Cryptoki from activating the specified operation. For example, an active object-searching operation would prevent Cryptoki from activating an encryption operation with C_EncryptInit. Or, an active digesting operation and an active encryption operation would prevent Cryptoki from activating a signature operation. Or, on a token which doesn't support simultaneous dual cryptographic operations in a session (see the description of the CKF_DUAL_CRYPTO_OPERATIONS flag in the CK_TOKEN_INFO structure), an active signature operation would prevent Cryptoki from activating an encryption operation."),
            CryptokiRetVal::OperationNotInitialized => write!(f, "Identifier: {self:?}. Description: There is no active operation of an appropriate type in the specified session. For example, an application cannot call C_Encrypt in a session without having called C_EncryptInit first to activate an encryption operation."),
            CryptokiRetVal::PinExpired => write!(f, "Identifier: {self:?}. Description: The specified PIN has expired, and the requested operation cannot be carried out unless C_SetPIN is called to change the PIN value. Whether or not the normal user's PIN on a token ever expires varies from token to token."),
            CryptokiRetVal::PinIncorrect => write!(f, "Identifier: {self:?}. Description: The specified PIN is incorrect, i.e., does not match the PIN stored on the token. More generally-- when authentication to the token involves something other than a PIN-- the attempt to authenticate the user has failed."),
            CryptokiRetVal::PinInvalid => write!(f, "Identifier: {self:?}. Description: The specified PIN has invalid characters in it. This return code only applies to functions which attempt to set a PIN."),
            CryptokiRetVal::PinLenRange => write!(f, "Identifier: {self:?}. Description: The specified PIN is too long or too short. This return code only applies to functions which attempt to set a PIN."),
            CryptokiRetVal::PinLocked => write!(f, "Identifier: {self:?}. Description: The specified PIN is \"locked\", and cannot be used. That is, because some particular number of failed authentication attempts has been reached, the token is unwilling to permit further attempts at authentication. Depending on the token, the specified PIN may or may not remain locked indefinitely."),
            CryptokiRetVal::PinTooWeak => write!(f, "Identifier: {self:?}. Description: The specified PIN is too weak so that it could be easy to guess. If the PIN is too short, CKR_PIN_LEN_RANGE should be returned instead. This return code only applies to functions which attempt to set a PIN."),
            CryptokiRetVal::PublicKeyInvalid => write!(f, "Identifier: {self:?}. Description: The public key fails a public key validation. For example, an EC public key fails the public key validation specified in Section 5.2.2 of ANSI X9.62. This error code may be returned by C_CreateObject, when the public key is created, or by C_VerifyInit or C_VerifyRecoverInit, when the public key is used.  It may also be returned by C_DeriveKey, in preference to  CKR_MECHANISM_PARAM_INVALID, if the other party's public key specified in the mechanism's parameters is invalid."),
            CryptokiRetVal::RandomNoRng => write!(f, "Identifier: {self:?}. Description: This value can be returned by C_SeedRandom and C_GenerateRandom. It indicates that the specified token doesn't have a random number generator. This return value has higher priority than CKR_RANDOM_SEED_NOT_SUPPORTED."),
            CryptokiRetVal::RandomSeedNotSupported => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_SeedRandom. It indicates that the token's random number generator does not accept seeding from an application. This return value has lower priority than CKR_RANDOM_NO_RNG."),
            CryptokiRetVal::SavedStateInvalid => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_SetOperationState. It indicates that the supplied saved cryptographic operations state is invalid, and so it cannot be restored to the specified session."),
            CryptokiRetVal::SessionCount => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_OpenSession. It indicates that the attempt to open a session failed, either because the token has too many sessions already open, or because the token has too many read/write sessions already open."),
            CryptokiRetVal::SessionExists => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_InitToken. It indicates that a session with the token is already open, and so the token cannot be initialized."),
            CryptokiRetVal::SessionParallelNotSupported => write!(f, "Identifier: {self:?}. Description: The specified token does not support parallel sessions. This is a legacy error code—in Cryptoki Version 2.01 and up, no token supports parallel sessions. CKR_SESSION_PARALLEL_NOT_SUPPORTED can only be returned by C_OpenSession, and it is only returned when C_OpenSession is called in a particular [deprecated] way."),
            CryptokiRetVal::SessionReadOnly => write!(f, "Identifier: {self:?}. Description: The specified session was unable to accomplish the desired action because it is a read-only session. This return value has lower priority than CKR_TOKEN_WRITE_PROTECTED."),
            CryptokiRetVal::SessionReadOnlyExists => write!(f, "Identifier: {self:?}. Description: A read-only session already exists, and so the SO cannot be logged in."),
            CryptokiRetVal::SessionReadWriteSoExists => write!(f, "Identifier: {self:?}. Description: A read/write SO session already exists, and so a read-only session cannot be opened."),
            CryptokiRetVal::SignatureLenRange => write!(f, "Identifier: {self:?}. Description: The provided signature/MAC can be seen to be invalid solely on the basis of its length. This return value has higher priority than CKR_SIGNATURE_INVALID."),
            CryptokiRetVal::SignatureInvalid => write!(f, "Identifier: {self:?}. Description: The provided signature/MAC is invalid. This return value has lower priority than CKR_SIGNATURE_LEN_RANGE."),
            CryptokiRetVal::SlotIdInvalid => write!(f, "Identifier: {self:?}. Description: The specified slot ID is not valid."),
            CryptokiRetVal::StateUnsaveable => write!(f, "Identifier: {self:?}. Description: The cryptographic operations state of the specified session cannot be saved for some reason (possibly the token is simply unable to save the current state). This return value has lower priority than CKR_OPERATION_NOT_INITIALIZED."),
            CryptokiRetVal::TemplateIncomplete => write!(f, "Identifier: {self:?}. Description: The template specified for creating an object is incomplete, and lacks some necessary attributes. See Section 4.1 for more information."),
            CryptokiRetVal::TemplateInconsistent => write!(f, "Identifier: {self:?}. Description: The template specified for creating an object has conflicting attributes. See Section 4.1 for more information."),
            CryptokiRetVal::TokenNotRecognized => write!(f, "Identifier: {self:?}. Description: The Cryptoki library and/or slot does not recognize the token in the slot."),
            CryptokiRetVal::TokenWriteProtected => write!(f, "Identifier: {self:?}. Description: The requested action could not be performed because the token is write-protected. This return value has higher priority than CKR_SESSION_READ_ONLY."),
            CryptokiRetVal::UnwrappingKeyHandleInvalid => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_UnwrapKey. It indicates that the key handle specified to be used to unwrap another key is not valid."),
            CryptokiRetVal::UnwrappingKeySizeRange => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_UnwrapKey. It indicates that although the requested unwrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key's size is outside the range of key sizes that it can handle."),
            CryptokiRetVal::UnwrappingKeyTypeInconsistent => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_UnwrapKey. It indicates that the type of the key specified to unwrap another key is not consistent with the mechanism specified for unwrapping."),
            CryptokiRetVal::UserAlreadyLoggedIn => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Login. It indicates that the specified user cannot be logged into the session, because it is already logged into the session. For example, if an application has an open SO session, and it attempts to log the SO into it, it will receive this error code."),
            CryptokiRetVal::UserAnotherAlreadyLoggedIn => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Login. It indicates that the specified user cannot be logged into the session, because another user is already logged into the session. For example, if an application has an open SO session, and it attempts to log the normal user into it, it will receive this error code."),
            CryptokiRetVal::UserNotLoggedIn => write!(f, "Identifier: {self:?}. Description: The desired action cannot be performed because the appropriate user (or an appropriate user) is not logged in. One example is that a session cannot be logged out unless it is logged in. Another example is that a private object cannot be created on a token unless the session attempting to create it is logged in as the normal user. A final example is that cryptographic operations on certain tokens cannot be performed unless the normal user is logged in."),
            CryptokiRetVal::UserPinNotInitialized => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_Login. It indicates that the normal user's PIN has not yet been initialized with C_InitPIN."),
            CryptokiRetVal::UserTooManyTypes => write!(f, "Identifier: {self:?}. Description: An attempt was made to have more distinct users simultaneously logged into the token than the token and/or library permits. For example, if some application has an open SO session, and another application attempts to log the normal user into a session, the attempt may return this error. It is not required to, however. Only if the simultaneous distinct users cannot be supported does C_Login have to return this value. Note that this error code generalizes to true multi-user tokens."),
            CryptokiRetVal::UserTypeInvalid => write!(f, "Identifier: {self:?}. Description: An invalid value was specified as a CK_USER_TYPE. Valid types are CKU_SO, CKU_USER, and CKU_CONTEXT_SPECIFIC."),
            CryptokiRetVal::WrappedKeyInvalid => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_UnwrapKey. It indicates that the provided wrapped key is not valid. If a call is made to C_UnwrapKey to unwrap a particular type of key (i.e., some particular key type is specified in the template provided to C_UnwrapKey), and the wrapped key provided to C_UnwrapKey is recognizably not a wrapped key of the proper type, then C_UnwrapKey should return CKR_WRAPPED_KEY_INVALID. This return value has lower priority than CKR_WRAPPED_KEY_LEN_RANGE."),
            CryptokiRetVal::WrappedKeyLenRange => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_UnwrapKey. It indicates that the provided wrapped key can be seen to be invalid solely on the basis of its length. This return value has higher priority than CKR_WRAPPED_KEY_INVALID."),
            CryptokiRetVal::WrappingKeyHandleInvalid => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_WrapKey. It indicates that the key handle specified to be used to wrap another key is not valid."),
            CryptokiRetVal::WrappingKeySizeRange => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_WrapKey. It indicates that although the requested wrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied wrapping key's size is outside the range of key sizes that it can handle."),
            CryptokiRetVal::WrappingKeyTypeInconsistent => write!(f, "Identifier: {self:?}. Description: This value can only be returned by C_WrapKey. It indicates that the type of the key specified to wrap another key is not consistent with the mechanism specified for wrapping."),
            CryptokiRetVal::NewPinMode => write!(f, "Identifier: {self:?}. Description: The supplied OTP was not accepted and the library requests a new OTP computed using a new PIN. The new PIN is set through means out of scope for this document."),
            CryptokiRetVal::NextOtp => write!(f, "Identifier: {self:?}. Description: The supplied OTP was correct but indicated a larger than normal drift in the token's internal state (e.g. clock, counter). To ensure this was not due to a temporary problem, the application should provide the next one-time password to the library for verification."),
            CryptokiRetVal::VendorDefined(v) => write!(f, "Identifier: VendorDefined({v:#X}). Description: This value are permanently reserved for token vendors. For interoperability, vendors should register their return values through the PKCS process"),
            CryptokiRetVal::Undefined(v) => write!(f, "Identifier: Undefined({v:#X}). Description: Undefined value."),
        }
    }
}

impl From<CK_RV> for CryptokiRetVal {
    fn from(ck_rv: CK_RV) -> Self {
        match ck_rv {
            CKR_OK => CryptokiRetVal::Ok,
            CKR_CANCEL => CryptokiRetVal::Cancel,
            CKR_HOST_MEMORY => CryptokiRetVal::HostMemory,
            CKR_SLOT_ID_INVALID => CryptokiRetVal::SlotIdInvalid,
            CKR_GENERAL_ERROR => CryptokiRetVal::GeneralError,
            CKR_FUNCTION_FAILED => CryptokiRetVal::FunctionFailed,
            CKR_ARGUMENTS_BAD => CryptokiRetVal::ArgumentsBad,
            CKR_NO_EVENT => CryptokiRetVal::NoEvent,
            CKR_NEED_TO_CREATE_THREADS => CryptokiRetVal::NeedToCreateThreads,
            CKR_CANT_LOCK => CryptokiRetVal::CantLock,
            CKR_ATTRIBUTE_READ_ONLY => CryptokiRetVal::AttributeReadOnly,
            CKR_ATTRIBUTE_SENSITIVE => CryptokiRetVal::AttributeSensitive,
            CKR_ATTRIBUTE_TYPE_INVALID => CryptokiRetVal::AttributeTypeInvalid,
            CKR_ATTRIBUTE_VALUE_INVALID => CryptokiRetVal::AttributeValueInvalid,
            CKR_ACTION_PROHIBITED => CryptokiRetVal::ActionProhibited,
            CKR_DATA_INVALID => CryptokiRetVal::DataInvalid,
            CKR_DATA_LEN_RANGE => CryptokiRetVal::DataLenRange,
            CKR_DEVICE_ERROR => CryptokiRetVal::DeviceError,
            CKR_DEVICE_MEMORY => CryptokiRetVal::DeviceMemory,
            CKR_DEVICE_REMOVED => CryptokiRetVal::DeviceRemoved,
            CKR_ENCRYPTED_DATA_INVALID => CryptokiRetVal::EncryptedDataInvalid,
            CKR_ENCRYPTED_DATA_LEN_RANGE => CryptokiRetVal::EncryptedDataLenRange,
            CKR_FUNCTION_CANCELED => CryptokiRetVal::FunctionCanceled,
            CKR_FUNCTION_NOT_PARALLEL => CryptokiRetVal::FunctionNotParallel,
            CKR_FUNCTION_NOT_SUPPORTED => CryptokiRetVal::FunctionNotSupported,
            CKR_KEY_HANDLE_INVALID => CryptokiRetVal::KeyHandleInvalid,
            CKR_KEY_SIZE_RANGE => CryptokiRetVal::KeySizeRange,
            CKR_KEY_TYPE_INCONSISTENT => CryptokiRetVal::KeyTypeInconsistent,
            CKR_KEY_NOT_NEEDED => CryptokiRetVal::KeyNotNeeded,
            CKR_KEY_CHANGED => CryptokiRetVal::KeyChanged,
            CKR_KEY_NEEDED => CryptokiRetVal::KeyNeeded,
            CKR_KEY_INDIGESTIBLE => CryptokiRetVal::KeyIndigestible,
            CKR_KEY_FUNCTION_NOT_PERMITTED => CryptokiRetVal::KeyFunctionNotPermitted,
            CKR_KEY_NOT_WRAPPABLE => CryptokiRetVal::KeyNotWrappable,
            CKR_KEY_UNEXTRACTABLE => CryptokiRetVal::KeyUnextractable,
            CKR_MECHANISM_INVALID => CryptokiRetVal::MechanismInvalid,
            CKR_MECHANISM_PARAM_INVALID => CryptokiRetVal::MechanismParamInvalid,
            CKR_OBJECT_HANDLE_INVALID => CryptokiRetVal::ObjectHandleInvalid,
            CKR_OPERATION_ACTIVE => CryptokiRetVal::OperationActive,
            CKR_OPERATION_NOT_INITIALIZED => CryptokiRetVal::OperationNotInitialized,
            CKR_PIN_INCORRECT => CryptokiRetVal::PinIncorrect,
            CKR_PIN_INVALID => CryptokiRetVal::PinInvalid,
            CKR_PIN_LEN_RANGE => CryptokiRetVal::PinLenRange,
            CKR_PIN_EXPIRED => CryptokiRetVal::PinExpired,
            CKR_PIN_LOCKED => CryptokiRetVal::PinLocked,
            CKR_SESSION_CLOSED => CryptokiRetVal::SessionClosed,
            CKR_SESSION_COUNT => CryptokiRetVal::SessionCount,
            CKR_SESSION_HANDLE_INVALID => CryptokiRetVal::SessionHandleInvalid,
            CKR_SESSION_PARALLEL_NOT_SUPPORTED => CryptokiRetVal::SessionParallelNotSupported,
            CKR_SESSION_READ_ONLY => CryptokiRetVal::SessionReadOnly,
            CKR_SESSION_EXISTS => CryptokiRetVal::SessionExists,
            CKR_SESSION_READ_ONLY_EXISTS => CryptokiRetVal::SessionReadOnlyExists,
            CKR_SESSION_READ_WRITE_SO_EXISTS => CryptokiRetVal::SessionReadWriteSoExists,
            CKR_SIGNATURE_INVALID => CryptokiRetVal::SignatureInvalid,
            CKR_SIGNATURE_LEN_RANGE => CryptokiRetVal::SignatureLenRange,
            CKR_TEMPLATE_INCOMPLETE => CryptokiRetVal::TemplateIncomplete,
            CKR_TEMPLATE_INCONSISTENT => CryptokiRetVal::TemplateInconsistent,
            CKR_TOKEN_NOT_PRESENT => CryptokiRetVal::TokenNotPresent,
            CKR_TOKEN_NOT_RECOGNIZED => CryptokiRetVal::TokenNotRecognized,
            CKR_TOKEN_WRITE_PROTECTED => CryptokiRetVal::TokenWriteProtected,
            CKR_UNWRAPPING_KEY_HANDLE_INVALID => CryptokiRetVal::UnwrappingKeyHandleInvalid,
            CKR_UNWRAPPING_KEY_SIZE_RANGE => CryptokiRetVal::UnwrappingKeySizeRange,
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => CryptokiRetVal::UnwrappingKeyTypeInconsistent,
            CKR_USER_ALREADY_LOGGED_IN => CryptokiRetVal::UserAlreadyLoggedIn,
            CKR_USER_NOT_LOGGED_IN => CryptokiRetVal::UserNotLoggedIn,
            CKR_USER_PIN_NOT_INITIALIZED => CryptokiRetVal::UserPinNotInitialized,
            CKR_USER_TYPE_INVALID => CryptokiRetVal::UserTypeInvalid,
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN => CryptokiRetVal::UserAnotherAlreadyLoggedIn,
            CKR_USER_TOO_MANY_TYPES => CryptokiRetVal::UserTooManyTypes,
            CKR_WRAPPED_KEY_INVALID => CryptokiRetVal::WrappedKeyInvalid,
            CKR_WRAPPED_KEY_LEN_RANGE => CryptokiRetVal::WrappedKeyLenRange,
            CKR_WRAPPING_KEY_HANDLE_INVALID => CryptokiRetVal::WrappingKeyHandleInvalid,
            CKR_WRAPPING_KEY_SIZE_RANGE => CryptokiRetVal::WrappingKeySizeRange,
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT => CryptokiRetVal::WrappingKeyTypeInconsistent,
            CKR_RANDOM_SEED_NOT_SUPPORTED => CryptokiRetVal::RandomSeedNotSupported,
            CKR_RANDOM_NO_RNG => CryptokiRetVal::RandomNoRng,
            CKR_DOMAIN_PARAMS_INVALID => CryptokiRetVal::DomainParamsInvalid,
            CKR_CURVE_NOT_SUPPORTED => CryptokiRetVal::CurveNotSupported,
            CKR_BUFFER_TOO_SMALL => CryptokiRetVal::BufferTooSmall,
            CKR_SAVED_STATE_INVALID => CryptokiRetVal::SavedStateInvalid,
            CKR_INFORMATION_SENSITIVE => CryptokiRetVal::InformationSensitive,
            CKR_STATE_UNSAVEABLE => CryptokiRetVal::StateUnsaveable,
            CKR_CRYPTOKI_NOT_INITIALIZED => CryptokiRetVal::CryptokiNotInitialized,
            CKR_CRYPTOKI_ALREADY_INITIALIZED => CryptokiRetVal::CryptokiAlreadyInitialized,
            CKR_MUTEX_BAD => CryptokiRetVal::MutexBad,
            CKR_MUTEX_NOT_LOCKED => CryptokiRetVal::MutexNotLocked,
            CKR_NEW_PIN_MODE => CryptokiRetVal::NewPinMode,
            CKR_NEXT_OTP => CryptokiRetVal::NextOtp,
            CKR_EXCEEDED_MAX_ITERATIONS => CryptokiRetVal::ExceededMaxIterations,
            CKR_FIPS_SELF_TEST_FAILED => CryptokiRetVal::FipsSelfTestFailed,
            CKR_LIBRARY_LOAD_FAILED => CryptokiRetVal::LibraryLoadFailed,
            CKR_PIN_TOO_WEAK => CryptokiRetVal::PinTooWeak,
            CKR_PUBLIC_KEY_INVALID => CryptokiRetVal::PublicKeyInvalid,
            CKR_FUNCTION_REJECTED => CryptokiRetVal::FunctionRejected,
            CKR_VENDOR_DEFINED..=CK_RV::MAX => CryptokiRetVal::VendorDefined(ck_rv),
            other => CryptokiRetVal::Undefined(other),
        }
    }
}

impl CryptokiRetVal {
    /// Convert the return value into a standard Result type
    pub fn into_result(self) -> Result<(), Error> {
        match self {
            CryptokiRetVal::Ok => Ok(()),
            ck_rv_error => Err(Error::Pkcs11(ck_rv_error)),
        }
    }
}
