use pkcs11_sys::*;

use pkcs11_macros::pkcs11_rv_type;

pkcs11_rv_type!(
    /// Cryptoki function return values.
    ///
    /// The values are divided into groups and ordered as described in
    /// [`Section 5.1`].
    ///
    /// [`Section 5.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693116
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    CryptokiRetVal, naming = UpperCamelCase;
    [
    // Universal Cryptoki function return values
    //
    // Any Cryptoki function can return any of the below values:

        /// The function executed successfully.
        /// Technically, [`Ok`] is not quite a "universal" return value;
        /// in particular, the legacy functions C_GetFunctionStatus and
        /// C_CancelFunction (see [`Section 5.20`]) cannot return [`Ok`].
        ///
        /// [`Ok`]: Self::Ok
        /// [`Section 5.20`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693242
        CKR_OK,

        /// Some horrible, unrecoverable error has occurred. In the worst case,
        /// it is possible that the function only partially succeeded, and that
        /// the computer and/or token is in an inconsistent state.
        CKR_GENERAL_ERROR,

        /// The computer that the Cryptoki library is running on has
        /// insufficient memory to perform the requested function.
        CKR_HOST_MEMORY,

        /// The requested function could not be performed, but detailed
        /// information about why not is not available in this error return. If
        /// the failed function uses a session, it is possible that the
        /// [`SessionInfo`] structure that can be obtained by calling
        /// [`get_session_info`] will hold useful information about what
        /// happened via [`device_error`] function. In any event, although the
        /// function call failed, the situation is not necessarily totally
        /// hopeless, as it is likely to be when [`GeneralError`] is returned.
        /// Depending on what the root cause of the error actually was, it is
        /// possible that an attempt to make the exact same function call again
        /// would succeed.
        ///
        /// [`SessionInfo`]: crate::doc_links::SessionInfo
        /// [`get_session_info`]: crate::doc_links::Session::get_session_info
        /// [`device_error`]: crate::doc_links::SessionInfo::device_error
        /// [`GeneralError`]: Self::GeneralError
        CKR_FUNCTION_FAILED,


    // Cryptoki function return values for functions that use a session handle
    //
    // Any Cryptoki function that takes a session handle as one of its
    // arguments (i.e., any Cryptoki function except for C_Initialize,
    // C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo,
    // C_GetTokenInfo, C_WaitForSlotEvent, C_GetMechanismList,
    // C_GetMechanismInfo, C_InitToken, C_OpenSession, and C_CloseAllSessions)
    // can return the below values:

        /// The specified session handle was invalid at the time that the
        /// function was invoked. Note that this can happen if the session's
        /// token is removed before the function invocation, since removing a
        /// token closes all sessions with it.
        CKR_SESSION_HANDLE_INVALID,

        /// The token was removed from its slot during the execution of the
        /// function.
        CKR_DEVICE_REMOVED,

        /// The session was closed during the execution of the function. Note
        /// that, as stated in [`PKCS11-UG`], the behavior of Cryptoki is
        /// undefined if multiple threads of an application attempt to access a
        /// common Cryptoki session simultaneously. Therefore, there is
        /// actually no guarantee that a function invocation could ever return
        /// the value [`SessionClosed`]. An example of multiple threads
        /// accessing a common session simultaneously is where one thread is
        /// using a session when another thread closes that same session.
        ///
        /// [`PKCS11-UG`]: http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html
        /// [`SessionClosed`]: Self::SessionClosed
        CKR_SESSION_CLOSED,



    // Cryptoki function return values for functions that use a token
    //
    // Any Cryptoki function that uses a particular token (i.e., any Cryptoki
    // function except for C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList,
    // C_GetSlotList, C_GetSlotInfo, or C_WaitForSlotEvent) can return any of
    // the below values:

        /// The token does not have sufficient memory to perform the requested
        /// function.
        CKR_DEVICE_MEMORY,

        /// Some problem has occurred with the token and/or slot. This error
        /// code can be returned by more than just the functions mentioned
        /// above; in particular, it is possible for [`get_slot_info`] to
        /// return [`DeviceError`].
        ///
        /// [`get_slot_info`]: crate::doc_links::Pkcs11Module::get_slot_info
        /// [`DeviceError`]: Self::DeviceError
        CKR_DEVICE_ERROR,

        /// The token was not present in its slot at the time that the function
        /// was invoked.
        CKR_TOKEN_NOT_PRESENT,

        // Defined in above section with functions that use a session handle.
        // DeviceRemoved,


    // Special return value for application-supplied callbacks
    //
    // There is a special-purpose return value which is not returned by any
    // function in the actual Cryptoki API, but which may be returned by an
    // application-supplied callback function. It is:

        /// When a function executing in serial with an application decides
        /// to give the application a chance to do some work, it calls
        /// an application-supplied function with a CKN_SURRENDER callback
        /// (see [`Section 5.21`]). If the callback returns the value
        /// [`Cancel`], then the function aborts and returns
        /// [`FunctionCanceled`].
        ///
        /// [`Section 5.21`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693245
        /// [`Cancel`]: Self::Cancel
        /// [`FunctionCanceled`]: Self::FunctionCanceled
        CKR_CANCEL,


    // Special return values for mutex-handling functions
    //
    // There are two other special-purpose return values which are not returned
    // by any actual Cryptoki functions. These values may be returned
    // by application-supplied mutex-handling functions, and they may safely
    // be ignored by application developers who are not using their own
    // threading model. They are:

        /// This error code can be returned by mutex-handling functions that
        /// are passed a bad mutex object as an argument. Unfortunately, it is
        /// possible for such a function not to recognize a bad mutex object.
        /// There is therefore no guarantee that such a function will
        /// successfully detect bad mutex objects and return this value.
        CKR_MUTEX_BAD,

        /// This error code can be returned by mutex-unlocking functions.
        /// It indicates that the mutex supplied to the mutex-unlocking
        /// function was not locked.
        CKR_MUTEX_NOT_LOCKED,


    // All other Cryptoki function return values
    //
    // Descriptions of the other Cryptoki function return values follow.
    // Except as mentioned in the descriptions of particular error codes,
    // there are in general no particular priorities among the errors listed
    // below, i.e., if more than one error code might apply to an execution
    // of a function, then the function may return any applicable error code.

        /// This value can only be returned by [`copy_object`],
        /// [`set_attribute_value`], and [`destroy_object`]. It denotes that
        /// the action may not be taken, either because of underlying policy
        /// restrictions on the token, or because the object has the the
        /// relevant [`Copyable`], [`Modifiable`] or [`Destroyable`] policy
        /// attribute set to `false`.
        ///
        /// [`copy_object`]: crate::doc_links::Session::copy_object
        /// [`set_attribute_value`]: crate::doc_links::Session::set_attribute_value
        /// [`destroy_object`]: crate::doc_links::Session::destroy_object
        /// [`Copyable`]: crate::doc_links::Attribute::Copyable
        /// [`Modifiable`]: crate::doc_links::Attribute::Modifiable
        /// [`Destroyable`]: crate::doc_links::Attribute::Destroyable
        CKR_ACTION_PROHIBITED,

        /// This is a rather generic error code which indicates that the
        /// arguments supplied to the Cryptoki function were in some way not
        /// appropriate.
        CKR_ARGUMENTS_BAD,

        /// An attempt was made to set a value for an attribute which may not
        /// be set by the application, or which may not be modified by the
        /// application. See [`Section 4.1`] for more information.
        ///
        /// [`Section 4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693063
        CKR_ATTRIBUTE_READ_ONLY,

        /// An attempt was made to obtain the value of an attribute of an
        /// object which cannot be satisfied because the object is either
        /// sensitive or un-extractable.
        CKR_ATTRIBUTE_SENSITIVE,

        /// An invalid attribute type was specified in a template. See
        /// [`Section 4.1`] for more information.
        ///
        /// [`Section 4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693063
        CKR_ATTRIBUTE_TYPE_INVALID,

        /// An invalid value was specified for a particular attribute in a
        /// template. See [`Section 4.1`] for more information.
        ///
        /// [`Section 4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693063
        CKR_ATTRIBUTE_VALUE_INVALID,

        /// The output of the function is too large to fit in the supplied
        /// buffer.
        CKR_BUFFER_TOO_SMALL,

        /// This value can only be returned by [`initialize`]. It means that
        /// the type of locking requested by the application for thread-safety
        /// is not available in this library, and so the application cannot
        /// make use of this library in the specified fashion.
        ///
        /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
        CKR_CANT_LOCK,

        /// This value can only be returned by [`initialize`]. It means that
        /// the Cryptoki library has already been initialized (by a previous
        /// call to [`initialize`] which did not have a matching [`finalize`]
        /// call).
        ///
        /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
        /// [`finalize`]: crate::doc_links::Pkcs11Module::finalize
        CKR_CRYPTOKI_ALREADY_INITIALIZED,

        /// This value can be returned by any function other than
        /// [`initialize`] and C_GetFunctionList. It indicates that the
        /// function cannot be executed because the Cryptoki library has not
        /// yet been initialized by a call to [`initialize`].
        ///
        /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
        CKR_CRYPTOKI_NOT_INITIALIZED,

        /// This curve is not supported by this token.
        /// Used with Elliptic Curve mechanisms.
        CKR_CURVE_NOT_SUPPORTED,

        /// The plaintext input data to a cryptographic operation is invalid.
        /// This return value has lower priority than [`DataLenRange`].
        ///
        /// [`DataLenRange`]: Self::DataLenRange
        CKR_DATA_INVALID,

        /// The plaintext input data to a cryptographic operation has a bad
        /// length. Depending on the operation's mechanism, this could mean
        /// that the plaintext data is too short, too long, or is not a
        /// multiple of some particular block size. This return value has
        /// higher priority than [`DataInvalid`].
        ///
        /// [`DataInvalid`]: Self::DataInvalid
        CKR_DATA_LEN_RANGE,

        /// Invalid or unsupported domain parameters were supplied to the
        /// function. Which representation methods of domain parameters are
        /// supported by a given mechanism can vary from token to token.
        CKR_DOMAIN_PARAMS_INVALID,

        /// The encrypted input to a decryption operation has been determined
        /// to be invalid ciphertext. This return value has lower priority than
        /// [`EncryptedDataLenRange`].
        ///
        /// [`EncryptedDataLenRange`]: Self::EncryptedDataLenRange
        CKR_ENCRYPTED_DATA_INVALID,

        /// The ciphertext input to a decryption operation has been determined
        /// to be invalid ciphertext solely on the basis of its length.
        /// Depending on the operation's mechanism, this could mean that
        /// the ciphertext is too short, too long, or is not a multiple of some
        /// particular block size. This return value has higher priority than
        /// [`EncryptedDataInvalid`].
        ///
        /// [`EncryptedDataInvalid`]: Self::EncryptedDataInvalid
        CKR_ENCRYPTED_DATA_LEN_RANGE,

        /// An iterative algorithm (for key pair generation, domain parameter
        /// generation etc.) failed because we have exceeded the maximum
        /// number of iterations. This error code has precedence over
        /// CKR_FUNCTION_FAILED. Examples of iterative algorithms include DSA
        /// signature generation (retry if either r = 0 or s = 0) and
        /// generation of DSA primes p and q specified in FIPS 186-4.
        CKR_EXCEEDED_MAX_ITERATIONS,

        /// A FIPS 140-2 power-up self-test or conditional self-test failed.
        /// The token entered an error state. Future calls to cryptographic
        /// functions on the token will return [`GeneralError`].
        /// [`FipsSelfTestFailed`] has a higher precedence over
        /// [`GeneralError`]. This error may be returned by [`initialize`],
        /// if a power-up self-test failed, by [`generate_random`] or
        /// [`seed_random`], if the continuous random number generator test
        /// failed, or by [`generate_key_pair`], if the pair-wise consistency
        /// test failed.
        ///
        /// [`GeneralError`]: Self::GeneralError
        /// [`FipsSelfTestFailed`]: Self::FipsSelfTestFailed
        /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
        /// [`generate_random`]: crate::doc_links::Session::generate_random
        /// [`seed_random`]: crate::doc_links::Session::seed_random
        /// [`generate_key_pair`]: crate::doc_links::Session::generate_key_pair
        CKR_FIPS_SELF_TEST_FAILED,

        /// The function was canceled in mid-execution. This happens to a
        /// cryptographic function if the function makes a CKN_SURRENDER
        /// application callback which returns [`Cancel`]. It also happens
        /// to a function that performs PIN entry through a protected path.
        /// The method used to cancel a protected path PIN entry operation
        /// is device dependent.
        ///
        /// [`Cancel`]: Self::Cancel
        CKR_FUNCTION_CANCELED,

        /// There is currently no function executing in parallel in the
        /// specified session. This is a legacy error code which is only
        /// returned by the legacy functions C_GetFunctionStatus and
        /// C_CancelFunction.
        CKR_FUNCTION_NOT_PARALLEL,

        /// The requested function is not supported by this Cryptoki library.
        /// Even unsupported functions in the Cryptoki API should have a "stub"
        /// in the library; this stub should simply return the value
        /// [`FunctionNotSupported`].
        ///
        /// [`FunctionNotSupported`]: Self::FunctionNotSupported
        CKR_FUNCTION_NOT_SUPPORTED,

        /// The signature request is rejected by the user.
        CKR_FUNCTION_REJECTED,

        /// The information requested could not be obtained because the token
        /// considers it sensitive, and is not able or willing to reveal it.
        CKR_INFORMATION_SENSITIVE,

        /// This value is only returned by [`set_operation_state`]. It
        /// indicates that one of the keys specified is not the same key that
        /// was being used in the original saved session.
        ///
        /// [`set_operation_state`]: crate::doc_links::Session::set_operation_state
        CKR_KEY_CHANGED,

        /// An attempt has been made to use a key for a cryptographic purpose
        /// that the key's attributes are not set to allow it to do. For
        /// example, to use a key for performing encryption, that key MUST have
        /// its [`Encrypt`] attribute set to `true` (the fact that the key MUST
        /// have a [`Encrypt`] attribute implies that the key cannot be a
        /// private key). This return value has lower priority than
        /// [`KeyTypeInconsistent`].
        ///
        /// [`Encrypt`]: crate::doc_links::Attribute::Encrypt
        /// [`KeyTypeInconsistent`]: Self::KeyTypeInconsistent
        CKR_KEY_FUNCTION_NOT_PERMITTED,

        /// The specified key handle is not valid. It may be the case that the
        /// specified handle is a valid handle for an object which is not a
        /// key. We reiterate here that 0 is never a valid key handle.
        CKR_KEY_HANDLE_INVALID,

        /// This error code can only be returned by [`digest_key`]. It
        /// indicates that the value of the specified key cannot be digested
        /// for some reason (perhaps the key isn't a secret key, or perhaps the
        /// token simply can't digest this kind of key).
        ///
        /// [`digest_key`]: crate::doc_links::Session::digest_key
        CKR_KEY_INDIGESTIBLE,

        /// This value is only returned by [`set_operation_state`]. It
        /// indicates that the session state cannot be restored because
        /// [`set_operation_state`] needs to be supplied with one or more
        /// keys that were being used in the original saved session.
        ///
        /// [`set_operation_state`]: crate::doc_links::Session::set_operation_state
        CKR_KEY_NEEDED,

        /// An extraneous key was supplied to [`set_operation_state`]. For
        /// example, an attempt was made to restore a session that had been
        /// performing a message digesting operation, and an encryption key was
        /// supplied.
        ///
        /// [`set_operation_state`]: crate::doc_links::Session::set_operation_state
        CKR_KEY_NOT_NEEDED,

        /// Although the specified private or secret key does not have its
        /// [`Extractable`] attribute set to `false`, Cryptoki (or the token)
        /// is unable to wrap the key as requested (possibly the token can only
        /// wrap a given key with certain types of keys, and the wrapping key
        /// specified is not one of these types). Compare with
        /// [`KeyUnextractable`].
        ///
        /// [`Extractable`]: crate::doc_links::Attribute::Extractable
        /// [`KeyUnextractable`]: Self::KeyUnextractable
        CKR_KEY_NOT_WRAPPABLE,

        /// Although the requested keyed cryptographic operation could in
        /// principle be carried out, this Cryptoki library (or the token) is
        /// unable to actually do it because the supplied key‘s size is outside
        /// the range of key sizes that it can handle.
        CKR_KEY_SIZE_RANGE,

        /// The specified key is not the correct type of key to use with the
        /// specified mechanism. This return value has a higher priority than
        /// [`KeyFunctionNotPermitted`].
        ///
        /// [`KeyFunctionNotPermitted`]: Self::KeyFunctionNotPermitted
        CKR_KEY_TYPE_INCONSISTENT,

        /// The specified private or secret key can't be wrapped because its
        /// [`Extractable`] attribute is set to `false`. Compare with
        /// [`KeyNotWrappable`].
        ///
        /// [`Extractable`]: crate::doc_links::Attribute::Extractable
        /// [`KeyNotWrappable`]: Self::KeyNotWrappable
        CKR_KEY_UNEXTRACTABLE,

        /// The Cryptoki library could not load a dependent shared library.
        CKR_LIBRARY_LOAD_FAILED,

        /// An invalid mechanism was specified to the cryptographic operation.
        /// This error code is an appropriate return value if an unknown
        /// mechanism was specified or if the mechanism specified cannot be
        /// used in the selected token with the selected function.
        CKR_MECHANISM_INVALID,

        /// Invalid parameters were supplied to the mechanism specified to
        /// the cryptographic operation. Which parameter values are supported
        /// by a given mechanism can vary from token to token.
        CKR_MECHANISM_PARAM_INVALID,

        /// This value can only be returned by [`initialize`]. It is returned
        /// when two conditions hold:
        /// 1. The application called [`initialize`] in a way which tells
        ///    the Cryptoki library that application threads executing calls
        ///    to the library cannot use native operating system methods
        ///    to spawn new threads.
        /// 2. The library cannot function properly without being able
        ///    to spawn new threads in the above fashion.
        ///
        /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
        CKR_NEED_TO_CREATE_THREADS,

        /// This value can only be returned by C_GetSlotEvent. It is returned
        /// when C_GetSlotEvent is called in non-blocking mode and there are
        /// no new slot events to return.
        CKR_NO_EVENT,

        /// The specified object handle is not valid. We reiterate here
        /// that 0 is never a valid object handle.
        CKR_OBJECT_HANDLE_INVALID,

        /// There is already an active operation (or combination of active
        /// operations) which prevents Cryptoki from activating the specified
        /// operation. For example, an active object-searching operation would
        /// prevent Cryptoki from activating an encryption operation with
        /// [`encrypt_init`]. Or, an active digesting operation and an active
        /// encryption operation would prevent Cryptoki from activating a
        /// signature operation. Or, on a token which doesn't support
        /// simultaneous dual cryptographic operations in a session (see the
        /// description of the [`dual_crypto_operations`] function), an active
        /// signature operation would prevent Cryptoki from activating an
        /// encryption operation.
        ///
        /// [`encrypt_init`]: crate::doc_links::Session::encrypt_init
        /// [`dual_crypto_operations`]: crate::doc_links::TokenInfo::dual_crypto_operations
        CKR_OPERATION_ACTIVE,

        /// There is no active operation of an appropriate type in the
        /// specified session. For example, an application cannot call
        /// [`encrypt`] in a session without having called [`encrypt_init`]
        /// first to activate an encryption operation.
        ///
        /// [`encrypt`]: crate::doc_links::Session::encrypt
        /// [`encrypt_init`]: crate::doc_links::Session::encrypt_init
        CKR_OPERATION_NOT_INITIALIZED,

        /// The specified PIN has expired, and the requested operation cannot
        /// be carried out unless [`set_pin`] is called to change the PIN
        /// value. Whether or not the normal user's PIN on a token ever expires
        /// varies from token to token.
        ///
        /// [`set_pin`]: crate::doc_links::Session::set_pin
        CKR_PIN_EXPIRED,

        /// The specified PIN is incorrect, i.e., does not match the PIN stored
        /// on the token. More generally -- when authentication to the token
        /// involves something other than a PIN -- the attempt to authenticate
        /// the user has failed.
        CKR_PIN_INCORRECT,

        /// The specified PIN has invalid characters in it. This return code
        /// only applies to functions which attempt to set a PIN.
        CKR_PIN_INVALID,

        /// The specified PIN is too long or too short. This return code only
        /// applies to functions which attempt to set a PIN.
        CKR_PIN_LEN_RANGE,

        /// The specified PIN is "locked", and cannot be used. That is, because
        /// some particular number of failed authentication attempts has been
        /// reached, the token is unwilling to permit further attempts at
        /// authentication. Depending on the token, the specified PIN may or
        /// may not remain locked indefinitely.
        CKR_PIN_LOCKED,

        /// The specified PIN is too weak so that it could be easy to guess. If
        /// the PIN is too short, [`PinLenRange`] should be returned instead.
        /// This return code only applies to functions which attempt to set a
        /// PIN.
        ///
        /// [`PinLenRange`]: Self::PinLenRange
        CKR_PIN_TOO_WEAK,

        /// The public key fails a public key validation. For example, an EC
        /// public key fails the public key validation specified in
        /// Section 5.2.2 of ANSI X9.62. This error code may be returned by
        /// [`create_object`], when the public key is created, or by
        /// [`verify_init`] or C_VerifyRecoverInit, when the public key is
        /// used. It may also be returned by [`derive_key`], in preference to
        /// [`MechanismParamInvalid`], if the other party's public key
        /// specified in the mechanism's parameters is invalid.
        ///
        /// [`create_object`]: crate::doc_links::Session::create_object
        /// [`verify_init`]: crate::doc_links::Session::verify_init
        /// [`derive_key`]: crate::doc_links::Session::derive_key
        /// [`MechanismParamInvalid`]: Self::MechanismParamInvalid
        CKR_PUBLIC_KEY_INVALID,

        /// This value can be returned by [`seed_random`] and
        /// [`generate_random`]. It indicates that the specified token doesn't
        /// have a random number generator. This return value has higher
        /// priority than [`RandomSeedNotSupported`].
        ///
        /// [`seed_random`]: crate::doc_links::Session::seed_random
        /// [`generate_random`]: crate::doc_links::Session::generate_random
        /// [`RandomSeedNotSupported`]: Self::RandomSeedNotSupported
        CKR_RANDOM_NO_RNG,

        /// This value can only be returned by [`seed_random`]. It indicates
        /// that the token's random number generator does not accept seeding
        /// from an application. This return value has lower priority than
        /// [`RandomNoRng`].
        ///
        /// [`seed_random`]: crate::doc_links::Session::seed_random
        /// [`RandomNoRng`]: Self::RandomNoRng
        CKR_RANDOM_SEED_NOT_SUPPORTED,

        /// This value can only be returned by [`set_operation_state`]. It
        /// indicates that the supplied saved cryptographic operations state is
        /// invalid, and so it cannot be restored to the specified session.
        ///
        /// [`set_operation_state`]: crate::doc_links::Session::set_operation_state
        CKR_SAVED_STATE_INVALID,

        /// This value can only be returned by [`open_session`]. It indicates
        /// that the attempt to open a session failed, either because the token
        /// has too many sessions already open, or because the token has too
        /// many read/write sessions already open.
        ///
        /// [`open_session`]: crate::doc_links::Pkcs11Module::open_session
        CKR_SESSION_COUNT,

        /// This value can only be returned by [`init_token`]. It indicates
        /// that a session with the token is already open, and so the token
        /// cannot be initialized.
        ///
        /// [`init_token`]: crate::doc_links::Pkcs11Module::init_token
        CKR_SESSION_EXISTS,

        /// The specified token does not support parallel sessions. This is a
        /// legacy error code—in Cryptoki Version 2.01 and up, no token
        /// supports parallel sessions. [`SessionParallelNotSupported`] can
        /// only be returned by [`open_session`], and it is only returned
        /// when [`open_session`] is called in a particular deprecated way.
        ///
        /// [`SessionParallelNotSupported`]: Self::SessionParallelNotSupported
        /// [`open_session`]: crate::doc_links::Pkcs11Module::open_session
        CKR_SESSION_PARALLEL_NOT_SUPPORTED,

        /// The specified session was unable to accomplish the desired action
        /// because it is a read-only session. This return value has lower
        /// priority than [`TokenWriteProtected`].
        ///
        /// [`TokenWriteProtected`]: Self::TokenWriteProtected
        CKR_SESSION_READ_ONLY,

        /// A read-only session already exists, and so the SO cannot be logged
        /// in.
        CKR_SESSION_READ_ONLY_EXISTS,

        /// A read/write SO session already exists, and so a read-only session
        /// cannot be opened.
        CKR_SESSION_READ_WRITE_SO_EXISTS,

        /// The provided signature/MAC can be seen to be invalid solely on
        /// the basis of its length. This return value has higher priority
        /// than [`SignatureInvalid`].
        ///
        /// [`SignatureInvalid`]: Self::SignatureInvalid
        CKR_SIGNATURE_LEN_RANGE,

        /// The provided signature/MAC is invalid. This return value has lower
        /// priority than [`SignatureLenRange`].
        ///
        /// [`SignatureLenRange`]: Self::SignatureLenRange
        CKR_SIGNATURE_INVALID,

        /// The specified slot ID is not valid.
        CKR_SLOT_ID_INVALID,

        /// The cryptographic operations state of the specified session cannot
        /// be saved for some reason (possibly the token is simply unable to
        /// save the current state). This return value has lower priority
        /// than [`OperationNotInitialized`].
        ///
        /// [`OperationNotInitialized`]: Self::OperationNotInitialized
        CKR_STATE_UNSAVEABLE,

        /// The template specified for creating an object is incomplete, and
        /// lacks some necessary attributes. See [`Section 4.1`] for more
        /// information.
        ///
        /// [`Section 4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693063
        CKR_TEMPLATE_INCOMPLETE,

        /// The template specified for creating an object has conflicting
        /// attributes. See [`Section 4.1`] for more information.
        ///
        /// [`Section 4.1`]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693063
        CKR_TEMPLATE_INCONSISTENT,

        /// The Cryptoki library and/or slot does not recognize the token in
        /// the slot.
        CKR_TOKEN_NOT_RECOGNIZED,

        /// The requested action could not be performed because the token
        /// is write-protected. This return value has higher priority
        /// than [`SessionReadOnly`].
        ///
        /// [`SessionReadOnly`]: Self::SessionReadOnly
        CKR_TOKEN_WRITE_PROTECTED,

        /// This value can only be returned by [`unwrap_key`]. It indicates
        /// that the key handle specified to be used to unwrap another key
        /// is not valid.
        ///
        /// [`unwrap_key`]: crate::doc_links::Session::unwrap_key
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,

        /// This value can only be returned by [`unwrap_key`]. It indicates
        /// that although the requested unwrapping operation could in principle
        /// be carried out, this Cryptoki library (or the token) is unable to
        /// actually do it because the supplied key's size is outside the range
        /// of key sizes that it can handle.
        ///
        /// [`unwrap_key`]: crate::doc_links::Session::unwrap_key
        CKR_UNWRAPPING_KEY_SIZE_RANGE,

        /// This value can only be returned by [`unwrap_key`]. It indicates
        /// that the type of the key specified to unwrap another key is not
        /// consistent with the mechanism specified for unwrapping.
        ///
        /// [`unwrap_key`]: crate::doc_links::Session::unwrap_key
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,

        /// This value can only be returned by [`login`]. It indicates that the
        /// specified user cannot be logged into the session, because it is
        /// already logged into the session. For example, if an application has
        /// an open SO session, and it attempts to log the SO into it, it will
        /// receive this error code.
        ///
        /// [`login`]: crate::doc_links::Session::login
        CKR_USER_ALREADY_LOGGED_IN,

        /// This value can only be returned by [`login`]. It indicates that the
        /// specified user cannot be logged into the session, because another
        /// user is already logged into the session. For example, if an
        /// application has an open SO session, and it attempts to log the
        /// normal user into it, it will receive this error code.
        ///
        /// [`login`]: crate::doc_links::Session::login
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,

        /// The desired action cannot be performed because the appropriate
        /// user (or an appropriate user) is not logged in. One example is that
        /// a session cannot be logged out unless it is logged in. Another
        /// example is that a private object cannot be created on a token
        /// unless the session attempting to create it is logged in as the
        /// normal user. A final example is that cryptographic operations on
        /// certain tokens cannot be performed unless the normal user is logged
        /// in.
        CKR_USER_NOT_LOGGED_IN,

        /// This value can only be returned by [`login`]. It indicates that the
        /// normal user's PIN has not yet been initialized with [`init_pin`].
        ///
        /// [`login`]: crate::doc_links::Session::login
        /// [`init_pin`]: crate::doc_links::Session::init_pin
        CKR_USER_PIN_NOT_INITIALIZED,

        /// An attempt was made to have more distinct users simultaneously
        /// logged into the token than the token and/or library permits. For
        /// example, if some application has an open SO session, and another
        /// application attempts to log the normal user into a session, the
        /// attempt may return this error. It is not required to, however. Only
        /// if the simultaneous distinct users cannot be supported does
        /// [`login`] have to return this value. Note that this error code
        /// generalizes to true multi-user tokens.
        ///
        /// [`login`]: crate::doc_links::Session::login
        CKR_USER_TOO_MANY_TYPES,

        /// An invalid value was specified as a [`UserType`]. Valid types are
        /// [`So`], [`User`], and [`ContextSpecific`].
        ///
        /// [`UserType`]: crate::doc_links::UserType
        /// [`So`]: crate::doc_links::UserType::So
        /// [`User`]: crate::doc_links::UserType::User
        /// [`ContextSpecific`]: crate::doc_links::UserType::ContextSpecific
        CKR_USER_TYPE_INVALID,

        /// This value can only be returned by [`unwrap_key`]. It indicates
        /// that the provided wrapped key is not valid. If a call is made to
        /// [`unwrap_key`] to unwrap a particular type of key (i.e., some
        /// particular key type is specified in the template provided to
        /// [`unwrap_key`]), and the wrapped key provided to [`unwrap_key`] is
        /// recognizably not a wrapped key of the proper type, then
        /// [`unwrap_key`] should return [`WrappedKeyInvalid`]. This return
        /// value has lower priority than [`WrappedKeyLenRange`].
        ///
        /// [`unwrap_key`]: crate::doc_links::Session::unwrap_key
        /// [`WrappedKeyInvalid`]: Self::WrappedKeyInvalid
        /// [`WrappedKeyLenRange`]: Self::WrappedKeyLenRange
        CKR_WRAPPED_KEY_INVALID,

        /// This value can only be returned by [`unwrap_key`]. It indicates
        /// that the provided wrapped key can be seen to be invalid solely on
        /// the basis of its length. This return value has higher priority
        /// than [`WrappedKeyInvalid`].
        ///
        /// [`unwrap_key`]: crate::doc_links::Session::unwrap_key
        /// [`WrappedKeyInvalid`]: Self::WrappedKeyInvalid
        CKR_WRAPPED_KEY_LEN_RANGE,

        /// This value can only be returned by [`wrap_key`]. It indicates that
        /// the key handle specified to be used to wrap another key is not
        /// valid.
        ///
        /// [`wrap_key`]: crate::doc_links::Session::wrap_key
        CKR_WRAPPING_KEY_HANDLE_INVALID,

        /// This value can only be returned by [`wrap_key`]. It indicates that
        /// although the requested wrapping operation could in principle be
        /// carried out, this Cryptoki library (or the token) is unable to
        /// actually do it because the supplied wrapping key's size is outside
        /// the range of key sizes that it can handle.
        ///
        /// [`wrap_key`]: crate::doc_links::Session::wrap_key
        CKR_WRAPPING_KEY_SIZE_RANGE,

        /// This value can only be returned by [`wrap_key`]. It indicates that
        /// the type of the key specified to wrap another key is not consistent
        /// with the mechanism specified for wrapping.
        ///
        /// [`wrap_key`]: crate::doc_links::Session::wrap_key
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT,

        /// The supplied OTP was not accepted and the library requests a new
        /// OTP computed using a new PIN. The new PIN is set through means out
        /// of scope for this document.
        CKR_NEW_PIN_MODE,

        /// The supplied OTP was correct but indicated a larger than normal
        /// drift in the token's internal state (e.g. clock, counter). To
        /// ensure this was not due to a temporary problem, the application
        /// should provide the next one-time password to the library for
        /// verification.
        CKR_NEXT_OTP,

        /// This value are permanently reserved for token vendors. For
        /// interoperability, vendors should register their return values
        /// through the PKCS process.
        CKR_VENDOR_DEFINED: CK_RV,
    ]
);
