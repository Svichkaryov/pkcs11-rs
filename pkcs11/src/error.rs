//! Encapsulated error type.
//!
//! This module defines the main [`Error`] enum and [`Result`] type used
//! throughout the crate. Errors can originate from library loading, PKCS#11
//! function calls or input validation.
//!
//! Most functions return a [`Result<T>`] where `T` is the success type.
//! Use standard Rust error handling patterns:
//!
//! ```no_run
//! use pkcs11::module::Pkcs11Module;
//! use pkcs11::types::InitializeArgs;
//!
//! fn action() -> pkcs11::error::Result<()> {
//!     let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
//!     let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;
//!     Ok(())
//! }
//!
//! match action() {
//!     Ok(()) => println!("Success"),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```

mod cryptoki_rv;

pub use cryptoki_rv::*;

/// The main error type.
///
/// This enum represents all possible errors that can occur during interaction
/// with the crate, ranging from system-level issues (e.g., library
/// loading) to protocol-level errors returned by the token.
#[derive(Debug)]
pub enum Error {
    /// Error loading the shared PKCS#11 library (e.g., `.so`, `.dll`).
    ///
    /// This typically occurs if the specified path is incorrect, the file
    /// does not exist or the library is not compatible with the current
    /// architecture.
    LibraryLoading(libloading::Error),

    /// General error originating from the PKCS#11 module state or logic.
    ///
    /// This wraps a string describing an issue that is not a return value
    /// from a Cryptoki function.
    Module(String),

    /// Error returned by the underlying Cryptoki function.
    Pkcs11(CryptokiRetVal),

    /// Invalid value provided to a function.
    ///
    /// This indicates that an argument passed to a method was syntactically
    /// correct but semantically invalid.
    InvalidValue,

    /// Invalid input provided to a function.
    ///
    /// Similar to [`InvalidValue`](Self::InvalidValue), but specifically
    /// refers to malformed input data.
    InvalidInput,

    /// The requested operation or feature is not supported.
    NotSupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error ({e})"),
            Error::Module(s) => write!(f, "PKCS11 module error: {s}"),
            Error::Pkcs11(e) => write!(f, "PKCS11 error: {e}"),
            Error::InvalidValue => write!(f, "Invalid value"),
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::NotSupported => write!(f, "Feature not supported"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Error::LibraryLoading(err) = self {
            Some(err)
        } else {
            None
        }
    }
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Self {
        Error::LibraryLoading(err)
    }
}

impl From<CryptokiRetVal> for Error {
    fn from(rv: CryptokiRetVal) -> Self {
        Error::Pkcs11(rv)
    }
}

/// Main Result type.
pub type Result<T> = core::result::Result<T, Error>;
