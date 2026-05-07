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

/// Main Error type.
#[derive(Debug)]
pub enum Error {
    LibraryLoading(libloading::Error),

    Module(String),

    Pkcs11(CryptokiRetVal),

    InvalidValue,

    InvalidInput,

    NotSupported,

    NotInitialized,

    AlreadyInitialized,
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
            Error::NotInitialized => write!(f, "PKCS11 module not initialized"),
            Error::AlreadyInitialized => {
                write!(f, "PKCS11 module has already been initialized")
            }
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
