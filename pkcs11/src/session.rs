//! Session management for tokens.
//!
//! This module provides the [`Session`] type and related operations for
//! interacting with PKCS#11 tokens. Sessions are created from initialized
//! modules and provide access to cryptographic operations, key management,
//! and token information.
//!
//! [`Session`] is created using methods on [`Pkcs11Module<Initialized>`] and
//! are automatically closed when dropped.
//!
//! # Thread Safety
//!
//! According to the PKCS#11 specification a single session can, in general,
//! perform only one operation at a time. The application should never make
//! multiple simultaneous function calls which use a common session.
//!
//! To enforce this requirement at the type level, the [`Session`] type does
//! not implement [`Send`] or [`Sync`]. This means that a session handle cannot
//! be shared or moved between threads. If your application needs concurrent
//! access to a token, each thread should open its own dedicated session.
//!
//! # Example
//!
//! ```no_run
//! use pkcs11::module::Pkcs11Module;
//! use pkcs11::types::{InitializeArgs, Slot};
//!
//! fn action(slot: Slot) -> pkcs11::error::Result<()> {
//!     let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
//!     let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;
//!
//!     let session = pkcs11.open_ro_session(slot)?;
//!     // ... use session
//!     Ok(())
//! }
//! ```

mod crypto;
mod crypto_raw;
mod key_management;
mod object_management;
mod random_number_generation;
mod session_management;
mod slot_token_management;

use crate::{
    error::{CryptokiRetVal, Result},
    module::{Initialized, Pkcs11Module, invoke_pkcs11},
    types::SessionHandle,
};

/// Session between an application and a token in a particular slot.
#[derive(Debug)]
pub struct Session {
    module: Pkcs11Module<Initialized>,

    handle: SessionHandle,

    // Deny Send and Sync.
    //
    // A consequence of the fact that a single session can, in general, perform
    // only one operation at a time is that an application should never make
    // multiple simultaneous function calls to Cryptoki which use a common
    // session. If multiple threads of an application attempt to use a common
    // session concurrently in this fashion, Cryptoki does not define what
    // happens. This means that if multiple threads of an application all need
    // to use Cryptoki to access a particular token, it might be appropriate
    // for each thread to have its own session with the token, unless
    // the application can ensure by some other means (e.g., by some locking
    // mechanism) that no sessions are ever used by multiple threads
    // simultaneously. This is true regardless of whether or not the Cryptoki
    // library was initialized in a fashion which permits safe multi-threaded
    // access to it. Even if it is safe to access the library from multiple
    // threads simultaneously, it is still not necessarily safe to use
    // a particular session from multiple threads simultaneously.
    _phantom: std::marker::PhantomData<*mut u32>,
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session handle: {}", self.handle)
    }
}

impl std::fmt::LowerHex for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session handle: {:08x}", self.handle)
    }
}

impl std::fmt::UpperHex for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session handle: {:08X}", self.handle)
    }
}

impl Session {
    pub(crate) fn new(module: Pkcs11Module<Initialized>, handle: SessionHandle) -> Self {
        Self {
            module,
            handle,
            _phantom: std::marker::PhantomData,
        }
    }

    // Called on drop.
    pub(crate) fn close(&self) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_CloseSession,
            self.handle().into()
        ))
        .into_result()
    }

    pub(crate) fn module(&self) -> &Pkcs11Module<Initialized> {
        &self.module
    }

    pub(crate) fn handle(&self) -> SessionHandle {
        self.handle
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            println!("Failed to close session: {}", e);
        }
    }
}
