mod crypto;
mod crypto_raw;
mod key_management;
mod object_management;
mod random_number_generation;
mod session_management;
mod slot_token_management;

use crate::{
    error::{CryptokiRetVal, Result},
    module::{general_purpose::*, types::*},
};

/// Session between an application and a token in a particular slot.
#[derive(Debug)]
pub struct Session {
    module: Pkcs11Module,

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
    pub fn new(module: Pkcs11Module, handle: SessionHandle) -> Self {
        Self {
            module,
            handle,
            _phantom: std::marker::PhantomData,
        }
    }

    // Called on drop.
    pub(crate) fn close(&self) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(self.module(), C_CloseSession, self.handle()))
            .into_result()
    }

    pub(crate) fn module(&self) -> &Pkcs11Module {
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
