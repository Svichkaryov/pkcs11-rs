//! Safe Rust implementation of the PKCS#11 API.
//!
//! # Example
//!
//! ```no_run
//! use pkcs11::module::Pkcs11Module;
//! use pkcs11::types::InitializeArgs;
//!
//! fn main() -> Result<(), pkcs11::error::Error> {
//!     let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
//!     let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;
//!
//!     let slots = pkcs11.get_all_slots()?;
//!     for slot in slots {
//!         println!("slot: {}", slot);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! [`Pkcs11Module`]: crate::doc_links::Pkcs11Module

pub mod error;
pub mod module;
pub mod session;
pub mod types;

mod ck_util;

#[doc(hidden)]
#[allow(unused_imports)]
pub(crate) mod doc_links {
    pub use crate::error::*;
    pub use crate::module::*;
    pub use crate::session::*;
    pub use crate::types::*;

    pub use pkcs11_sys::*;
}
