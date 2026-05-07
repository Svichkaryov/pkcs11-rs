//! This module provides a state-typed [`Pkcs11Module`] that distinguishes
//! between an uninitialized library handle and an initialized one.
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

mod general_purpose;
mod slot_token_management;

pub use general_purpose::*;
