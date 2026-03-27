use bitflags::bitflags;
use secrecy::SecretString;
use std::convert::TryFrom;

pub use crate::bindings::*;
use crate::{
    error::{Error, Result},
    module::ck_util::string_from_blank_padded,
};

pub type Byte = CK_BYTE;

pub type Ulong = CK_ULONG;

pub type Version = CK_VERSION;

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

pub type Slot = CK_SLOT_ID;

pub type SecretPin = SecretString;

// CK_DATE

pub type Date = CK_DATE;

impl Date {
    pub fn is_empty(&self) -> bool {
        self.year == <[u8; 4]>::default()
            && self.month == <[u8; 2]>::default()
            && self.day == <[u8; 2]>::default()
    }
}

/// Display format: YYYY-MM-DD
impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}",
            u32::from_be_bytes(self.year),
            u16::from_be_bytes(self.month),
            u16::from_be_bytes(self.day)
        )
    }
}

impl PartialEq for Date {
    fn eq(&self, other: &Self) -> bool {
        self.year == other.year && self.month == other.month && self.day == other.day
    }
}

impl Eq for Date {}

// CK_INFO

bitflags! {
    #[derive(Debug, Clone)]
    struct InfoFlags: CK_FLAGS {
        // Reserved
    }
}

/// General information about Cryptoki.
#[derive(Debug, Clone)]
pub struct Info {
    /// Cryptoki interface version number, for compatibility with future
    /// revisions of this interface.
    pub cryptoki_version: Version,
    /// ID of the Cryptoki library manufacturer. Max length is 32 bytes.
    pub manufacturer_id: String,
    /// Bit flags reserved for future versions. MUST be zero for this version.
    _flags: InfoFlags,
    /// Character-string description of the library. Max length is 32 bytes.
    pub library_description: String,
    /// Cryptoki library version number.
    pub library_version: Version,
}

impl TryFrom<CK_INFO> for Info {
    type Error = Error;
    fn try_from(ck_info: CK_INFO) -> Result<Self> {
        if ck_info.flags != 0 {
            return Err(Error::InvalidValue);
        }
        Ok(Self {
            cryptoki_version: ck_info.cryptokiVersion,
            manufacturer_id: string_from_blank_padded(&ck_info.manufacturerID),
            _flags: InfoFlags::empty(),
            library_description: string_from_blank_padded(&ck_info.libraryDescription),
            library_version: ck_info.libraryVersion,
        })
    }
}
