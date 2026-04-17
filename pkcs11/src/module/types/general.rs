use {bitflags::bitflags, secrecy::SecretString, std::convert::TryFrom};

pub use pkcs11_sys::*;

use crate::{
    error::{Error, Result},
    module::ck_util::{
        from_byte_slice_to_num, from_byte_slice_to_num_unchecked,
        string_from_blank_padded,
    },
};

pub type Byte = CK_BYTE;

pub type Ulong = CK_ULONG;

#[derive(Debug, Clone, Copy)]
pub struct Version(CK_VERSION);

impl Version {
    pub fn new(major: Byte, minor: Byte) -> Self {
        Self(CK_VERSION { major, minor })
    }

    pub fn major(&self) -> Byte {
        self.major
    }
    pub fn minor(&self) -> Byte {
        self.minor
    }
}

impl std::ops::Deref for Version {
    type Target = CK_VERSION;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<CK_VERSION> for Version {
    fn from(v: CK_VERSION) -> Self {
        Self(v)
    }
}

impl From<Version> for CK_VERSION {
    fn from(v: Version) -> Self {
        *v
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

impl Eq for Version {}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

pub type Slot = CK_SLOT_ID;

pub type SecretPin = SecretString;

// CK_DATE

#[derive(Debug, Default, Clone, Copy)]
pub struct Date(CK_DATE);

impl Date {
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self> {
        let y = format!("{year:04}");
        let m = format!("{month:02}");
        let d = format!("{day:02}");

        Self::try_from(CK_DATE {
            year: y.as_bytes()[..4].try_into().unwrap(),
            month: m.as_bytes()[..2].try_into().unwrap(),
            day: d.as_bytes()[..2].try_into().unwrap(),
        })
    }

    pub fn year(&self) -> u16 {
        from_byte_slice_to_num_unchecked!(&self.0.year)
    }

    pub fn month(&self) -> u8 {
        from_byte_slice_to_num_unchecked!(&self.0.month)
    }

    pub fn day(&self) -> u8 {
        from_byte_slice_to_num_unchecked!(&self.0.day)
    }

    pub fn is_empty(&self) -> bool {
        self.year == <[u8; 4]>::default()
            && self.month == <[u8; 2]>::default()
            && self.day == <[u8; 2]>::default()
    }
}

impl std::ops::Deref for Date {
    type Target = CK_DATE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Date> for CK_DATE {
    fn from(v: Date) -> Self {
        *v
    }
}

impl TryFrom<CK_DATE> for Date {
    type Error = Error;

    fn try_from(ck_date: CK_DATE) -> Result<Self> {
        let year: u16 = from_byte_slice_to_num!(&ck_date.year)?;
        let month: u8 = from_byte_slice_to_num!(&ck_date.month)?;
        let day: u8 = from_byte_slice_to_num!(&ck_date.day)?;

        if !(1900..=9999).contains(&year) {
            return Err(Error::InvalidValue);
        }
        if !(1..=12).contains(&month) {
            return Err(Error::InvalidValue);
        }
        if !(1..=31).contains(&day) {
            return Err(Error::InvalidValue);
        }

        Ok(Self(ck_date))
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
            cryptoki_version: ck_info.cryptokiVersion.into(),
            manufacturer_id: string_from_blank_padded(&ck_info.manufacturerID),
            _flags: InfoFlags::empty(),
            library_description: string_from_blank_padded(&ck_info.libraryDescription),
            library_version: ck_info.libraryVersion.into(),
        })
    }
}
