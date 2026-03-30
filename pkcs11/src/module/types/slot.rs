use bitflags::bitflags;

use crate::module::ck_util::string_from_blank_padded;

use super::general::*;

bitflags! {
    #[derive(Debug, Clone)]
    /// Slot information flags for [`CK_SLOT_INFO`]
    pub struct SlotInfoFlags: CK_FLAGS {
        const TOKEN_PRESENT = CKF_TOKEN_PRESENT;
        const REMOVABLE_DEVICE = CKF_REMOVABLE_DEVICE;
        const HW_SLOT = CKF_HW_SLOT;
    }
}

/// Information about a slot.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    /// Character-string description of the slot. Max length is 64 bytes.
    pub slot_description: String,
    /// ID of the slot manufacturer. Max length is 32 bytes.
    pub manufacturer_id: String,
    /// Bits flags that provide capabilities of the slot.
    pub flags: SlotInfoFlags,
    /// Version number of the slot's hardware.
    pub hardware_version: Version,
    /// Version number of the slot's firmware.
    pub firmware_version: Version,
}

impl SlotInfo {
    /// True if a token is present in the slot (e.g., a device is
    /// in the reader).
    pub fn token_present(&self) -> bool {
        self.flags.contains(SlotInfoFlags::TOKEN_PRESENT)
    }

    /// True if the reader supports removable devices.
    ///
    /// For a given slot, this flag *never changes*.
    /// In addition, if this flag is not set for a given slot, then the
    /// [`TOKEN_PRESENT`](SlotInfoFlags::TOKEN_PRESENT)
    /// flag for that slot is always set. That is, if a slot does not support
    /// a removable device, then that slot always has a token in it.
    pub fn removable_device(&self) -> bool {
        self.flags.contains(SlotInfoFlags::REMOVABLE_DEVICE)
    }

    /// True if the slot is a hardware slot, as opposed to a software slot
    /// implementing a "soft token".
    pub fn hardware_slot(&self) -> bool {
        self.flags.contains(SlotInfoFlags::HW_SLOT)
    }
}

impl From<CK_SLOT_INFO> for SlotInfo {
    fn from(ck_slot_info: CK_SLOT_INFO) -> Self {
        Self {
            slot_description: string_from_blank_padded(&ck_slot_info.slotDescription),
            manufacturer_id: string_from_blank_padded(&ck_slot_info.manufacturerID),
            flags: SlotInfoFlags::from_bits_truncate(ck_slot_info.flags),
            hardware_version: ck_slot_info.hardwareVersion,
            firmware_version: ck_slot_info.firmwareVersion,
        }
    }
}
