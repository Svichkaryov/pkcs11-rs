use secrecy::ExposeSecret;

use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{ck_util::*, general_purpose::*, types::*},
};

impl Pkcs11Module {
    fn get_slot_list(&self, with_token: CK_BBOOL) -> Result<Vec<Slot>> {
        self.initialized()?;

        // An application will often call C_GetSlotList twice (or sometimes
        // even more times—if an application is trying to get a list of all
        // slots with a token present, then the number of such slots
        // can (unfortunately) change between when the application asks for
        // how many such slots there are and when the application asks for
        // the slots themselves).
        let mut slot_count: CK_ULONG = 0;
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetSlotList,
            with_token,
            std::ptr::null_mut() as CK_SLOT_ID_PTR,
            &mut slot_count
        ))
        .into_result()?;

        let mut slot_list: Vec<Slot> = vec![0; slot_count as usize];
        let mut ck_ret: CK_RV;
        loop {
            // A race condition may occur. If someone calls the C_GetSlotList
            // function with NULL pSlotList that executes at this location
            // and returned before the next code is called,
            // the list of slots will update and may get larger.
            ck_ret = invoke_pkcs11!(
                self,
                C_GetSlotList,
                with_token,
                slot_list.as_mut_ptr() as CK_SLOT_ID_PTR,
                &mut slot_count
            );

            if ck_ret != CKR_BUFFER_TOO_SMALL {
                CryptokiRetVal::from(ck_ret).into_result()?;
                break;
            }
            slot_list.resize(slot_count as usize, 0);
        }

        slot_list.truncate(slot_count as usize);

        Ok(slot_list)
    }

    /// Obtain a list of all slots in the system.
    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        self.get_slot_list(CK_FALSE)
    }

    /// Obtain a list of all slots with a token in the system.
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        self.get_slot_list(CK_TRUE)
    }

    /// Obtain a list of all slots with an initialized token in the system.
    pub fn get_slots_with_initialized_token(&self) -> Result<Vec<Slot>> {
        let slots = self.get_slots_with_token()?;

        slots
            .into_iter()
            .filter_map(|slot| match self.get_token_info(slot) {
                Ok(token_info) => {
                    if token_info.token_initialized() {
                        Some(Ok(slot))
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Obtains information about a particular slot in the system.
    pub fn get_slot_info(&self, slot: Slot) -> Result<SlotInfo> {
        self.initialized()?;

        let mut ck_slot_info = CK_SLOT_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetSlotInfo,
            slot,
            &mut ck_slot_info as CK_SLOT_INFO_PTR
        ))
        .into_result()?;

        Ok(SlotInfo::from(ck_slot_info))
    }

    /// Obtains information about a particular token in the system.
    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo> {
        self.initialized()?;

        let mut ck_token_info = CK_TOKEN_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetTokenInfo,
            slot,
            &mut ck_token_info as CK_TOKEN_INFO_PTR
        ))
        .into_result()?;

        TokenInfo::try_from(ck_token_info)
    }

    /// Waits for a slot event, such as token insertion or token removal, to occur.
    ///
    /// Although the parameters supplied to
    /// [`Pkcs11Module::initialize`][crate::module::general_purpose::Pkcs11Module::initialize]
    /// can in general allow for safe multi-threaded access to a Cryptoki library,
    /// [`Pkcs11Module::wait_for_slot_event`][crate::module::slot_token_management::Pkcs11Module::wait_for_slot_event]
    /// is exceptional in that the behavior of Cryptoki is undefined if multiple
    /// threads of a single application make simultaneous calls to
    /// [`Pkcs11Module::wait_for_slot_event`][crate::module::slot_token_management::Pkcs11Module::wait_for_slot_event].
    pub fn wait_for_slot_event(&self) -> Result<Option<Slot>> {
        self.initialized()?;

        let mut slot = Slot::default();
        match invoke_pkcs11!(
            self,
            C_WaitForSlotEvent,
            CKF_DONT_BLOCK,
            &mut slot,
            std::ptr::null_mut()
        ) {
            CKR_OK => Ok(Some(slot)),
            CKR_NO_EVENT => Ok(None),
            err => Err(Error::Pkcs11(CryptokiRetVal::from(err))),
        }
    }

    /// Obtains information about a particular mechanism possibly supported
    /// by a token.
    pub fn get_mechanism_info(
        &self,
        slot: Slot,
        mech_type: MechanismType,
    ) -> Result<MechanismInfo> {
        self.initialized()?;

        let mut ck_mechanism_info = CK_MECHANISM_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetMechanismInfo,
            slot,
            mech_type.into(),
            &mut ck_mechanism_info as CK_MECHANISM_INFO_PTR
        ))
        .into_result()?;

        Ok(MechanismInfo::from(ck_mechanism_info))
    }

    /// Obtain a list of mechanism types supported by a token.
    pub fn get_mechanism_list(&self, slot: Slot) -> Result<Vec<MechanismType>> {
        self.initialized()?;

        let mut mech_type_count: CK_ULONG = 0;
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetMechanismList,
            slot,
            std::ptr::null_mut() as CK_SLOT_ID_PTR,
            &mut mech_type_count
        ))
        .into_result()?;

        let mut mech_type_list: Vec<CK_MECHANISM_TYPE> =
            vec![0; mech_type_count as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_GetMechanismList,
            slot,
            mech_type_list.as_mut_ptr() as CK_SLOT_ID_PTR,
            &mut mech_type_count
        ))
        .into_result()?;

        mech_type_list.truncate(mech_type_count as usize);

        Ok(mech_type_list
            .into_iter()
            .filter_map(|mech_type| mech_type.try_into().ok())
            .collect())
    }

    /// Initializes a token.
    pub fn init_token(
        &self,
        slot: Slot,
        pin: Option<&SecretPin>,
        label: &str,
    ) -> Result<()> {
        self.initialized()?;

        let mut c_label = c_label_from_str(label)?.to_vec();

        let (pin_ptr, pin_len) = match pin {
            Some(pin) => {
                if pin.expose_secret().contains('\0') {
                    return Err(Error::InvalidInput);
                }

                (
                    pin.expose_secret().as_ptr() as CK_UTF8CHAR_PTR,
                    pin.expose_secret().len() as CK_ULONG,
                )
            }
            None => (std::ptr::null_mut(), 0),
        };

        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_InitToken,
            slot,
            pin_ptr,
            pin_len,
            c_label.as_mut_ptr() as CK_UTF8CHAR_PTR
        ))
        .into_result()
    }
}
