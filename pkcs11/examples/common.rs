#![allow(dead_code)]

use std::env;

use pkcs11::module::{InitializeArgs, Initialized, Pkcs11Module, SecretPin, UserType};

pub(crate) fn get_pkcs11_module() -> Pkcs11Module<Initialized> {
    let path = env::var("EXAMPLE_PKCS11_PATH")
        .unwrap_or_else(|_| "/usr/lib/libfake.so".to_string());
    let pkcs11 = Pkcs11Module::new(path).unwrap();
    pkcs11.initialize(InitializeArgs::OsLocking).unwrap()
}

pub(crate) fn reset_token() {
    let pkcs11 = get_pkcs11_module();

    let all_slots = pkcs11.get_all_slots().unwrap();
    let slot = all_slots.first().copied().expect("No slots available");

    let so_pin = SecretPin::new("00000000".into());
    pkcs11
        .init_token(slot, Some(&so_pin), "Test token")
        .unwrap();

    let session = pkcs11.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&so_pin)).unwrap();
    let user_pin = SecretPin::new("12345678".into());
    session.init_pin(Some(&user_pin)).unwrap();
    session.logout().unwrap();
}
