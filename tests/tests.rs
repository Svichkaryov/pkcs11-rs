use serial_test::serial;
use std::{env, thread};

// use pkcs11::bindings::*;
//use pkcs11::error::*;
use pkcs11::{error::CryptokiRetVal, module::*};

fn get_test_pkcs11_path() -> String {
    env::var("TEST_PKCS11_PATH").unwrap_or_else(|_| "/usr/lib/libfake.so".to_string())
}

fn get_pkcs11_module() -> Pkcs11Module {
    let mut pkcs11 = Pkcs11Module::new(get_test_pkcs11_path()).unwrap();
    pkcs11.initialize(InitializeArgs::OsLocking).unwrap();

    pkcs11
}

#[test]
#[serial]
fn test_print_rv() {
    println!(
        "Return value (std::fmt::Display): {}",
        CryptokiRetVal::BufferTooSmall
    );
    println!(
        "Return value (std::fmt::Debug): {:?}",
        CryptokiRetVal::BufferTooSmall
    );
}

#[test]
#[serial]
fn test_get_all_slots() {
    let pkcs11 = get_pkcs11_module();
    let slots = pkcs11.get_all_slots().unwrap();
    println!("Slots: {:?}", slots);
    println!("")
}

#[test]
#[serial]
fn test_module_get_info_threads() {
    let pkcs11 = get_pkcs11_module();

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();

    for _ in 0..3 {
        let pkcs11: Pkcs11Module = pkcs11.clone();
        threads.push(thread::spawn(move || {
            let info = pkcs11.get_info().unwrap();
            println!("Module info: {:#?}", info);
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }
}
