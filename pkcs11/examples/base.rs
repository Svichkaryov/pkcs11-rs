use pkcs11::{
    error::{Error, Result},
    types::{SecretPin, UserType},
};

mod common;

fn main() -> Result<()> {
    let pkcs11 = common::get_pkcs11_module();

    let slots = pkcs11.get_slots_with_initialized_token()?;
    if slots.is_empty() {
        return Err(Error::Module("No slots available".to_owned()));
    }
    let slot = slots[0];
    println!(
        "Found {} slot(s). Using first slot: {:?}",
        slots.len(),
        slot
    );

    let session = pkcs11.open_ro_session(slot)?;
    let user_pin = SecretPin::new("12345678".into());
    session.login(UserType::User, Some(&user_pin))?;

    let all_data_objects = session.find_objects(&[]).unwrap();
    println!("All objects: {all_data_objects:?}");

    Ok(())
}
