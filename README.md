# pkcs11

This crate provides a safe, idiomatic Rust interface to **PKCS#11** API.

The current implementation is compatible with **PKCS#11 v2.40**. Support for **PKCS#11 v3.2** is planned in the future.

## Example

Add dependency to your *Cargo.toml*:

```toml
[dependencies]
pkcs11-rs = { git = "https://github.com/Svichkaryov/pkcs11-rs.git" }
```

Run:

```rust
use pkcs11::{
    error::{Error, Result},
    module::Pkcs11Module,
    types::{InitializeArgs, SecretPin, UserType},
};

mod common;

fn main() -> Result<()> {
    let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
    let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;

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
```

The [examples] folder contains various examples of how to use `pkcs11-rs`.

You can run the examples as follows:

```bash
$ export EXAMPLE_PKCS11_PATH="/usr/lib/libpkcs11.so"
$ cargo run --example base
$ cargo run --example general_info
```

[examples]: https://github.com/Svichkaryov/pkcs11-rs/tree/main/pkcs11/examples
