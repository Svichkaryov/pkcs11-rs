use std::env;

use pkcs11::module::{InitializeArgs, MechanismType, Pkcs11Module, Slot};

struct Printer {
    indent: usize,
}

impl Printer {
    fn new() -> Self {
        Self { indent: 0 }
    }

    fn println(&self, s: impl std::fmt::Display) {
        println!("{:indent$}{s}", "", indent = self.indent * 4);
    }

    fn group(&self, title: impl std::fmt::Display, f: impl FnOnce(&Printer)) {
        self.println(title);
        f(&Printer {
            indent: self.indent + 1,
        });
    }

    fn start_section(&self) {
        println!("------------------------------");
    }

    fn end_section(&self) {
        println!("\n==============================\n");
    }

    fn separator(&self) {
        self.start_section()
    }

    fn blank_line(&self) {
        self.println("")
    }
}

macro_rules! println_aligned {
    ($p:expr, $( $key:literal : $val:expr ),* $(,)?) => {{
        let max_len = [ $( $key.len() ),* ].into_iter().max().unwrap_or(0);
        $(
            $p.println(format!("{:<width$} {}", $key, $val, width = max_len));
        )*
    }};
}

fn get_pkcs11_module() -> Pkcs11Module {
    let path = env::var("EXAMPLE_PKCS11_PATH")
        .unwrap_or_else(|_| "/usr/lib/libfake.so".to_string());
    let mut pkcs11 = Pkcs11Module::new(path).unwrap();
    pkcs11.initialize(InitializeArgs::OsLocking).unwrap();
    pkcs11
}

fn print_library_info(p: &Printer, pkcs11: &Pkcs11Module) {
    let info = pkcs11.get_info().unwrap();
    p.group("Cryptoki general info:", |p| {
        println_aligned!(p,
            "Cryptoki version:": info.cryptoki_version,
            "Manufacturer id:": info.manufacturer_id,
            "Library description:": info.library_description,
            "Library version:": info.library_version,
        );
    });
    p.blank_line();
    p.println(format!("Debug library info: {info:#?}"));
}

fn print_slot_token_list_info(p: &Printer, pkcs11: &Pkcs11Module, slots: &[Slot]) {
    p.println(format!("Slot list: {slots:#?}"));
    p.blank_line();

    for &slot in slots {
        let slot_info = pkcs11.get_slot_info(slot).unwrap();
        p.group(format!("Slot (#{slot:#?}) info:"), |p| {
            println_aligned!(p,
                "Description:": slot_info.slot_description,
                "Manufacturer id:": slot_info.manufacturer_id,
                "Hardware version:": slot_info.hardware_version,
                "Firmware version:": slot_info.firmware_version,
            );
            p.group("Flags:", |p| {
                println_aligned!(p,
                    "Token present:": slot_info.token_present(),
                    "Removable device:": slot_info.removable_device(),
                    "Hardware slot:": slot_info.hardware_slot(),
                );
            });
        });
        p.blank_line();
        p.println(format!("Debug slot (#{slot:#?}) info: {slot_info:#?}"));
        p.separator();

        let token_info = pkcs11.get_token_info(slot).unwrap();
        p.group(format!("Token (#{slot:#?}) info:"), |p| {
            println_aligned!(p,
                "Label:": token_info.label,
                "Manufacturer id:": token_info.manufacturer_id,
                "Model:": token_info.model,
                "Serial number:": token_info.serial_number,
                "Max session count:": format!("{:?}", token_info.max_session_count),
                "Session count:": format!("{:?}", token_info.session_count),
                "Max rw session count:": format!("{:?}", token_info.max_rw_session_count),
                "Rw session count:": format!("{:?}", token_info.rw_session_count),
                "Max pin length:": token_info.max_pin_len,
                "Min pin length:": token_info.min_pin_len,
                "Total public memory:": format!("{:?}", token_info.total_public_memory),
                "Hardware version:": token_info.hardware_version,
                "Firmware version:": token_info.firmware_version,
                "UTC time:": format!("{:?}", token_info.utc_time),
            );
            p.group("Flags:", |p| {
                println_aligned!(p,
                    "Rng:": token_info.rng(),
                    "Write protected:": token_info.write_protected(),
                    "Login required:": token_info.login_required(),
                    "User pin initialized:": token_info.user_pin_initialized(),
                    "Restore key not needed:": token_info.restore_key_not_needed(),
                    "Clock on token:": token_info.clock_on_token(),
                    "Protected authentication path:": token_info.protected_authentication_path(),
                    "Dual crypto operations:": token_info.dual_crypto_operations(),
                    "Token initialized:": token_info.token_initialized(),
                    "Secondary authentication:": token_info.secondary_authentication(),
                    "User pin count low:": token_info.user_pin_count_low(),
                    "User pin final try:": token_info.user_pin_final_try(),
                    "User pin locked:": token_info.user_pin_locked(),
                    "User pin to be changed:": token_info.user_pin_to_be_changed(),
                    "SO pin count low:": token_info.so_pin_count_low(),
                    "SO pin final try:": token_info.so_pin_final_try(),
                    "SO pin locked:": token_info.so_pin_locked(),
                    "SO pin to be changed:": token_info.so_pin_to_be_changed(),
                    "Error state:": token_info.error_state(),
                    "UTC time:": format!("{:?}", token_info.utc_time),
                );
            });
        });
        p.blank_line();
        p.println(format!("Debug token (#{slot:#?}) info: {token_info:#?}"));
        p.separator();
    }
}

fn print_mechanism_list(p: &Printer, mechs: &[MechanismType]) {
    p.println(format!("Mechanism list (id): {mechs:?}"));
    p.group("Mechanism list:", |p| {
        for mech in mechs {
            p.println(format!("{mech},"));
        }
    });
}

fn print_mechanism_info(
    p: &Printer,
    pkcs11: &Pkcs11Module,
    slot: Slot,
    mechs: &[MechanismType],
) {
    for &mech_type in mechs {
        let mech_info = pkcs11.get_mechanism_info(slot, mech_type).unwrap();
        p.group(format!("Mechanism ({mech_type}) info:"), |p| {
            println_aligned!(p,
                "Min key size:": mech_info.min_key_size,
                "Max key size:": mech_info.max_key_size,
            );
            p.group("Flags:", |p| {
                println_aligned!(p,
                    "Hardware:": mech_info.hardware(),
                    "Encrypt:": mech_info.encrypt(),
                    "Decrypt:": mech_info.decrypt(),
                    "Digest:": mech_info.digest(),
                    "Sign:": mech_info.sign(),
                    "Sign recover:": mech_info.sign_recover(),
                    "Verify:": mech_info.verify(),
                    "Verify recover:": mech_info.verify_recover(),
                    "Generate:": mech_info.generate(),
                    "Generate key pair:": mech_info.generate_key_pair(),
                    "Wrap:": mech_info.wrap(),
                    "Unwrap:": mech_info.unwrap(),
                    "Derive:": mech_info.derive(),
                    "EC F_p:": mech_info.ec_f_p(),
                    "EC F_2m:": mech_info.ec_f_2m(),
                    "EC from params:": mech_info.ec_from_parameters(),
                    "EC named curve:": mech_info.ec_from_named_curve(),
                    "EC uncompressed:": mech_info.ec_uncompressed(),
                    "EC compressed:": mech_info.ec_compressed(),
                );
            });
        });
        p.blank_line();
        p.println(format!("Debug mechanism (#{slot:#?}) info: {mech_info:#?}"));
        p.separator();
    }
}

fn fmt_decorate(title: &str, f: impl FnOnce(&Printer)) {
    let p = Printer::new();
    p.println(title);
    p.start_section();
    f(&p);
    p.end_section();
}

fn main() {
    let pkcs11 = get_pkcs11_module();

    fmt_decorate("Library info", |p| {
        print_library_info(p, &pkcs11);
    });

    fmt_decorate("All slots/tokens info", |p| {
        let slots = pkcs11.get_all_slots().unwrap();
        print_slot_token_list_info(p, &pkcs11, &slots);
    });

    fmt_decorate("Slots with token", |p| {
        let slots = pkcs11.get_slots_with_token().unwrap();
        p.println(format!("List: {slots:#?}"));
    });

    fmt_decorate("Slots with initialized token", |p| {
        let slots = pkcs11.get_slots_with_initialized_token().unwrap();
        p.println(format!("List: {slots:#?}"));
    });

    fmt_decorate("Mechanism list", |p| {
        let slots = pkcs11.get_all_slots().unwrap();
        let Some(&slot) = slots.first() else {
            p.println("No slots available");
            return;
        };
        let mechs = pkcs11.get_mechanism_list(slot).unwrap();
        print_mechanism_list(p, &mechs);
        print_mechanism_info(p, &pkcs11, slot, &mechs);
    });
}
