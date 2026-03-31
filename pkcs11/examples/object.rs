use pkcs11::module::{Attribute, AttributeType, ObjectClass, SecretPin, UserType};

mod common;

fn main() {
    let pkcs11 = common::get_pkcs11_module();

    let all_slots = pkcs11.get_slots_with_initialized_token().unwrap();
    let slot = all_slots.first().copied().expect("No slots available");

    let session = pkcs11.open_rw_session(slot).unwrap();
    let user_pin = SecretPin::new("12345678".into());
    session.login(UserType::User, Some(&user_pin)).unwrap();

    let is_tmp_object = true;

    let object1_template = vec![
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(!is_tmp_object),
        Attribute::Label(String::from("label_test_object1")),
        Attribute::Application(String::from("app_test")),
        Attribute::Value("Test data 1".as_bytes().to_vec()),
    ];

    let object2_template = vec![
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(!is_tmp_object),
        Attribute::Label(String::from("label_test_object2")),
        Attribute::Application(String::from("app_test")),
        Attribute::Value("Test data 2".as_bytes().to_vec()),
    ];

    println!("Creating object1 with template: {object1_template:?}");
    let _object1 = session.create_object(&object1_template).unwrap();
    println!("Creating object2 with template: {object2_template:?}");
    let object2 = session.create_object(&object2_template).unwrap();

    let find_template = vec![Attribute::Class(ObjectClass::DATA)];

    {
        let all_data_objects = session.find_objects(&find_template).unwrap();
        println!("All objects: {all_data_objects:#?}");

        let find_template_obj1 = vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(String::from("label_test_object1")),
        ];

        let object1 = session.find_objects(&find_template_obj1).unwrap();
        println!("Object1: {object1:#?}");
        let attrs_types = &[
            AttributeType::APPLICATION,
            AttributeType::LABEL,
            AttributeType::VALUE,
        ];

        let attrs = session.get_attributes(object1[0], attrs_types).unwrap();
        println!("Object1 attributes: {attrs:?}");
        for attr in attrs {
            if let Attribute::Value(value) = attr {
                println!(
                    "Object1 attribute value: {}",
                    String::from_utf8_lossy(&value)
                );
            }
        }
    }

    {
        println!("Destroying object2 with handle: {object2:#?}");
        session.destroy_object(object2).unwrap();

        let all_data_objects = session.find_objects(&find_template).unwrap();
        println!("All objects: {all_data_objects:#?}");
    }
}
