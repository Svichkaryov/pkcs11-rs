use {
    proc_macro::TokenStream,
    quote::quote,
    syn::{DeriveInput, parse_macro_input},
};

fn has_valid_repr(attrs: &[syn::Attribute]) -> bool {
    const VALID: &[&str] = &[
        "u8",
        "u16",
        "u32",
        "u64",
        "usize",
        "i8",
        "i16",
        "i32",
        "i64",
        "isize",
        "C",
        "transparent",
    ];

    attrs.iter().any(|attr| {
        if !attr.path().is_ident("repr") {
            return false;
        }
        attr.parse_args::<syn::Ident>()
            .map(|ident| VALID.contains(&ident.to_string().as_str()))
            .unwrap_or(false)
    })
}

pub(crate) fn derive_attribute_pod_type_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let type_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let valid_repr = has_valid_repr(&input.attrs);

    if !valid_repr {
        return syn::Error::new_spanned(
            &input.ident,
            "AttributePodType derive requires #[repr(C)], \
            #[repr(transparent)], etc.",
        )
        .to_compile_error()
        .into();
    }

    quote! {
        impl #impl_generics CkPodType
            for #type_name #ty_generics #where_clause {}
    }
    .into()
}

pub(crate) fn derive_try_from_ck_attribute_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let type_name = &input.ident;

    let valid_repr = has_valid_repr(&input.attrs);

    if !valid_repr {
        return syn::Error::new_spanned(
            &input.ident,
            "TryFromCkAttribute derive requires #[repr(C)], \
            #[repr(transparent)], etc and Ulong inner type",
        )
        .to_compile_error()
        .into();
    }

    quote! {
        impl TryFromCkAttribute for #type_name {
            fn try_from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Self> {
                <#type_name as TryFromCkAttribute>::try_from_ck_attr(&attr)
            }
        }
    }
    .into()
}
