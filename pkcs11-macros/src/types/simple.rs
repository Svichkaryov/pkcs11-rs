use {
    proc_macro::TokenStream,
    quote::quote,
    syn::{Attribute, Ident, parse_macro_input},
};

use crate::{naming::convert_name, types::input::Pkcs11Type};

pub(crate) fn pkcs11_type_impl(input: TokenStream) -> TokenStream {
    let Pkcs11Type {
        type_attrs,
        type_name,
        inner_type,
        naming,
        entries,
        const_prefix,
        vendor_defined_const,
    } = parse_macro_input!(input as Pkcs11Type);

    // For simple types there must always be a type
    // let inner_type = inner_type.unwrap_or_else(|| parse_quote!(u64));

    struct NamePair {
        // doc comments
        attrs: Vec<Attribute>,
        rust_name: Ident,
        c_name: Ident,
    }

    let name_pairs: Vec<NamePair> = entries
        .into_iter()
        .filter(|entry| !entry.ck_name.to_string().ends_with("_VENDOR_DEFINED"))
        .map(|entry| {
            let converted =
                convert_name(&entry.ck_name.to_string(), &const_prefix, &naming);
            NamePair {
                attrs: entry.attrs,
                rust_name: Ident::new(&converted, entry.ck_name.span()),
                c_name: entry.ck_name,
            }
        })
        .collect();

    // Type impl
    let const_defs = name_pairs.iter().map(|p| {
        let (attrs, rust_name, c_name) = (&p.attrs, &p.rust_name, &p.c_name);
        quote! {
            #(#attrs)*
            pub const #rust_name: #type_name = #type_name(#c_name);
        }
    });

    let const_all_variants = name_pairs.iter().map(|p| {
        let rust_name = &p.rust_name;
        quote! { #type_name::#rust_name }
    });

    let impl_ts = quote! {
        #(#type_attrs)*
        #[derive(Copy, Clone, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct #type_name(#inner_type);

        impl #type_name {
            #(#const_defs)*

            /// Returns a slice of all known variants.
            pub fn all() -> &'static [#type_name] {
                &[ #(#const_all_variants),* ]
            }
        }
    };

    //
    let optional_vendor_defined_impl =
        vendor_defined_const.as_ref().map(|vendor_const| {
            quote! {
                impl #type_name {
                    pub fn new_vendor_defined(value: #inner_type) -> Result<#type_name> {
                        if value >= #vendor_const {
                            Ok(#type_name(value))
                        } else {
                            Err(Error::InvalidInput)
                        }
                    }

                    pub fn is_vendor_defined(&self) -> bool {
                        self.0 >= #vendor_const
                    }
                }
            }
        });

    let deref_ts = quote! {
        impl ::std::ops::Deref for #type_name {
            type Target = #inner_type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };

    let from_ts = quote! {
        impl ::std::convert::From<#type_name> for #inner_type {
            fn from(val: #type_name) -> Self {
                *val
            }
        }
    };

    // TryFrom
    let try_from_arms = name_pairs.iter().map(|p| {
        let (c_name, rust_name) = (&p.c_name, &p.rust_name);
        quote! {
            #c_name => Ok(Self::#rust_name),
        }
    });

    let try_from_vendor_defined_ext = match &vendor_defined_const {
        Some(vendor_const) => quote! {
            v if v >= #vendor_const => Ok(Self(v)),
        },
        None => quote! {},
    };

    let try_from_ts = quote! {
        impl ::std::convert::TryFrom<#inner_type> for #type_name {
            type Error = Error;

            fn try_from(val: #inner_type) -> Result<Self> {
                match val {
                    #(#try_from_arms)*
                    #try_from_vendor_defined_ext
                    _ => Err(Error::NotSupported),
                }
            }
        }
    };

    let type_name_str = type_name.to_string();

    // Display
    let display_arms = name_pairs.iter().map(|p| {
        let (rust_name, c_name_str) = (&p.rust_name, p.c_name.to_string());
        quote! {
            #type_name::#rust_name => ::std::write!(f, #c_name_str),
        }
    });

    let display_vendor_defined_ext = vendor_defined_const
        .as_ref()
        .map(|vendor_const| {
            let vendor_const_str = vendor_const.to_string();
            quote! {
                _ if self.is_vendor_defined() => {
                    ::std::write!(f, "{}({:#x})", #vendor_const_str, self.0)
                }
            }
        })
        .unwrap_or_default();

    let display_ts = quote! {
        impl ::std::fmt::Display for #type_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match *self {
                    #(#display_arms)*
                    #display_vendor_defined_ext
                    other => ::std::write!(f, "Unknown {}: {:#x}", #type_name_str, *other),
                }
            }
        }
    };

    // Debug
    let debug_arms = name_pairs.iter().map(|p| {
        let rust_name = &p.rust_name;
        let rust_name_str = rust_name.to_string();
        quote! {
            #type_name::#rust_name => ::std::write!(
                f, "{}::{}({:#x})",
                #type_name_str, #rust_name_str, self.0
            ),
        }
    });

    let debug_vendor_defined_ext = vendor_defined_const
        .as_ref()
        .map(|_| {
            quote! {
                _ if self.is_vendor_defined() => {
                    ::std::write!(f, "{}(VendorDefined({:#x}))", #type_name_str, self.0)
                }
            }
        })
        .unwrap_or_default();

    let debug_ts = quote! {
        impl ::std::fmt::Debug for #type_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match *self {
                    #(#debug_arms)*
                    #debug_vendor_defined_ext
                    other => ::std::write!(f, "Unknown {}({:#x})", #type_name_str, *other),
                }
            }
        }
    };

    // Generate the final code for a newtype: impl, traits.
    quote! {
        #impl_ts
        #optional_vendor_defined_impl
        #deref_ts
        #from_ts
        #try_from_ts
        #display_ts
        #debug_ts
    }
    .into()
}
