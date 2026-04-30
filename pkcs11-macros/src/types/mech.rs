use {
    proc_macro::TokenStream,
    proc_macro2::TokenStream as TokenStream2,
    quote::quote,
    syn::{Ident, Type, parse_macro_input},
};

use crate::{
    naming::{NamingConvention, convert_name},
    types::{
        input::{Pkcs11Type, TypeEntry},
        pkcs11_type_impl,
    },
};

fn is_vec_type(ty: &Type) -> bool {
    if let syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "Vec";
    }
    false
}

pub(crate) fn pkcs11_mechanism_type_impl(input: TokenStream) -> TokenStream {
    let Pkcs11Type {
        type_attrs,
        type_name,
        inner_type: _,
        naming,
        entries,
        const_prefix,
        vendor_defined_const: _,
    } = parse_macro_input!(input as Pkcs11Type);
    // Build a new type with `pkcs11_type` macro

    let attr_type_name = Ident::new(&format!("{}Type", type_name), type_name.span());

    let ck_const_list: Vec<TokenStream2> = entries
        .iter()
        .map(|e| {
            let attrs = &e.attrs;
            let ck_const = &e.ck_name;
            quote! { #(#attrs)* #ck_const }
        })
        .collect();

    let pkcs11_type_ts: TokenStream2 = quote! {
        /// Identifies an mechanism type.
        #[derive(AttributePodType, TryFromCkAttribute)]
        #attr_type_name: CK_MECHANISM_TYPE, naming = ScreamingSnakeCase;
        [ #(#ck_const_list),* ]
    };

    let attr_type_ts: TokenStream2 = pkcs11_type_impl(pkcs11_type_ts.into()).into();

    //
    struct NamePair<'a> {
        mech_name: Ident,
        mech_type_const_name: Ident,
        entry: &'a TypeEntry,
    }

    let name_pairs: Vec<NamePair> = entries
        .iter()
        .filter(|e| !e.ck_name.to_string().ends_with("_VENDOR_DEFINED"))
        .map(|entry| {
            let ck_name_str = entry.ck_name.to_string();
            let mech_name = Ident::new(
                &convert_name(&ck_name_str, &const_prefix, &naming),
                entry.ck_name.span(),
            );
            let mech_type_const_name = Ident::new(
                &convert_name(
                    &ck_name_str,
                    &const_prefix,
                    &NamingConvention::ScreamingSnakeCase,
                ),
                entry.ck_name.span(),
            );
            NamePair {
                mech_name,
                mech_type_const_name,
                entry,
            }
        })
        .collect();

    // Type enumeration
    let enum_variants = name_pairs.iter().map(|p| {
        let (attrs, name, mech_ty) = (&p.entry.attrs, &p.mech_name, &p.entry.ty);
        match mech_ty {
            Some(ty) => quote! { #(#attrs)* #name(#ty) },
            None => quote! { #(#attrs)* #name },
        }
    });

    let enum_ts = quote! {
        #(#type_attrs)*
        #[derive(Debug, Clone)]
        pub enum #type_name<'a> {
            #(#enum_variants,)*
            /// Vendor-defined mechanism.
            VendorDefined(VendorDefinedMechanism<'a>),
        }
    };

    // Type impl
    let mechanism_type_arms = name_pairs.iter().map(|p| {
        let (mech_name, const_name, mech_type) =
            (&p.mech_name, &p.mech_type_const_name, &p.entry.ty);

        match mech_type {
            Some(_) => {
                quote! {
                    #type_name::#mech_name(_) => #attr_type_name::#const_name,
                }
            }
            None => quote! {
                #type_name::#mech_name => #attr_type_name::#const_name,
            },
        }
    });

    let ptr_arms = name_pairs.iter().map(|p| {
        let (mech_name, mech_type) = (&p.mech_name, &p.entry.ty);

        match mech_type {
            Some(ty) => {
                if is_vec_type(ty) {
                    quote! {
                        #type_name::#mech_name(param) => param.as_ptr() as CK_VOID_PTR,
                    }
                } else {
                    quote! {
                        #type_name::#mech_name(param) => param as *const _ as CK_VOID_PTR,
                    }
                }
            }
            None => quote! {
                #type_name::#mech_name => std::ptr::null_mut() as CK_VOID_PTR,
            },
        }
    });

    let len_arms = name_pairs.iter().map(|p| {
        let (mech_name, mech_type) = (&p.mech_name, &p.entry.ty);

        match mech_type {
            Some(ty) => {
                if is_vec_type(ty) {
                    quote! {
                        #type_name::#mech_name(param) => std::mem::size_of_val(param.as_slice()) as CK_ULONG,
                    }
                } else {
                    quote! {
                        #type_name::#mech_name(param) => std::mem::size_of_val(param) as CK_ULONG,
                    }
                }
            }
            None => quote! { #type_name::#mech_name => 0 as CK_ULONG, },
        }
    });

    let impl_ts = quote! {
        #[allow(clippy::len_without_is_empty)]
        impl<'a> #type_name<'a> {
            pub fn new_vendor_defined(
                mechanism_type: #attr_type_name,
                param: Option<&'a [u8]>,
            ) -> Result<Self> {
                if !mechanism_type.is_vendor_defined() {
                    return Err(crate::error::Error::InvalidInput);
                }
                Ok(Self::VendorDefined(VendorDefinedMechanism {
                    mechanism_type,
                    param,
                }))
            }

            pub fn mechanism_type(&self) -> #attr_type_name {
                match self {
                    #(#mechanism_type_arms)*
                    #type_name::VendorDefined(v) => v.mechanism_type,
                }
            }

            pub fn ptr(&self) -> CK_VOID_PTR {
                match self {
                    #(#ptr_arms)*
                    #type_name::VendorDefined(m) => {
                        m.param.map_or(std::ptr::null_mut() as CK_VOID_PTR, |p| {
                            p.as_ptr() as CK_VOID_PTR
                        })
                    }
                }
            }

            pub fn len(&self) -> CK_ULONG {
                match self {
                    #(#len_arms)*
                    #type_name::VendorDefined(m) => {
                        m.param.map_or(0, |p| std::mem::size_of_val(p) as CK_ULONG)
                    }
                }
            }
        }
    };

    // From
    let from_ts = quote! {
        impl<'a> From<&#type_name<'a>> for CK_MECHANISM {
            fn from(mechanism: &#type_name) -> Self {
                Self {
                    mechanism: mechanism.mechanism_type().into(),
                    pParameter: mechanism.ptr(),
                    ulParameterLen: mechanism.len(),
                }
            }
        }
    };

    // No out Mechanism
    // impl !TryFrom<CK_MECHANISM> for Mechanism<'_> {}

    quote! {
        #attr_type_ts

        #enum_ts
        #impl_ts
        #from_ts
    }
    .into()
}
