use {
    proc_macro::TokenStream,
    proc_macro2::TokenStream as TokenStream2,
    quote::quote,
    syn::{
        bracketed,
        parse::{Parse, ParseStream},
        parse_macro_input,
        punctuated::Punctuated,
        Attribute, Error, Ident, Result, Token, Type,
    },
};

use crate::{
    naming::{convert_name, extract_prefix, NamingConvention},
    types::pkcs11_type_impl,
};

struct MechEntry {
    /// Doc comments.
    attrs: Vec<Attribute>,
    /// A c-style pkcs#11 constant name.
    ck_name: Ident,
    /// Attribute type.
    ty: Option<Type>,
}

impl Parse for MechEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let ck_name: Ident = input.parse()?;
        let ty = if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
            Some(input.parse::<Type>()?)
        } else {
            None
        };
        Ok(MechEntry { attrs, ck_name, ty })
    }
}

/// Input for the `pkcs11_mechanism_type!` procedure macro.
struct Pkcs11MechanismType {
    /// Doc comments and derive attributes for the type impl.
    type_attrs: Vec<Attribute>,
    /// Type name.
    type_name: Ident,
    /// Naming convention for attribute types (default: UpperCamelCase).
    naming: NamingConvention,
    /// Attribute entries with type.
    entries: Vec<MechEntry>,
    /// Validated common prefix to all c-style pkcs#11 constants.
    const_prefix: String,
}

impl Parse for Pkcs11MechanismType {
    fn parse(input: ParseStream) -> Result<Self> {
        let type_attrs = input.call(Attribute::parse_outer)?;
        let type_name: Ident = input.parse()?;

        let naming = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let key: Ident = input.parse()?;
            if key != "naming" {
                return Err(Error::new(
                    key.span(),
                    format!("expected `naming`, found `{key}`"),
                ));
            }
            input.parse::<Token![=]>()?;
            input.parse::<NamingConvention>()?
        } else {
            NamingConvention::UpperCamelCase
        };

        input.parse::<Token![;]>()?;

        // Parse list of constants in brackets
        let content;
        bracketed!(content in input);
        let entries: Vec<MechEntry> =
            Punctuated::<MechEntry, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .collect();

        // Validate list

        if entries.is_empty() {
            return Err(Error::new(type_name.span(), "expected at least one entry"));
        }

        let prefixes: Vec<String> = entries
            .iter()
            .map(|entry| {
                let name = entry.ck_name.to_string();
                extract_prefix(&name).ok_or_else(|| {
                    Error::new_spanned(
                        &entry.ck_name,
                        "constant does not contain a prefix",
                    )
                })
            })
            .collect::<Result<_>>()?;

        let first = prefixes[0].clone();
        for (entry, prefix) in entries.iter().zip(prefixes.iter()) {
            if prefix != &first {
                return Err(Error::new_spanned(
                    &entry.ck_name,
                    format!(
                        "mismatched prefix: expected `{}`, found `{}`",
                        first, prefix
                    ),
                ));
            }
        }

        Ok(Pkcs11MechanismType {
            type_attrs,
            type_name,
            naming,
            entries,
            const_prefix: first,
        })
    }
}

fn is_vec_type(ty: &Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Vec";
        }
    }
    false
}

pub(crate) fn pkcs11_mechanism_type_impl(input: TokenStream) -> TokenStream {
    let Pkcs11MechanismType {
        type_attrs,
        type_name,
        naming,
        entries,
        const_prefix,
    } = parse_macro_input!(input as Pkcs11MechanismType);
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
        entry: &'a MechEntry,
    }

    let typed_entries: Vec<&MechEntry> = entries
        .iter()
        .filter(|e| e.ty.is_some() && !e.ck_name.to_string().ends_with("_VENDOR_DEFINED"))
        .collect();

    let name_pairs: Vec<NamePair> = typed_entries
        .iter()
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
                        #type_name::#mech_name(param) => std::mem::size_of_val(param.as_slice()) as Ulong,
                    }
                } else {
                    quote! {
                        #type_name::#mech_name(param) => std::mem::size_of_val(param) as Ulong,
                    }
                }
            }
            None => quote! { #type_name::#mech_name => 0 as Ulong, },
        }
    });

    let impl_ts = quote! {
        #[allow(clippy::len_without_is_empty)]
        impl<'a> #type_name<'a> {
            pub fn new_vendor_defined(
                mechanism_type: #attr_type_name,
                param: Option<&'a [Byte]>,
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

            pub fn len(&self) -> Ulong {
                match self {
                    #(#len_arms)*
                    #type_name::VendorDefined(m) => {
                        m.param.map_or(0, |p| std::mem::size_of_val(p) as Ulong)
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
