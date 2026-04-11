use {
    proc_macro::TokenStream,
    proc_macro2::TokenStream as TokenStream2,
    quote::quote,
    syn::{parse_macro_input, Ident},
};

use crate::{
    naming::{convert_name, NamingConvention},
    types::{
        input::{Pkcs11Type, TypeEntry},
        pkcs11_type_impl,
    },
};

pub(crate) fn pkcs11_attribute_type_impl(input: TokenStream) -> TokenStream {
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
        /// Identifies an attribute type.
        #attr_type_name: CK_ATTRIBUTE_TYPE, naming = ScreamingSnakeCase;
        [ #(#ck_const_list),* ]
    };

    let attr_type_ts: TokenStream2 = pkcs11_type_impl(pkcs11_type_ts.into()).into();

    //
    struct NamePair<'a> {
        attr_name: Ident,
        attr_type_const_name: Ident,
        entry: &'a TypeEntry,
    }

    let name_pairs: Vec<NamePair> = entries
        .iter()
        .filter(|e| e.ty.is_some() && !e.ck_name.to_string().ends_with("_VENDOR_DEFINED"))
        .map(|entry| {
            let ck_name_str = entry.ck_name.to_string();
            let attr_name = Ident::new(
                &convert_name(&ck_name_str, &const_prefix, &naming),
                entry.ck_name.span(),
            );
            let attr_type_const_name = Ident::new(
                &convert_name(
                    &ck_name_str,
                    &const_prefix,
                    &NamingConvention::ScreamingSnakeCase,
                ),
                entry.ck_name.span(),
            );
            NamePair {
                attr_name,
                attr_type_const_name,
                entry,
            }
        })
        .collect();

    // Type enumeration
    let enum_variants = name_pairs.iter().map(|p| {
        let (attrs, name, ty) =
            (&p.entry.attrs, &p.attr_name, p.entry.ty.as_ref().unwrap());
        quote! { #(#attrs)* #name(#ty) }
    });

    let enum_ts = quote! {
        #(#type_attrs)*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum #type_name {
            #(#enum_variants,)*
            /// Vendor-defined attribute.
            VendorDefined(VendorDefinedAttribute),
        }
    };

    // Type impl
    let attribute_type_arms = name_pairs.iter().map(|p| {
        let (attr_name, const_name) = (&p.attr_name, &p.attr_type_const_name);
        quote! {
            #type_name::#attr_name(_) => #attr_type_name::#const_name,
        }
    });

    let inner_value_arms = name_pairs.iter().map(|p| {
        let attr_name = &p.attr_name;
        quote! {
            #type_name::#attr_name(v) => v,
        }
    });

    let impl_ts = quote! {
        #[allow(clippy::len_without_is_empty)]
        impl #type_name {
            pub fn attribute_type(&self) -> #attr_type_name {
                match self {
                    #(#attribute_type_arms)*
                    #type_name::VendorDefined(v) => v.attr_type,
                }
            }

            pub fn inner_value(&self) -> &dyn AttributeValue {
                match self {
                    #(#inner_value_arms)*
                    #type_name::VendorDefined(v) => &v.value,
                }
            }

            pub fn ptr(&self) -> CK_VOID_PTR {
                self.inner_value().as_ck_ptr()
            }

            pub fn len(&self) -> Ulong {
                self.inner_value().len()
            }
        }
    };

    // From
    let from_ts = quote! {
        impl ::std::convert::From<&#type_name> for CK_ATTRIBUTE {
            fn from(attribute: &#type_name) -> Self {
                Self {
                    attrType: attribute.attribute_type().into(),
                    pValue: attribute.ptr(),
                    ulValueLen: attribute.len(),
                }
            }
        }
    };

    // TryFrom
    let try_from_arms = name_pairs.iter().map(|p| {
        let (attr_name, const_name, ty) = (
            &p.attr_name,
            &p.attr_type_const_name,
            p.entry.ty.as_ref().unwrap(),
        );
        quote! {
            #attr_type_name::#const_name => Ok(#type_name::#attr_name(
                <#ty as TryFromCkAttribute>::try_from_ck_attr(&ck_attribute)?
            )),
        }
    });

    let try_from_ts = quote! {
        impl ::std::convert::TryFrom<CK_ATTRIBUTE> for #type_name {
            type Error = Error;

            fn try_from(ck_attribute: CK_ATTRIBUTE) -> Result<Self> {
                let attr_type = #attr_type_name::try_from(ck_attribute.attrType)?;
                match attr_type {
                    #(#try_from_arms)*
                    _ => Ok(#type_name::VendorDefined(
                        VendorDefinedAttribute::try_from_ck_attr(&ck_attribute)?
                    )),
                }
            }
        }
    };

    // Generate the final code for a newtype: impl, traits.
    quote! {
        #attr_type_ts

        #enum_ts
        #impl_ts
        #from_ts
        #try_from_ts
    }
    .into()
}
