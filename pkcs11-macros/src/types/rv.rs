use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{Ident, parse_macro_input};

use crate::{
    naming::convert_name,
    types::input::{Pkcs11Type, TypeEntry},
};

pub(crate) fn pkcs11_rv_type_impl(input: TokenStream) -> TokenStream {
    let Pkcs11Type {
        type_attrs,
        type_name,
        inner_type: _,
        naming,
        entries,
        const_prefix,
        vendor_defined_const,
    } = parse_macro_input!(input as Pkcs11Type);
    struct NamePair<'a> {
        rust_name: Ident,
        c_name: Ident,
        entry: &'a TypeEntry,
    }

    let name_pairs: Vec<NamePair> = entries
        .iter()
        .map(|entry| {
            let converted =
                convert_name(&entry.ck_name.to_string(), &const_prefix, &naming);
            NamePair {
                rust_name: Ident::new(&converted, entry.ck_name.span()),
                c_name: entry.ck_name.clone(),
                entry,
            }
        })
        .collect();

    // Type enumeration
    let enum_variants = name_pairs.iter().map(|p| {
        let (attrs, name, ty) = (&p.entry.attrs, &p.rust_name, &p.entry.ty);
        match ty {
            Some(ty) => quote! { #(#attrs)* #name(#ty), },
            None => quote! { #(#attrs)* #name, },
        }
    });

    let enum_ts = quote! {
        #(#type_attrs)*
        pub enum #type_name {
            #(#enum_variants)*
            /// Undefined return value.
            Undefined(CK_RV),
        }
    };

    // Display
    let display_arms = name_pairs.iter().map(|p| {
        let (c_name, rust_name, description, ty) = (
            &p.c_name,
            &p.rust_name,
            doc_to_display_string(&p.entry.attrs),
            &p.entry.ty,
        );

        let is_vendor_variant =
            ty.is_some() && vendor_defined_const.as_ref() == Some(c_name);

        if is_vendor_variant {
            let fmt = format!(
                "Identifier: VendorDefined({{v:#X}}). Description: {description}"
            );
            quote! { #type_name::#rust_name(v) => ::std::write!(f, #fmt), }
        } else if ty.is_some() {
            // skip
            quote! {}
        } else {
            let fmt = format!("Identifier: {{self:?}}. Description: {description}");
            quote! { #type_name::#rust_name => ::std::write!(f, #fmt), }
        }
    });

    let display_ts = quote! {
        impl ::std::fmt::Display for #type_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match self {
                    #(#display_arms)*
                    #type_name::Undefined(v) => ::std::write!(
                        f,
                        "Identifier: Undefined({v:#X}). Description: \
                         Undefined return value.",
                    ),
                }
            }
        }
    };

    // From
    let from_arms = name_pairs.iter().map(|p| {
        let (c_name, rust_name, ty) = (&p.c_name, &p.rust_name, &p.entry.ty);

        let is_vendor_variant =
            ty.is_some() && vendor_defined_const.as_ref() == Some(c_name);
        if is_vendor_variant {
            quote! { v if v >= #c_name => #type_name::#rust_name(v), }
        } else if ty.is_some() {
            // skip
            quote! {}
        } else {
            quote! { #c_name => #type_name::#rust_name, }
        }
    });

    let from_ts = quote! {
        impl ::std::convert::From<CK_RV> for #type_name {
            fn from(ck_rv: CK_RV) -> Self {
                match ck_rv {
                    #(#from_arms)*
                    other => #type_name::Undefined(other),
                }
            }
        }
    };

    // Type impl
    let ok_variant = name_pairs
        .iter()
        .find(|p| p.c_name == "CKR_OK")
        .map(|p| p.rust_name.clone())
        .unwrap_or_else(|| Ident::new("Ok", Span::call_site()));

    let impl_ts = quote! {
        impl #type_name {
            /// Convert the return value into a standard [`Result`].
            ///
            /// [`Result`]: crate::doc_links::Result
            pub fn into_result(self) -> ::std::result::Result<(), crate::error::Error> {
                match self {
                    #type_name::#ok_variant => ::std::result::Result::Ok(()),
                    err => ::std::result::Result::Err(
                        crate::error::Error::Pkcs11(err)
                    ),
                }
            }
        }
    };

    quote! {
        #enum_ts
        #display_ts
        #from_ts
        #impl_ts
    }
    .into()
}

/// Determines whether a line is a [`link to a target`].
///
/// [`link to a target`]: https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#link-all-the-things
fn is_link_target(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with('[') {
        return false;
    }
    t.find(']')
        .map(|i| t[i + 1..].trim_start().starts_with(':'))
        .unwrap_or(false)
}

/// Convert the documentation from attributes into a single line for the
/// Display trait and remove the Link targets at the end.
#[allow(clippy::collapsible_if)]
fn doc_to_display_string(attrs: &[syn::Attribute]) -> String {
    use syn::{Expr, Lit, Meta};

    attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .filter_map(|a| {
            if let Meta::NameValue(mnv) = &a.meta {
                if let Expr::Lit(el) = &mnv.value {
                    if let Lit::Str(s) = &el.lit {
                        let line = s.value();
                        if !is_link_target(&line) {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                return Some(trimmed.to_owned());
                            }
                        }
                    }
                }
            }
            None
        })
        .collect::<Vec<_>>()
        .join(" ")
}
