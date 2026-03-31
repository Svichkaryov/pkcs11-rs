use proc_macro::TokenStream;
use quote::quote;
use syn::{
    bracketed,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Attribute, Error, Ident, Result, Token,
};

#[allow(clippy::enum_variant_names)]
enum NamingConvention {
    // UpperCamelCase
    UpperCamelCase,
    // SCREAMING_SNAKE_CASE
    ScreamingSnakeCase,
    // snake_case
    SnakeCase,
}

impl Parse for NamingConvention {
    fn parse(input: ParseStream) -> Result<Self> {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "UpperCamelCase" => Ok(Self::UpperCamelCase),
            "ScreamingSnakeCase" => Ok(Self::ScreamingSnakeCase),
            "SnakeCase" => Ok(Self::SnakeCase),
            other => Err(Error::new(
                ident.span(),
                format!(
                    "unknown convention `{other}`, expected one of: \
                    UpperCamelCase, ScreamingSnakeCase, SnakeCase"
                ),
            )),
        }
    }
}

struct ConstEntry {
    /// Doc comments.
    attrs: Vec<Attribute>,
    /// A c-style pkcs#11 constant name.
    name: Ident,
}

impl Parse for ConstEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let name = input.parse()?;
        Ok(ConstEntry { attrs, name })
    }
}

fn extract_prefix(name: &str) -> Option<String> {
    let pos = name.find('_')?;
    if pos == 0 {
        return None; // "_FOO"
    }
    Some(name[..=pos].to_string())
}

/// Converts a PKCS#11 constant name to the desired naming convention,
/// stripping the common prefix.
fn convert_name(name: &str, prefix: &str, naming: &NamingConvention) -> String {
    let stripped = name.strip_prefix(prefix).unwrap_or(name);

    match naming {
        NamingConvention::UpperCamelCase => stripped
            .split('_')
            .filter(|p| !p.is_empty())
            .map(|word| {
                let mut result = String::with_capacity(word.len());
                let mut chars = word.chars();
                let first = chars.next().unwrap();
                result.extend(first.to_uppercase());
                result.extend(chars.flat_map(|c| c.to_lowercase()));
                result
            })
            .collect(),
        NamingConvention::ScreamingSnakeCase => stripped.to_uppercase(),
        NamingConvention::SnakeCase => stripped.to_lowercase(),
    }
}

/// Input for the `pkcs11_type!` procedure macro.
struct Pkcs11Type {
    /// Doc comments for the type impl.
    type_attrs: Vec<Attribute>,
    /// Type name.
    type_name: Ident,
    /// Inner type of the newtype.
    inner_type: Ident,
    /// Naming convention for generated constants
    /// (default: ScreamingSnakeCase).
    naming: NamingConvention,
    /// PKCS#11 C constant list.
    constants: Vec<ConstEntry>,
    /// Validated common prefix to all c-style pkcs#11 constants.
    const_prefix: String,
    /// Optional CK*_VENDOR_DEFINED constant. If present, generates extra
    /// methods for vendor-defined values.
    vendor_defined_const: Option<Ident>,
}

impl Parse for Pkcs11Type {
    fn parse(input: ParseStream) -> Result<Self> {
        let type_attrs = input.call(Attribute::parse_outer)?;
        let type_name: Ident = input.parse()?;

        input.parse::<Token![:]>()?;
        let inner_type: Ident = input.parse()?;

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
            NamingConvention::ScreamingSnakeCase
        };

        input.parse::<Token![;]>()?;

        // Parse list of constants in brackets
        let content;
        bracketed!(content in input);

        let constants: Vec<ConstEntry> =
            Punctuated::<ConstEntry, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .collect();

        // Validate list

        if constants.is_empty() {
            return Err(Error::new(
                type_name.span(),
                "expected at least one constant",
            ));
        }

        let prefixes: Vec<String> = constants
            .iter()
            .map(|entry| {
                let name = entry.name.to_string();
                extract_prefix(&name).ok_or_else(|| {
                    Error::new_spanned(&entry.name, "constant does not contain a prefix")
                })
            })
            .collect::<Result<_>>()?;

        let first = prefixes[0].clone();
        for (entry, prefix) in constants.iter().zip(prefixes.iter()) {
            if prefix != &first {
                return Err(Error::new_spanned(
                    &entry.name,
                    format!(
                        "mismatched prefix: expected `{}`, found `{}`",
                        first, prefix
                    ),
                ));
            }
        }

        let const_prefix = first;

        // Remove CK*_VENDOR_DEFINED contant marker from the main const list.
        let mut vendor_defined_const: Option<Ident> = None;
        let constants = constants
            .into_iter()
            .filter_map(|entry| {
                if entry.name.to_string().ends_with("_VENDOR_DEFINED") {
                    vendor_defined_const = Some(entry.name);
                    None
                } else {
                    Some(entry)
                }
            })
            .collect();

        Ok(Pkcs11Type {
            type_attrs,
            type_name,
            inner_type,
            naming,
            constants,
            const_prefix,
            vendor_defined_const,
        })
    }
}

/// Generate rust newtype and traits for a PKCS#11 type based on a list of
/// C-style constants.
///
/// /// # Example:
///
/// ```rust
/// pkcs11_type!(
///    /// PKCS#11 object classes.
///    ObjectClass: u64, naming = ScreamingSnakeCase;
///    [
///        /// Certificate objects hold public-key or attribute certificates.
///        CKO_CERTIFICATE,
///
///        /// Public key object.
///        CKO_PUBLIC_KEY,
///
///        /// Private key object.
///        CKO_PRIVATE_KEY,
///    ]
/// );
/// ```
#[proc_macro]
pub fn pkcs11_type(input: TokenStream) -> TokenStream {
    let Pkcs11Type {
        type_attrs,
        type_name,
        inner_type,
        naming,
        constants,
        const_prefix,
        vendor_defined_const,
    } = parse_macro_input!(input as Pkcs11Type);

    struct NamePair {
        // doc comments
        attrs: Vec<Attribute>,
        rust_name: Ident,
        c_name: Ident,
    }

    let name_pairs: Vec<NamePair> = constants
        .into_iter()
        .map(|entry| {
            let converted = convert_name(&entry.name.to_string(), &const_prefix, &naming);
            NamePair {
                attrs: entry.attrs,
                rust_name: Ident::new(&converted, entry.name.span()),
                c_name: entry.name,
            }
        })
        .collect();

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

    let type_name_str = type_name.to_string();

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

    // Generate the final code for a newtype: impl, traits.
    quote! {
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

        #optional_vendor_defined_impl

        impl ::std::ops::Deref for #type_name {
            type Target = #inner_type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl ::std::convert::From<#type_name> for #inner_type {
            fn from(val: #type_name) -> Self {
                *val
            }
        }

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

        impl ::std::fmt::Display for #type_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match *self {
                    #(#display_arms)*
                    #display_vendor_defined_ext
                    other => ::std::write!(f, "Unknown {}: {:#x}", #type_name_str, *other),
                }
            }
        }

        impl ::std::fmt::Debug for #type_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match *self {
                    #(#debug_arms)*
                    #debug_vendor_defined_ext
                    other => ::std::write!(f, "Unknown {}({:#x})", #type_name_str, *other),
                }
            }
        }
    }
    .into()
}
