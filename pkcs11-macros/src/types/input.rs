use syn::{
    Attribute, Error, Ident, Result, Token, Type, bracketed,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

use crate::naming::{NamingConvention, extract_prefix};

pub(crate) struct TypeEntry {
    /// Doc comments.
    pub attrs: Vec<Attribute>,
    /// A c-style pkcs#11 constant name.
    pub ck_name: Ident,
    /// Attribute type.
    pub ty: Option<Type>,
}

impl Parse for TypeEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let ck_name: Ident = input.parse()?;
        let ty = if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
            Some(input.parse::<Type>()?)
        } else {
            None
        };
        Ok(TypeEntry { attrs, ck_name, ty })
    }
}

/// Input for the pkcs11_* procedural macros.
pub(crate) struct Pkcs11Type {
    /// Doc comments and derive attributes for the type impl.
    pub type_attrs: Vec<Attribute>,
    /// Type name.
    pub type_name: Ident,
    /// Inner type of the newtype.
    pub inner_type: Option<Ident>,
    /// Naming convention for generated types
    /// (default: ScreamingSnakeCase).
    pub naming: NamingConvention,
    /// Entries with optional type.
    pub entries: Vec<TypeEntry>,
    /// Validated common prefix to all c-style pkcs#11 constants.
    pub const_prefix: String,
    /// Optional CK*_VENDOR_DEFINED constant. If present, generates extra
    /// methods for vendor-defined values.
    pub vendor_defined_const: Option<Ident>,
}

impl Parse for Pkcs11Type {
    fn parse(input: ParseStream) -> Result<Self> {
        let type_attrs = input.call(Attribute::parse_outer)?;
        let type_name: Ident = input.parse()?;

        let inner_type = if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
            Some(input.parse::<Ident>()?)
        } else {
            None
        };

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
        let entries: Vec<TypeEntry> =
            Punctuated::<TypeEntry, Token![,]>::parse_terminated(&content)?
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

        //
        let const_prefix = first;

        let vendor_defined_const = entries
            .iter()
            .find(|e| e.ck_name.to_string().ends_with("_VENDOR_DEFINED"))
            .map(|e| e.ck_name.clone());

        Ok(Pkcs11Type {
            type_attrs,
            type_name,
            inner_type,
            naming,
            entries,
            const_prefix,
            vendor_defined_const,
        })
    }
}
