use syn::{
    parse::{Parse, ParseStream},
    Attribute, Ident, Result, Token, Type,
};

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
