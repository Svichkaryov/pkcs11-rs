use syn::{
    Error, Ident, Result,
    parse::{Parse, ParseStream},
};

#[allow(clippy::enum_variant_names)]
pub(crate) enum NamingConvention {
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

pub(crate) fn extract_prefix(name: &str) -> Option<String> {
    let pos = name.find('_')?;
    if pos == 0 {
        return None; // "_FOO"
    }
    Some(name[..=pos].to_string())
}

/// Converts a PKCS#11 constant name to the desired naming convention,
/// stripping the common prefix.
pub(crate) fn convert_name(
    name: &str,
    prefix: &str,
    naming: &NamingConvention,
) -> String {
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
