// https://tools.ietf.org/html/draft-foudil-securitytxt-09

use chrono::prelude::*;
use core::str::FromStr;
use language_tags::LanguageTag;
use std::error::Error;
use std::fmt;
use url::Url;

/// The conventional name of the file.
pub const FILENAME: &str = "security.txt";

/// The path under which security.txt MUST be placed, when served over HTTP
pub const WELL_KNOWN_PATH: &str = "/.well-known/security.txt";

/// The required file format of the "security.txt" file (MUST be plain text).
pub const MIMETYPE: &str = "text/plain";

#[derive(Debug, PartialEq)]
pub enum Field {
    Acknowledgments(Url), // Required HTTPS?
    Canonical(Url),       // Required HTTPS?
    Contact(Url),
    Encryption(Url),
    Expires(DateTime<FixedOffset>), // Must appear only once
    Hiring(Url),                    // Required HTTPS?
    Policy(Url),
    PreferredLanguages(Vec<LanguageTag>), // Must appear only once
    Extension(String, String),
}

fn split_at_str(string: &str, pattern: char) -> Option<(&str, &str)> {
    let mut split = string.splitn(2, pattern);
    let first = split.next().unwrap();
    match split.next() {
        Some(second) => Some((first, second)),
        None => None,
    }
}

fn parse_rfc5322_datetime(string: &str) -> chrono::ParseResult<DateTime<FixedOffset>> {
    // TODO: See https://tools.ietf.org/html/rfc5322#section-3.3
    DateTime::parse_from_str(string, "")
}

impl FromStr for Field {
    type Err = ParseError;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if let Some((name, value)) = split_at_str(string, ':') {
            return Ok(match &*name.to_lowercase() {
                "acknowledgments" => Self::Acknowledgments(Url::parse(value)?),
                "canonical" => Self::Canonical(Url::parse(value)?),
                "contact" => Self::Contact(Url::parse(value)?),
                "encryption" => Self::Encryption(Url::parse(value)?),
                "expires" => Self::Expires(parse_rfc5322_datetime(value)?),
                "hiring" => Self::Hiring(Url::parse(value)?),
                "policy" => Self::Policy(Url::parse(value)?),
                "preferred-languages" => {
                    let languages = value
                        .split(',')
                        .map(|s| LanguageTag::from_str(s))
                        .collect::<Result<_, _>>()?;
                    Self::PreferredLanguages(languages)
                }
                _ => Self::Extension(name.into(), value.into()),
            });
        }
        Err(ParseError("Missing `:`".into()))
    }
}

/// Signifies an error in the specification
#[derive(Debug, PartialEq)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ParseError {}

impl From<language_tags::Error> for ParseError {
    fn from(error: language_tags::Error) -> Self {
        ParseError(error.to_string())
    }
}

impl From<url::ParseError> for ParseError {
    fn from(error: url::ParseError) -> Self {
        ParseError(error.to_string())
    }
}

impl From<chrono::format::ParseError> for ParseError {
    fn from(error: chrono::format::ParseError) -> Self {
        ParseError(error.to_string())
    }
}

pub enum Line {
    Field(Field),
    Comment(String),
}

impl FromStr for Line {
    type Err = ParseError;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if let Some(string) = string.strip_prefix("#") {
            Ok(Self::Comment(string.into()))
        } else {
            Ok(Self::Field(Field::from_str(string)?))
        }
    }
}

pub fn parse_fields<'a>(string: &'a str) -> impl Iterator<Item = Result<Field, ParseError>> + 'a {
    string
        .lines()
        .filter_map(|line| match Line::from_str(line) {
            Ok(Line::Field(field)) => Some(Ok(field)),
            Ok(Line::Comment(_)) => None,
            Err(e) => Some(Err(e)),
        })
}

pub fn parse(string: &str) -> Result<SecurityTxt, ParseError> {
    SecurityTxt::from_str(string)
}

#[derive(Debug, PartialEq)]
pub struct SecurityTxt {
    acknowledgments: Vec<Url>,
    canonical: Vec<Url>,
    /// Always at least one present
    contacts: (Url, Vec<Url>),
    encryptions: Vec<Url>,
    /// Must appear once and only once
    expires: DateTime<FixedOffset>,
    hiring: Vec<Url>,
    policies: Vec<Url>,
    /// The tag must appear only once
    preferred_languages: Vec<LanguageTag>,
    extensions: Vec<(String, String)>,
}

impl FromStr for SecurityTxt {
    type Err = ParseError;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut acknowledgments = vec![];
        let mut canonical = vec![];
        let mut contacts: Option<(_, Vec<_>)> = None;
        let mut encryptions = vec![];
        let mut expires = None;
        let mut hiring = vec![];
        let mut policies = vec![];
        let mut preferred_languages = None;
        let mut extensions = vec![];

        for field in parse_fields(string) {
            match field? {
                Field::Acknowledgments(url) => acknowledgments.push(url),
                Field::Canonical(url) => canonical.push(url),
                Field::Contact(url) => {
                    if let Some((_, rest)) = &mut contacts {
                        rest.push(url);
                    } else {
                        contacts = Some((url, vec![]));
                    }
                }
                Field::Encryption(url) => encryptions.push(url),
                Field::Expires(dt) => {
                    if expires.is_some() {
                        return Err(ParseError("The Expires field must only appear once".into()));
                    } else {
                        expires = Some(dt);
                    }
                }
                Field::Hiring(url) => hiring.push(url),
                Field::Policy(url) => policies.push(url),
                Field::PreferredLanguages(languages) => {
                    if preferred_languages.is_some() {
                        return Err(ParseError(
                            "The Preferred-Languages field must only appear once".into(),
                        ));
                    } else {
                        preferred_languages = Some(languages)
                    }
                }
                Field::Extension(s1, s2) => extensions.push((s1, s2)),
            }
        }

        let contacts =
            contacts.ok_or_else(|| ParseError("Must have at least one Contact field".into()))?;

        let expires = expires.ok_or_else(|| ParseError("Must have an Expires field".into()))?;

        let preferred_languages = preferred_languages.unwrap_or_else(|| vec![]);

        Ok(Self {
            acknowledgments,
            canonical,
            contacts,
            encryptions,
            expires,
            hiring,
            policies,
            preferred_languages,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(
            Ok(Field::Acknowledgments(
                Url::parse("https://abc.com").unwrap()
            )),
            Field::from_str("Acknowledgments:https://abc.com")
        );
    }
}
