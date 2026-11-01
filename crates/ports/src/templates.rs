//! The `TemplateRenderer` port.
//!
//! Mail and web templates ship German and English (`ENGINEERING_RULES` R15). A renderer turns a template name, a
//! locale, a theme and a JSON model into subject, HTML and plain text. The production adapter renders with
//! MiniJinja under strict undefined behaviour and auto-escaping, so a template that references a missing model
//! field fails loudly instead of printing an empty string.

use core::fmt;

use async_trait::async_trait;
use bytes::Bytes;
use davhaven_domain::{ETag, Locale};
use serde::{Deserialize, Serialize};

use crate::error::PortError;

/// The name of a template in the catalog, for example `imip_request` or `rsvp_page`.
///
/// One to 64 characters: lowercase letters, digits, `_`, `-` and `.`, starting with a letter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TemplateName(String);

/// Why text is not a valid [`TemplateName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid template name: use 1 to 64 lowercase letters, digits, `_`, `-` or `.`, starting with a letter")]
pub struct TemplateNameError;

impl TemplateName {
    /// Validates a template name.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateNameError`] when the text is empty, longer than 64 bytes, does not start with a lowercase
    /// letter or contains other characters than lowercase letters, digits, `_`, `-` and `.`.
    pub fn parse(input: &str) -> Result<Self, TemplateNameError> {
        let mut bytes = input.bytes();
        let starts_with_letter = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'));
        if input.len() <= 64 && starts_with_letter && rest_ok {
            Ok(Self(input.to_owned()))
        } else {
            Err(TemplateNameError)
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TemplateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for TemplateName {
    type Err = TemplateNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<String> for TemplateName {
    type Error = TemplateNameError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Self::parse(&input)
    }
}

impl From<TemplateName> for String {
    fn from(name: TemplateName) -> Self {
        name.0
    }
}

/// What to render.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderRequest {
    /// The template to render.
    pub template: TemplateName,
    /// The locale of the recipient or page visitor; the renderer falls back to its default locale when it has no
    /// translation.
    pub locale: Locale,
    /// The theme name (`tenant.settings.theme`), empty when the tenant names none. The renderer uses its default theme
    /// (`templates.default_theme`) for an empty name and falls back to it for a name that is not loaded; the contract suite
    /// checks that every implementation does. (An empty string is the sentinel of "no theme", which the next break of
    /// this contract should replace with an `Option` or a choice type.)
    pub theme: String,
    /// The template model. Templates may only use fields that are present (strict undefined behaviour).
    pub model: serde_json::Value,
}

/// A rendered template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The subject line (mail templates) or the title of a page. It is plain text, rendered without
    /// auto-escaping: whoever puts it into HTML (a page title, a heading) must escape it, because it can carry
    /// event summaries and names.
    pub subject: String,
    /// The HTML body, auto-escaped.
    pub html: String,
    /// The plain text alternative.
    pub text: String,
}

/// A static file of a theme (a style sheet, a logo) that the web layer serves as `/assets/{theme}/{file}`.
///
/// Themes are trusted configuration, but the files are checked when they are loaded: a flat directory, plain
/// file names, a fixed list of media types and a size limit, so serving never touches the file system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeAsset {
    /// The media type to answer with, for example `text/css; charset=utf-8`.
    pub content_type: &'static str,
    /// The content.
    pub body: Bytes,
    /// The strong entity tag of `body`.
    pub etag: ETag,
}

/// Renders mail and web templates.
#[async_trait]
pub trait TemplateRenderer: Send + Sync {
    /// Renders a template.
    ///
    /// # Errors
    ///
    /// * `Invalid`: the template does not exist in the catalog, or the model lacks a field the template uses.
    /// * `Internal`: the template or theme is broken.
    async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError>;

    /// Renders a template for a visitor who named several languages, best first (the entries of `Accept-Language`): the
    /// first of them in which the theme has the template wins, then the renderer's default locale. `request.locale` is
    /// the visitor's best language and is what a renderer that does not know the list uses; the default implementation is
    /// exactly that, so only a renderer that has translations to choose from needs to override it.
    ///
    /// # Errors
    ///
    /// As [`render`](Self::render).
    async fn render_preferring(&self, request: RenderRequest, preferred: &[Locale]) -> Result<Rendered, PortError> {
        let mut request = request;
        if let Some(best) = preferred.first() {
            request.locale = best.clone();
        }
        self.render(request).await
    }

    /// The names of every template the renderer can render, sorted.
    fn catalog(&self) -> Vec<TemplateName>;

    /// The static file `file` of `theme`, for the web layer's `/assets/{theme}/{file}`.
    ///
    /// A theme that lacks the file falls back to the built-in files, so the page layout of a theme that ships no
    /// style sheet of its own still finds `page.css`. The default has no assets: renderers that only render text
    /// need not provide any.
    fn asset(&self, _theme: &str, _file: &str) -> Option<ThemeAsset> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_names_follow_the_documented_charset() {
        for ok in ["imip_request", "rsvp_page", "a", "mail.imip-cancel.v2", "x0"] {
            assert_eq!(TemplateName::parse(ok).unwrap().as_str(), ok);
        }
        let too_long = "a".repeat(65);
        for bad in ["", "Imip", "1abc", "_abc", "a b", "a/b", "ä", "a\n", too_long.as_str()] {
            assert_eq!(TemplateName::parse(bad), Err(TemplateNameError), "{bad:?}");
        }
        assert!(TemplateName::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn template_names_serialize_as_plain_strings() {
        let name: TemplateName = "imip_request".parse().unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"imip_request\"");
        assert_eq!(serde_json::from_str::<TemplateName>("\"imip_request\"").unwrap(), name);
        assert!(serde_json::from_str::<TemplateName>("\"Bad Name\"").is_err());
        assert_eq!(name.to_string(), "imip_request");
        assert_eq!(String::from(name), "imip_request");
    }
}
