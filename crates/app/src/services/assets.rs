//! Static theme assets: the style sheet and the images of the pages the web surface renders.

use async_trait::async_trait;
use bytes::Bytes;
use davhaven_domain::{ETag, Locale, RequestContext};

use crate::error::{AppError, AppResult};
use crate::services::RenderedPage;

/// A static file of a theme, ready to be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAsset {
    /// The media type to answer with, for example `text/css; charset=utf-8`.
    pub content_type: &'static str,
    /// The content.
    pub body: Bytes,
    /// The strong entity tag of the content; the web layer answers `304` for clients that have it.
    pub etag: ETag,
}

/// The static assets of the themes (`GET /assets/{theme}/{file}`).
///
/// Assets are public: no credential, no tenant. The files come from the theme directories of the deployment and
/// from the built-in theme, which every theme falls back to.
#[async_trait]
pub trait AssetService: Send + Sync {
    /// The file `file` of `theme`, or of the built-in theme when the theme has none of that name.
    ///
    /// # Errors
    ///
    /// `NotFound` when neither the theme nor the built-in theme has the file, or when `theme` or `file` are not
    /// plain names (the lookup never touches the file system, so no name can leave the theme directory).
    async fn get(&self, ctx: &RequestContext, theme: &str, file: &str) -> AppResult<StaticAsset>;

    /// The page that tells a visitor of the web surface that a link cannot be served, rendered by the `rsvp_unavailable`
    /// template for the HTTP `status` of the failure (404 for a link that is unknown, expired or withdrawn, 429 for a
    /// visitor who has to wait, 5xx for a service that is not available, any other 4xx for a request that was refused).
    ///
    /// The page is made for a visitor whose link does not authenticate, so it knows no tenant (and must not reveal
    /// that a link ever existed): it is rendered in the theme the deployment chose (`templates.default_theme`) and in
    /// the first of `languages` (the visitor's, best first, as the web layer reads them from `Accept-Language`) in which
    /// that theme has the page, else in the deployment's default language. It contains nothing the request or the
    /// application chose: no path, no token, no message. The page depends on the status and the languages only, so the
    /// service keeps the pages it has rendered.
    ///
    /// # Errors
    ///
    /// `Unavailable` or `Internal` when the template cannot be rendered; the caller falls back to its static page.
    async fn unavailable_page(
        &self,
        _ctx: &RequestContext,
        _status: u16,
        _languages: &[Locale],
    ) -> AppResult<RenderedPage> {
        // unsupported-allowed: AssetServiceImpl implements the method; the default serves test doubles.
        Err(AppError::unsupported())
    }
}
