//! The [`AssetService`] of the application: static theme assets from the template renderer.
//!
//! The web surface answers every page with a strict `Content-Security-Policy` (`style-src 'self'`, no inline
//! styles), so the pages link their style sheet from the server's own origin: `/assets/{theme}/page.css`. The
//! files are the renderer's to know (it loads the `assets/` directories of the theme directories and carries the
//! built-in ones), and the web layer may depend on the application only, so the way from one to the other is this
//! service: `web` calls [`AssetService::get`], the service asks `TemplateRenderer::asset`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{Locale, RequestContext};
use davhaven_ports::{RenderRequest, TemplateName};
use serde_json::json;
use tokio::sync::Mutex;

use crate::error::{AppError, AppResult};
use crate::services::{AssetService, RenderedPage, StaticAsset};
use crate::wiring::AppCore;

/// The longest theme name and file name the service looks up, in bytes.
const MAX_NAME_BYTES: usize = 100;

/// The pages of failures that were rendered, by status and languages (see [`AssetService::unavailable_page`]).
type Pages = Arc<Mutex<HashMap<(u16, String), RenderedPage>>>;

/// The [`AssetService`] on the shared application core.
#[derive(Debug, Clone)]
pub struct AssetServiceImpl {
    core: AppCore,
    pages: Pages,
}

impl AssetServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            core,
            pages: Pages::default(),
        }
    }
}

/// Whether `name` is a plain name: letters, digits, `.`, `_` and `-`, not starting with a dot.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[async_trait]
impl AssetService for AssetServiceImpl {
    async fn get(&self, _ctx: &RequestContext, theme: &str, file: &str) -> AppResult<StaticAsset> {
        if !plain(theme) || !plain(file) {
            return Err(AppError::not_found());
        }
        let asset = self
            .core
            .deps()
            .templates
            .asset(theme, file)
            .ok_or_else(AppError::not_found)?;
        Ok(StaticAsset {
            content_type: asset.content_type,
            body: asset.body,
            etag: asset.etag,
        })
    }

    async fn unavailable_page(
        &self,
        _ctx: &RequestContext,
        status: u16,
        languages: &[Locale],
    ) -> AppResult<RenderedPage> {
        // A visitor chooses the languages, so only the first few count.
        let preferred: Vec<Locale> = languages.iter().take(MAX_LANGUAGES).cloned().collect();
        let key = (
            status,
            preferred.iter().map(Locale::as_str).collect::<Vec<_>>().join(","),
        );
        if let Some(page) = self.pages.lock().await.get(&key) {
            return Ok(page.clone());
        }
        // "und" is the language tag of "undetermined": no theme has files for it, so the renderer answers in the default
        // locale of the deployment (`templates.default_locale`), and English at the last.
        let locale = match preferred.first() {
            Some(locale) => locale.clone(),
            None => Locale::parse(UNDETERMINED).map_err(AppError::internal)?,
        };
        let rendered = self
            .core
            .deps()
            .templates
            .render_preferring(
                RenderRequest {
                    template: TemplateName::parse("rsvp_unavailable").map_err(AppError::internal)?,
                    locale,
                    // No tenant: the empty theme name is the deployment's default theme.
                    theme: String::new(),
                    model: json!({ "status": status }),
                },
                &preferred,
            )
            .await?;
        let page = RenderedPage { html: rendered.html };
        let mut pages = self.pages.lock().await;
        if pages.len() < MAX_PAGES {
            pages.insert(key, page.clone());
        }
        Ok(page)
    }
}

/// The language tag of a visitor who named no language.
const UNDETERMINED: &str = "und";

/// How many of the languages of a visitor the page considers.
const MAX_LANGUAGES: usize = 5;

/// How many pages the service keeps: a few statuses in a few languages. The languages are the visitor's to choose, so the
/// number is bounded; a visitor that asks for more combinations than that gets the page rendered every time.
const MAX_PAGES: usize = 64;

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use davhaven_domain::{ETag, ErrorKind, RequestId, TenantId};
    use davhaven_ports::{RenderRequest, Rendered, TemplateName, TemplateRenderer, ThemeAsset};
    use uuid::Uuid;

    use super::*;
    use crate::outbox::fixture::Fixture;

    /// A renderer whose only asset is `corporate/logo.png`.
    struct Themed;

    #[async_trait]
    impl TemplateRenderer for Themed {
        async fn render(&self, _request: RenderRequest) -> Result<Rendered, davhaven_ports::PortError> {
            Err(davhaven_ports::PortError::unsupported())
        }

        fn catalog(&self) -> Vec<TemplateName> {
            Vec::new()
        }

        fn asset(&self, theme: &str, file: &str) -> Option<ThemeAsset> {
            (theme == "corporate" && file == "logo.png").then(|| ThemeAsset {
                content_type: "image/png",
                body: Bytes::from_static(b"\x89PNG"),
                etag: ETag::from_bytes(b"\x89PNG"),
            })
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(0)),
            RequestId::from_uuid(Uuid::from_u128(1)),
        )
    }

    #[tokio::test]
    async fn the_service_serves_what_the_renderer_has_and_nothing_else() {
        let fixture = Fixture::with(|deps| deps.templates = std::sync::Arc::new(Themed));
        let service = AssetServiceImpl::new(fixture.core.clone());
        let asset = service.get(&ctx(), "corporate", "logo.png").await.unwrap();
        assert_eq!(asset.content_type, "image/png");
        assert_eq!(asset.body.as_ref(), b"\x89PNG");
        assert_eq!(asset.etag, ETag::from_bytes(b"\x89PNG"));
        for (theme, file) in [("corporate", "other.png"), ("other", "logo.png")] {
            let error = service.get(&ctx(), theme, file).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound, "{theme}/{file}");
        }
    }

    #[tokio::test]
    async fn names_that_are_not_plain_are_not_looked_up_at_all() {
        // The renderer would answer for `corporate/logo.png`; none of these may reach it.
        let fixture = Fixture::with(|deps| deps.templates = std::sync::Arc::new(Themed));
        let service = AssetServiceImpl::new(fixture.core.clone());
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        for (theme, file) in [
            ("..", "logo.png"),
            (".corporate", "logo.png"),
            ("corporate/..", "logo.png"),
            ("corporate", "../logo.png"),
            ("corporate", "sub/logo.png"),
            ("corporate", "..\\logo.png"),
            ("corporate", ".hidden"),
            ("corporate", ""),
            ("", "logo.png"),
            ("corporate", "logo.png\0"),
            ("corporate", "logo%2epng"),
            (long.as_str(), "logo.png"),
            ("corporate", long.as_str()),
        ] {
            let error = service.get(&ctx(), theme, file).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound, "{theme:?} {file:?}");
        }
    }

    /// A renderer that records what it is asked for the page of a failure and answers with it.
    #[derive(Default)]
    struct Pages {
        asked: tokio::sync::Mutex<Vec<(RenderRequest, Vec<Locale>)>>,
        broken: bool,
    }

    #[async_trait]
    impl TemplateRenderer for Pages {
        async fn render(&self, _request: RenderRequest) -> Result<Rendered, davhaven_ports::PortError> {
            Err(davhaven_ports::PortError::unsupported())
        }

        async fn render_preferring(
            &self,
            request: RenderRequest,
            preferred: &[Locale],
        ) -> Result<Rendered, davhaven_ports::PortError> {
            self.asked.lock().await.push((request.clone(), preferred.to_vec()));
            if self.broken {
                return Err(davhaven_ports::PortError::internal("the theme is broken"));
            }
            let languages: Vec<&str> = preferred.iter().map(Locale::as_str).collect();
            Ok(Rendered {
                subject: String::new(),
                html: format!("page {} for {}", request.model["status"], languages.join(",")),
                text: String::new(),
            })
        }

        fn catalog(&self) -> Vec<TemplateName> {
            Vec::new()
        }
    }

    fn service_with(renderer: Arc<Pages>) -> AssetServiceImpl {
        let fixture = Fixture::with(move |deps| deps.templates = renderer);
        AssetServiceImpl::new(fixture.core.clone())
    }

    fn locales(tags: &[&str]) -> Vec<Locale> {
        tags.iter().map(|tag| Locale::parse(tag).unwrap()).collect()
    }

    #[tokio::test]
    async fn the_page_of_a_failure_is_the_template_in_the_default_theme_in_the_languages_of_the_visitor() {
        let renderer = Arc::new(Pages::default());
        let service = service_with(Arc::clone(&renderer));
        let languages = locales(&["fr", "de-AT", "en"]);
        let page = service.unavailable_page(&ctx(), 404, &languages).await.unwrap();
        assert_eq!(page.html, "page 404 for fr,de-AT,en");
        let asked = renderer.asked.lock().await;
        let (request, preferred) = &asked[0];
        assert_eq!(request.template.as_str(), "rsvp_unavailable");
        assert_eq!(request.theme, "", "the deployment's default theme: no tenant is known");
        assert_eq!(request.model, json!({ "status": 404 }));
        assert_eq!(request.locale.as_str(), "fr", "the best language of the visitor");
        assert_eq!(
            preferred, &languages,
            "the renderer sees the whole ranking and picks what the theme ships"
        );
        drop(asked);

        // A visitor who named nothing gets the default of the deployment: the renderer is told no language at all.
        let plain = service.unavailable_page(&ctx(), 503, &[]).await.unwrap();
        assert_eq!(plain.html, "page 503 for ");
        let asked = renderer.asked.lock().await;
        assert_eq!(asked[1].0.locale.as_str(), UNDETERMINED);
        assert_eq!(asked[1].1, Vec::<Locale>::new());
    }

    #[tokio::test]
    async fn only_the_first_languages_of_a_visitor_count() {
        let renderer = Arc::new(Pages::default());
        let service = service_with(Arc::clone(&renderer));
        let many = locales(&["aa", "bb", "cc", "dd", "ee", "ff", "gg"]);
        let page = service.unavailable_page(&ctx(), 404, &many).await.unwrap();
        assert_eq!(page.html, "page 404 for aa,bb,cc,dd,ee");
    }

    #[tokio::test]
    async fn a_page_is_rendered_once_for_a_status_and_languages() {
        let renderer = Arc::new(Pages::default());
        let service = service_with(Arc::clone(&renderer));
        let german = locales(&["de"]);
        let first = service.unavailable_page(&ctx(), 404, &german).await.unwrap();
        let again = service.unavailable_page(&ctx(), 404, &german).await.unwrap();
        assert_eq!(first, again);
        assert_eq!(
            renderer.asked.lock().await.len(),
            1,
            "the second request costs no rendering"
        );
        // Another status, another language and another ranking are other pages.
        service.unavailable_page(&ctx(), 429, &german).await.unwrap();
        service.unavailable_page(&ctx(), 404, &locales(&["en"])).await.unwrap();
        service
            .unavailable_page(&ctx(), 404, &locales(&["de", "en"]))
            .await
            .unwrap();
        assert_eq!(renderer.asked.lock().await.len(), 4);
        // The copy of the service shares its pages.
        service.clone().unavailable_page(&ctx(), 404, &german).await.unwrap();
        assert_eq!(renderer.asked.lock().await.len(), 4);
    }

    #[tokio::test]
    async fn the_number_of_kept_pages_is_bounded_because_the_visitor_chooses_the_languages() {
        let renderer = Arc::new(Pages::default());
        let service = service_with(Arc::clone(&renderer));
        for status in 400..(400 + u16::try_from(MAX_PAGES).unwrap()) {
            service.unavailable_page(&ctx(), status, &[]).await.unwrap();
        }
        let before = renderer.asked.lock().await.len();
        assert_eq!(before, MAX_PAGES);
        // The table is full: a page that is not in it is rendered every time, and the pages in it are still served from it.
        service.unavailable_page(&ctx(), 599, &[]).await.unwrap();
        service.unavailable_page(&ctx(), 599, &[]).await.unwrap();
        service.unavailable_page(&ctx(), 400, &[]).await.unwrap();
        assert_eq!(renderer.asked.lock().await.len(), before + 2);
    }

    #[tokio::test]
    async fn a_page_that_cannot_be_rendered_is_an_error_and_is_not_kept() {
        let renderer = Arc::new(Pages {
            broken: true,
            ..Pages::default()
        });
        let service = service_with(Arc::clone(&renderer));
        for _ in 0..2 {
            let error = service.unavailable_page(&ctx(), 404, &[]).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Internal);
        }
        assert_eq!(renderer.asked.lock().await.len(), 2);
    }

    #[test]
    fn plain_names_are_letters_digits_dots_underscores_and_dashes() {
        for good in ["page.css", "logo-2.min.png", "a_b", "A1"] {
            assert!(plain(good), "{good}");
        }
        for bad in ["", ".a", "a/b", "a b", "ä", "a\\b"] {
            assert!(!plain(bad), "{bad:?}");
        }
    }
}
