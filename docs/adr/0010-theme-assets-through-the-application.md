# ADR-0010: Theme assets reach the web surface through the application

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.1 (crates, layering), 2.13 (RSVP pages); R1; crates `web`, `templates`, `app`

## Context

The pages of the web surface (RSVP, OAuth result) are served under a strict content security policy: no scripts, no
inline styles, `style-src 'self'`. The page templates therefore link a style sheet of the own origin,
`/assets/{theme}/page.css`, and a deployment's theme may ship more files (a logo). The files belong to the template
renderer: it loads the `assets/` directories of the theme directories and carries the built-in ones.

The obvious implementation, a route that makes the web crate depend on the templates crate to read those files, breaks R1: the
edge layers depend on the application and not on adapters, and the architecture check allows only the server and the
testkit to know them.

## Decision

The route goes through the application, like everything else the edges do:

- `davhaven_ports::TemplateRenderer::asset(theme, file) -> Option<ThemeAsset>` (default `None`) returns the static file
  with its media type and a strong ETag. A theme that lacks the file falls back to the built-in one.
- `davhaven_app::services::AssetService::get(ctx, theme, file)` is the service the edges call (`AppServices::assets`). It
  accepts plain names only (letters, digits, `.`, `_`, `-`, not starting with a dot, at most 100 bytes), so a path that
  could leave the directory cannot even be expressed, and answers `NotFound` for everything else.
- The web route `GET /assets/{theme}/{file}` answers 200 with the content type, the ETag and a cache header, or 304 for a
  current `If-None-Match`, and a plain 404 otherwise. It never touches the file system and names no adapter.

Files are checked when the theme is loaded (a flat directory, plain names, a fixed list of media types, a size limit);
symbolic links are followed (configuration volumes of container platforms are mounted that way), so theme directories
belong to the operator.

## Themes are layered, and templates know the time

A deployment brands the mails and pages by changing the layout (`_mail.html`, `_page.html`), the footers and the style
sheet, and wants the content templates (what an invitation says) from the default theme. If partials resolved only inside
the theme of the template that included them, a theme that brought only its layout would not get its layout around the
default content, and a page rendered from a default template would link `/assets/default/page.css` whatever theme was asked
for. **Themes are therefore layered:** a request is rendered *in* a theme `T`, and what `T` lacks comes from the themes it falls
back to, in the order `T`, the deployment's `templates.default_theme`, `default`, the built-in theme; the theme `default` itself
falls back to the built-in theme alone, so that a tenant that names the neutral theme never takes on the branding of the
deployment's default theme through a partial `default` directory. A *template* comes as
a whole from the first theme that provides it for the locale (a theme that provides a template provides all its parts), a
*partial* (a file whose name starts with `_`) file by file; partials are always looked up in `T` first. The layers are
flattened when the themes are loaded (the files of the fallback themes are registered again under the name of `T`), so
`{% extends %}` and `{% include %}` stay a plain lookup inside one theme, and every template of every theme, inherited ones
included, is rendered with the sample models at startup and in `davhaven config check`; a layout that does not render the
`content` block of the templates it wraps is refused there, because the engine would drop the block without an error and the
mail or page would go out empty. The `theme` variable is the theme the request was rendered in, so the page links the style
sheet of the theme that was asked for. `Themes` owns the order (which theme a request is rendered in, which templates and
assets it finds), and the renderer asks it.

The renderer also gets the time from the `Clock` of the server (reserved variables `now`, an object with `date`, `time`,
`zone = "UTC"` and `year`, and `year`), so a footer can print the year without the application putting a time into every
model; the clock is a required argument of `MiniJinjaRenderer::new`, `load` and `from_themes`, so no renderer reads the wall clock by
default, and tests pass a `ManualClock`.

## Consequences

- Contract changes (additive): `ThemeAsset`, `TemplateRenderer::asset`, the `AssetService` trait and `AppServices::assets`
  (the fake application implements it too). `davhaven-web` loses its dependency on `davhaven-templates`.
- Any other renderer (tests, a future adapter) serves assets by implementing one method.
- The CSP does not change, and neither does the URL of the style sheet.

## Alternatives considered

- **An asset directory configured on the web surface**: two places that name the theme directories, and a path that reaches
  the file system from the request.
- **Inlining the style sheet into the page**: needs `style-src 'unsafe-inline'`, which the policy forbids.
