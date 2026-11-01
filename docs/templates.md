# Templates and themes

Mails and the pages of the web surface (RSVP, OAuth result) are rendered from **templates** in German and English.
The `templates` adapter renders them with [MiniJinja](https://docs.rs/minijinja) under strict undefined behavior and
HTML auto-escaping; a **theme** is a directory of template files. The built-in `default` theme is neutral (no
branding) and is compiled into the binary; a deployment brings its own themes as directories, and every tenant picks
one (`tenant.settings.theme`; a tenant that names none follows `templates.default_theme`, which is `default` unless the
operator chose another, and a name that is not loaded falls back to the same theme). This repository contains only the
generic default theme.

A tenant that names `default` explicitly is pinned to the neutral theme whatever the deployment chose:
`PATCH /api/v1/tenants/{tenant}` with `{"settings": {"theme": null}}` (a system token) makes it follow
`templates.default_theme` again. `admin bootstrap --theme <name>` sets the theme of a new tenant; without the flag it names none.

## The catalog

| Template | Kind | Parts | Used for |
| --- | --- | --- | --- |
| `imip_request` | mail | `subject`, `txt`, `html` | the invitation or its update, to an external attendee |
| `imip_cancel` | mail | `subject`, `txt`, `html` | the cancellation, to an external attendee |
| `imip_reply` | mail | `subject`, `txt`, `html` | the answer of an internal attendee, to an external organizer |
| `rsvp_page` | page | `html` (its `subject` is the page title) | the invitation and the form to answer it |
| `rsvp_answered` | page | `html` | what the page shows after an answer was recorded |
| `rsvp_unavailable` | page | `html` | every failure of the web routes: an unknown, expired, revoked or cancelled link, an address that does not exist, a rate limit, a service that is not available; one page, worded by the `status` |
| `oauth_result` | page | `html` | where the OAuth callback of a calendar provider ends |
| `feed_busy` | snippet | `subject` | the localized summary of busy blocks in feeds ("Busy"), in the language of the feed's owner; a tenant's own settings override it: `busy_text_by_locale` (a text per language, looked up as the language is and then without its last subtag) and `busy_text` (one text for every language, for the languages the map does not name). Where a tenant names neither, this template speaks, so a deployment that wants its own words for every tenant writes it in its theme |

The names are the contract between the application and the themes. A theme may provide any subset: what it does not have
comes from the themes it falls back to (see **Layered themes** below). A template a theme provides must have all its parts.

## Files of a theme

```text
{theme_dir}/{theme}/
    imip_request.de.subject      one line: the subject of the mail, or the title of a page
    imip_request.de.html         the HTML body (auto-escaped)
    imip_request.de.txt          the plain text body
    imip_request.en.subject  …
    _mail.html                   partials: files whose names start with `_`, found by their plain name by
    _footer.de.html              `{% extends %}` and `{% include %}` within the same theme
    assets/                      static files, served as /assets/{theme}/{file}
```

A theme can be as small as one file: the usual theme of a deployment brings its layout (`_mail.html`, `_page.html`), its
footers and its style sheet, and gets what an invitation says from the default theme.

File names have the form `{template}.{locale}.{part}`. Everything that does not look like that (assets, notes,
hidden files) is ignored; a file that looks like a template but is not in the catalog, or has no valid locale, is an
error. A file may be at most 256 KiB. A theme directory, a template file or an `assets/` file may be a symbolic link
(configuration volumes of container platforms are mounted that way): links are followed, so the theme directories
belong to the operator and nobody else may write to them.

Configuration:

```toml
[plugins]
templates = "minijinja"          # or "echo": renders nothing and returns the model; refused in production mode

[plugin.minijinja]
theme_dirs = ["/etc/davhaven/themes"]   # a theme found here replaces the built-in theme of the same name
fuel = 200000                            # the most instructions one render may take

[templates]                      # read by the same plugin: the server passes these two keys along with its own table
default_theme = "default"
default_locale = "en"
```

The `echo` renderer would put the data of events and the names of attendees into mails as JSON, so the server
refuses to start with it in production mode.

**Fallbacks.** The locale of a request is tried as it is (`de-AT`), by its language (`de`), then the default locale
the same way, and English last. A request for a locale no theme has (say `fr`) therefore renders in the default locale or
English, never fails.

**Layered themes.** A request is rendered *in* a theme: the theme the tenant names, or `templates.default_theme` when it
names none or one that is not loaded. What that theme lacks comes from the themes it falls back to, in this order: the
deployment's `default_theme`, `default`, the built-in theme. The theme `default` is the neutral one: **it falls back to the
built-in theme alone**, never to the deployment's `default_theme`, so a tenant that names `default` does not get the layout or
the footers of the deployment's own theme, even when the deployment ships a partial `default` directory.

* A **template** (`imip_request.de.html` and its parts) comes as a whole from the first theme in that order that provides it
  for the locale. A theme never mixes the parts of one template with those of another theme.
* A **partial** (a file whose name starts with `_`) comes file by file from the first theme that has it, and is always looked
  up in the theme the request is rendered in first, **whichever theme provided the template that includes it**. A theme that
  brings only its own `_mail.html` therefore wraps the default invitation in its layout, and one that brings only
  `_footer.de.html` changes the German footer and nothing else.
* The reserved variable `theme` is the theme the request was rendered in, so a page links `/assets/{theme}/page.css` of the
  theme that was asked for, and `/assets/{theme}/…` falls back to the built-in files for what that theme does not ship.

The default theme's templates use these partials, which a theme can replace: the layouts `_mail.html` and `_page.html`
(blocks `title` and `content`; the mail layout includes `_footer.{locale}.html`, the page layout
`_page_footer.{locale}.html`), and the footers `_footer.{locale}.html`, `_footer.{locale}.txt` and
`_page_footer.{locale}.html`. A replaced layout keeps the two blocks, or the content of the default templates does not show:
the engine drops, without an error, a block that its layout does not render. The check at startup catches the one that
matters, so a layout without a `content` block (or one that never renders it) fails the start and `davhaven config check`
with the theme and the layout in the message. A missing `title` block is not checked: the page then has no title.

**Checks at startup and in `config check`.** Loading renders every template × locale **in every theme** (the templates a
theme inherits included, inside its layout), **those of the deployment's theme directories among them**, with the sample
models of the catalog (`davhaven_templates::catalog::Template::sample_models`, which reach every branch of the built-in
templates). A theme that uses a field the application does not supply, calls a missing partial, has a syntax error or loops
for too long stops the server from starting, with the file and the line in the message, and `davhaven config check`
**loads the themes the same way**: a `default_theme` that does not exist or a broken template fails the check and not the
first mail, and a `theme_dirs` entry that holds no theme (a volume that is not mounted) is reported as a warning. The sample
models are kept in step with what the application really builds: an integration test renders the mails with the model of the
composer and fails when the two drift apart.

## What a template can use

* The **model** of the template (below), as JSON. Optional parts are always present and `null` when absent, so
  `{% if event.location %}` works under strict undefined behavior; a field that is not in the model is an error.
* The reserved variables `locale` (the locale of the files that were found, for example `de`), `theme` (the theme the request
  was rendered in), `now` and `year`. `now` is the time of the server's clock in UTC, in the form of the date objects of the
  models (`now.date` = `2027-01-12`, `now.time` = `10:00`, `now.zone` = `UTC`, so `when(now, none)` prints it), with `now.year`
  added, and `year` is the same number alone: `© {{ year }} {{ tenant.name }}` in a footer. They come from the `Clock` of the
  server, never from the system the renderer runs on, so tests move them.
* `when(start, end)`: the localized time range of an event from the `start` and `end` objects of the model
  (`Dienstag, 12. Januar 2027, 10:00–11:30 Uhr (Europe/Berlin)`). German and English are built in, every other
  language reads like English. For all-day events `end` is the last day, inclusive.
* `text | multiline`: escapes the text and turns line breaks into `<br>`; `null` gives nothing.
* Auto-escaping is on for `.html` and off for `.txt` and `.subject`. The subject is made a single line afterwards
  (control characters and runs of white space become one space), so a subject can never carry a header break.

## Models

Dates are objects `{ "date": "2027-01-12", "time": "10:00" | null, "zone": "Europe/Berlin" | null }`; `time` is
`null` for all-day events. UTC times are converted to the time zone of the tenant before they reach the template.

**Mails** (`imip_request`, `imip_cancel`, `imip_reply`):

| Field | Type | |
| --- | --- | --- |
| `tenant.name` | string | the sender name of the tenant (display name unless `sender.display_name` is set) |
| `organizer.name` | string | the organizer; never `null` (falls back to the address, then to `""`) |
| `organizer.email` | string or `null` | |
| `attendee.name` | string or `null` | the attendee the mail is about (for a reply: the one who answered) |
| `attendee.email` | string or `null` | |
| `event.summary` | string | |
| `event.description`, `event.location` | string or `null` | blank text is `null`; descriptions are cut at 4000 characters |
| `event.start` | date object | |
| `event.end` | date object or `null` | `null` when the event has no end, or ends on its first day (all-day) |
| `event.all_day`, `event.recurring` | boolean | |
| `update` | boolean | the mail updates an invitation sent before (`SEQUENCE` above 0) |
| `rsvp_url` | string or `null` | the link of an invitation; `null` for cancellations and replies |
| `reply_to` | string or `null` | the address a reply to the mail reaches a person at: the `Reply-To` of the service form, or the `From` of `from_mode = organizer`; `null` when the mail comes from the tenant's no-reply address (the person has no address of their own, as a service account), so a footer can tell the reader not to reply: `{% if reply_to %}Replies go to {{ reply_to }}.{% else %}Please do not reply.{% endif %}` |
| `reply` | object or `null` | for replies: `{ "partstat": "ACCEPTED" \| "DECLINED" \| "TENTATIVE" \| …, "comment": string or null }` |

**`rsvp_page`:** `tenant.name`, `event` (as above, but `description` is always `null`: the link is a bearer
credential that may be forwarded, and descriptions carry dial-in codes and private notes), `organizer.name`, `cancelled` (boolean: a cancelled event shows
no form), `current` (the answer so far, `NEEDS-ACTION` or `ACCEPTED`, `DECLINED`, `TENTATIVE`), `error` (`null`, or
`invalid_csrf`, `invalid_answer`, `comment_too_long` when the page is shown again after a refused answer: the application renders the form again with a fresh `form.csrf` and status 200, and records nothing) and `form`:
`{ "action": "?", "csrf": "…", "comment_max": 500 }`. The `action` is a relative reference to the address of the page itself
(the application never holds the link, only the id of the token row), so a `POST` goes to `/rsvp/{token}` and works
under any public base URL.

The form of the page is a contract with the RSVP handler: a `POST` to `form.action` with the fields `csrf` (hidden,
the value of `form.csrf`), `partstat` (`ACCEPTED`, `TENTATIVE` or `DECLINED`, the value of the pressed button) and
`comment` (at most `form.comment_max` characters). It works without JavaScript.

**`rsvp_answered`:** `tenant.name`, `event` (without description, as on the page), `organizer.name`, `answer` (`ACCEPTED`, `DECLINED` or `TENTATIVE`) and
`link` (the page to change the answer). **`rsvp_unavailable`:** `status`, the HTTP status of the failure (an integer: 404 for a link that is not valid, 429, 5xx, any other 4xx), and nothing else (a page that reveals nothing about the link). The page is rendered for visitors whose link does not authenticate, so it has no `tenant`: it uses the deployment's default theme and the language of the visitor's `Accept-Language` when a theme ships it, else `templates.default_locale`.
**`oauth_result`:** `success` (boolean) and `provider` (the display name of the provider). **`feed_busy`:** nothing.

## Pages: content security policy

Pages are served with `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self';
form-action 'self'; …`: no scripts, no inline styles (not even `style` attributes), nothing from other origins. The
default theme links its style sheet from the own origin, `/assets/default/page.css`. The files belong to the
renderer, which loads the `assets/` directories of the configured theme directories and carries the built-in ones;
the web layer reaches them only through the application (`AssetService::get`, which asks `TemplateRenderer::asset`),
so it depends on no adapter. `GET /assets/{theme}/{file}` serves a file of the theme with its content type and ETag
and falls back to the built-in assets; a theme or file name that is not a plain name (letters, digits, `.`, `_`,
`-`) is a plain 404. A theme of a deployment ships its style sheet in its own `assets/` directory and links
`/assets/{theme}/…`. Mails are the opposite: mail clients ignore linked style sheets and block remote content, so mail
templates carry their styles inline and load nothing from outside (no images, no `<link>`, no `@import`).

## Writing a theme

Start from the smallest theme that does the job: a directory with `_mail.html`, `_page.html`, the footers and
`assets/page.css`. Copy more of `crates/templates/themes/default` only for the templates whose words you change. The
default theme is the reference for what the checks expect:

* **Accessibility (WCAG 2.1 AA):** `lang` on `<html>`, one `<main>` and one `<h1>`, labelled form controls, a
  group label for the answer buttons, `role="alert"` for errors and `role="status"` for confirmations, visible
  focus, targets of at least 44 px, colors with a contrast of 4.5:1 in the light and the dark scheme (the tests
  of the default theme compute it).
* **Mails:** a plain text alternative that stands on its own, tables and inline styles for layout, a footer.
  A cancellation must say it is a cancellation in the subject.
* **Texts** are written for a person: no ids, no tokens besides the RSVP link, no raw error codes.
* Run the theme through the tests of the crate (`cargo nextest run -p davhaven-templates`): every template × locale
  renders under strict undefined behavior with every sample model.

## Locale and formatting

German and English ship with the server. The locale of a mail is, in this order: the locale of the job (the
recipient's, when known), the locale of the tenant. Dates are formatted by the templates (`when`), never by the
application, so a theme decides how a date reads. The application passes wall-clock values together with the name of
their zone and does no time zone arithmetic for display besides converting UTC instants into the tenant's zone.
