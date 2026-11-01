//! Theme loading and the built-in default theme.
//!
//! A theme is a directory of template files; the built-in `default` theme is compiled into the binary and is
//! neutral (no branding, German and English). A deployment configures directories with its own themes
//! (`plugin.minijinja.theme_dirs`) and selects one per tenant (`tenant.settings.theme`). Themes are **layered**: a
//! theme brings only what it changes (typically the layout and the footers, with the style sheet in `assets/`) and
//! falls back to the default theme for the rest, see [`Themes`].
//!
//! # Layout of a theme directory
//!
//! ```text
//! {theme_dir}/{theme}/
//!     imip_request.de.subject      a single-line template: the subject of the mail (or the title of a page)
//!     imip_request.de.html         the HTML body (auto-escaped)
//!     imip_request.de.txt          the plain text body
//!     _mail.html                   a partial: any file whose name starts with `_`; `{% extends %}` and
//!     _footer.de.html              `{% include %}` find partials of the same theme by their plain name
//!     assets/                      static files the web layer serves as `/assets/{theme}/{file}` (the pages
//!                                  link their style sheet there: the page CSP allows no inline styles); see
//!                                  [`assets`](crate::assets) for what is accepted
//! ```
//!
//! File names that look like `{template}.{locale}.{subject|html|txt}` must name a template of the catalog and a
//! valid locale; everything else (assets, notes, hidden files) is ignored. Each template a theme provides must
//! have the parts its kind requires ([`Template::required_parts`](crate::catalog::Template::required_parts)).
//! A theme may provide any subset of the catalog and of the partials: what it lacks comes from the theme it falls back
//! to (the deployment's default theme, then `default`, then the built-in theme; the theme `default` falls back to the
//! built-in theme alone).
//!
//! # Checks at startup
//!
//! Loading compiles every file and renders every template × locale **in every theme** (the templates of the themes it
//! falls back to included, inside its layout) with the sample models of the catalog under strict undefined behavior, so
//! a theme that references a field the application does not provide, calls a missing partial or loops for too long
//! fails when the server starts (and in `davhaven config check`), with the file and line in the message. A layout that
//! leaves out the `content` block of the templates it wraps is refused as well: the engine drops the block of a template
//! that its layout does not render, without an error, and the mail or the page would go out without its content.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use davhaven_domain::Locale;
use davhaven_ports::ThemeAsset;
use minijinja::value::Value;
use minijinja::{AutoEscape, Environment, ErrorKind, UndefinedBehavior};

use crate::catalog::{Kind, Template};
use crate::config::is_valid_theme_name;
use crate::locale::{Day, Moment, TimeOfDay, format_when};

/// The name of the built-in theme.
pub const DEFAULT_THEME: &str = "default";

/// The hidden name under which the pristine built-in theme stays available as the last resort, even when a
/// directory replaces the theme named `default`.
pub const BUILTIN_THEME: &str = "@builtin";

/// The largest theme file the loader reads.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Why a theme cannot be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThemeError {
    /// A directory or file cannot be read.
    #[error("cannot read `{path}` ({kind})")]
    Io {
        /// The path.
        path: PathBuf,
        /// What went wrong.
        kind: std::io::ErrorKind,
    },
    /// A file is not usable.
    #[error("theme `{theme}`, file `{file}`: {reason}")]
    File {
        /// The theme.
        theme: String,
        /// The file name.
        file: String,
        /// What is wrong.
        reason: String,
    },
    /// A theme does not provide a part its template needs.
    #[error("theme `{theme}`: template `{template}` in `{locale}` lacks its {part} part (`{file}`)")]
    Missing {
        /// The theme.
        theme: String,
        /// The template.
        template: &'static str,
        /// The locale.
        locale: String,
        /// The part: `subject`, `html` or `txt`.
        part: &'static str,
        /// The file that would provide it.
        file: String,
    },
    /// A template does not render with the sample models of the catalog.
    #[error("theme `{theme}`, template `{template}` in `{locale}` does not render: {reason}")]
    Render {
        /// The theme.
        theme: String,
        /// The template.
        template: &'static str,
        /// The locale.
        locale: String,
        /// The engine's explanation (no model values).
        reason: String,
    },
    /// A layout does not render the `content` block of the template it wraps, so the content would be dropped.
    #[error(
        "theme `{theme}`: the layout `{layout}` does not render the content block of template `{template}` in `{locale}`, so \
         the content would be left out; the layout needs a content block"
    )]
    Layout {
        /// The theme the template was rendered in.
        theme: String,
        /// The layout that wraps the templates of the kind: `_mail.html` or `_page.html`.
        layout: &'static str,
        /// The template whose content is lost.
        template: &'static str,
        /// The locale.
        locale: String,
    },
}

/// The kinds of file a template consists of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// `{template}.{locale}.subject`.
    Subject,
    /// `{template}.{locale}.html`.
    Html,
    /// `{template}.{locale}.txt`.
    Text,
}

impl Part {
    /// The file extension.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Html => "html",
            Self::Text => "txt",
        }
    }

    fn from_extension(extension: &str) -> Option<Self> {
        [Self::Subject, Self::Html, Self::Text]
            .into_iter()
            .find(|part| part.extension() == extension)
    }
}

/// The classification of a file name inside a theme directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    /// A part of a template in one locale.
    Template {
        /// The template.
        template: Template,
        /// The locale of the file name, normalized.
        locale: String,
        /// The part.
        part: Part,
    },
    /// A partial for `extends` and `include`.
    Partial,
    /// Not a template file.
    Ignored,
}

/// Classifies `name`.
///
/// # Errors
///
/// A description of the problem for names that look like template files but do not name a template of the catalog
/// or a valid locale (a typo must not silently leave a template unthemed).
pub fn classify(name: &str) -> Result<FileKind, String> {
    if name.starts_with('.') {
        return Ok(FileKind::Ignored);
    }
    if name.starts_with('_') {
        let plain = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
        return if plain && name.len() <= 100 {
            Ok(FileKind::Partial)
        } else {
            Err("partial names may only contain letters, digits, `_`, `-` and `.`".to_owned())
        };
    }
    let parts: Vec<&str> = name.split('.').collect();
    let [template, locale, extension] = parts.as_slice() else {
        return Ok(FileKind::Ignored);
    };
    let Some(part) = Part::from_extension(extension) else {
        return Ok(FileKind::Ignored);
    };
    let Some(template) = Template::from_name(template) else {
        return Err(format!(
            "`{template}` is not a template of the catalog (known: {})",
            Template::ALL.map(Template::name).join(", ")
        ));
    };
    let locale = Locale::parse(locale).map_err(|_| format!("`{locale}` is not a locale such as `de` or `en-GB`"))?;
    Ok(FileKind::Template {
        template,
        locale: locale.as_str().to_owned(),
        part,
    })
}

/// The files of one theme: file name to source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeFiles {
    /// The theme name.
    pub name: String,
    /// Where the files come from, for messages: `built-in` or a directory.
    pub origin: String,
    /// The files, keyed by file name.
    pub files: BTreeMap<String, String>,
    /// The static assets, keyed by file name (`/assets/{theme}/{file}`).
    pub assets: BTreeMap<String, ThemeAsset>,
}

macro_rules! builtin_files {
    ($($file:literal),+ $(,)?) => {
        &[$(($file, include_str!(concat!("../themes/default/", $file)))),+]
    };
}

/// The files of the built-in theme.
const BUILTIN: &[(&str, &str)] = builtin_files![
    "_footer.de.html",
    "_footer.de.txt",
    "_footer.en.html",
    "_footer.en.txt",
    "_mail.html",
    "_page.html",
    "_page_footer.de.html",
    "_page_footer.en.html",
    "feed_busy.de.subject",
    "feed_busy.en.subject",
    "imip_cancel.de.html",
    "imip_cancel.de.subject",
    "imip_cancel.de.txt",
    "imip_cancel.en.html",
    "imip_cancel.en.subject",
    "imip_cancel.en.txt",
    "imip_reply.de.html",
    "imip_reply.de.subject",
    "imip_reply.de.txt",
    "imip_reply.en.html",
    "imip_reply.en.subject",
    "imip_reply.en.txt",
    "imip_request.de.html",
    "imip_request.de.subject",
    "imip_request.de.txt",
    "imip_request.en.html",
    "imip_request.en.subject",
    "imip_request.en.txt",
    "oauth_result.de.html",
    "oauth_result.de.subject",
    "oauth_result.en.html",
    "oauth_result.en.subject",
    "rsvp_answered.de.html",
    "rsvp_answered.de.subject",
    "rsvp_answered.en.html",
    "rsvp_answered.en.subject",
    "rsvp_page.de.html",
    "rsvp_page.de.subject",
    "rsvp_page.en.html",
    "rsvp_page.en.subject",
    "rsvp_unavailable.de.html",
    "rsvp_unavailable.de.subject",
    "rsvp_unavailable.en.html",
    "rsvp_unavailable.en.subject",
];

/// The built-in default theme.
pub fn builtin() -> ThemeFiles {
    ThemeFiles {
        name: DEFAULT_THEME.to_owned(),
        origin: "built-in".to_owned(),
        files: BUILTIN
            .iter()
            .map(|(name, source)| ((*name).to_owned(), (*source).to_owned()))
            .collect(),
        assets: crate::assets::builtin(),
    }
}

/// Reads the themes of a directory: every subdirectory with a valid theme name is a theme. Subdirectories with
/// other names are ignored (they may hold anything), as are files directly in `dir`.
///
/// # Errors
///
/// [`ThemeError::Io`] for unreadable directories and files and [`ThemeError::File`] for oversized files and
/// files that look like templates but are not valid ones (see [`classify`]).
pub fn read_dir(dir: &Path) -> Result<Vec<ThemeFiles>, ThemeError> {
    let io_error = |path: &Path, error: &std::io::Error| ThemeError::Io {
        path: path.to_path_buf(),
        kind: error.kind(),
    };
    let mut themes = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|error| io_error(dir, &error))?
        .collect::<Result<_, _>>()
        .map_err(|error| io_error(dir, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        // `metadata` follows symbolic links: a directory that a configuration management system or a mounted
        // ConfigMap exposes as links is a theme like any other.
        if !is_valid_theme_name(&name)
            || !std::fs::metadata(&path)
                .map_err(|error| io_error(&path, &error))?
                .is_dir()
        {
            continue;
        }
        let mut files = BTreeMap::new();
        let mut theme_entries: Vec<_> = std::fs::read_dir(&path)
            .map_err(|error| io_error(&path, &error))?
            .collect::<Result<_, _>>()
            .map_err(|error| io_error(&path, &error))?;
        theme_entries.sort_by_key(std::fs::DirEntry::file_name);
        for file in theme_entries {
            let file_name = file.file_name().to_string_lossy().into_owned();
            let file_path = file.path();
            // A dangling link is an error of the deployment, not a file that is silently missing.
            if !std::fs::metadata(&file_path)
                .map_err(|error| io_error(&file_path, &error))?
                .is_file()
            {
                continue;
            }
            let fail = |reason: String| ThemeError::File {
                theme: name.clone(),
                file: file_name.clone(),
                reason,
            };
            match classify(&file_name).map_err(fail)? {
                FileKind::Ignored => continue,
                FileKind::Template { .. } | FileKind::Partial => {}
            }
            let size = std::fs::metadata(&file_path)
                .map_err(|error| io_error(&file_path, &error))?
                .len();
            if size > MAX_FILE_BYTES {
                return Err(ThemeError::File {
                    theme: name.clone(),
                    file: file_name,
                    reason: "the file is larger than 256 KiB".to_owned(),
                });
            }
            let source = std::fs::read_to_string(&file_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    ThemeError::File {
                        theme: name.clone(),
                        file: file_name.clone(),
                        reason: "the file is not valid UTF-8".to_owned(),
                    }
                } else {
                    io_error(&file_path, &error)
                }
            })?;
            files.insert(file_name, source);
        }
        let assets = crate::assets::read_dir(&name, &path)?;
        themes.push(ThemeFiles {
            name,
            origin: dir.display().to_string(),
            files,
            assets,
        });
    }
    Ok(themes)
}

/// The template names of one (template, locale) pair of a theme inside the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The subject (or page title) template.
    pub subject: Option<String>,
    /// The HTML template.
    pub html: Option<String>,
    /// The plain text template.
    pub text: Option<String>,
}

impl Entry {
    /// The environment name of a part.
    pub fn part(&self, part: Part) -> Option<&str> {
        match part {
            Part::Subject => self.subject.as_deref(),
            Part::Html => self.html.as_deref(),
            Part::Text => self.text.as_deref(),
        }
    }

    fn set(&mut self, part: Part, name: String) {
        match part {
            Part::Subject => self.subject = Some(name),
            Part::Html => self.html = Some(name),
            Part::Text => self.text = Some(name),
        }
    }
}

/// What the renderer found for a request.
#[derive(Debug, Clone, Copy)]
pub struct Resolved<'a> {
    /// The template parts.
    pub entry: &'a Entry,
    /// The theme the request was rendered in: the theme whose layout, partials and assets the page uses, which is not
    /// always the theme that provides the template itself.
    pub theme: &'a str,
    /// The locale the parts are written in.
    pub locale: &'a str,
}

/// What a theme brings of one template in one locale: for each part the file name and the source.
type Parts<'a> = BTreeMap<Part, (&'a str, &'a str)>;

/// The templates that the files of the themes provide themselves, by `(theme, template, locale)`.
type OwnTemplates<'a> = BTreeMap<(String, Template, String), Parts<'a>>;

/// All loaded themes, layered and compiled into one template environment.
///
/// # Layers
///
/// A theme does not have to be complete. When a template is rendered *in* a theme `T`, every file it needs is looked
/// for in `T` first and then in the themes `T` falls back to, in this order: the deployment's default theme
/// (`templates.default_theme`), `default`, and the pristine built-in theme. The theme `default` is the neutral one and
/// follows the deployment's default theme in nothing: it falls back to the pristine built-in theme alone, so that a tenant
/// that names `default` never gets the layout or the footers of the deployment's own theme (`layers_of`). What falls
/// back depends on what the file is:
///
/// * a **template** (`imip_request.de.html`, ...) comes as a whole from the first theme in that order that provides it
///   for the locale: a theme that provides a template must provide all its parts, and never mixes them with the parts of
///   another theme;
/// * a **partial** (any file whose name starts with `_`: the layout `_mail.html`, the footers) comes file by file from
///   the first theme that has it. A partial is found by its plain name, in the theme the request is rendered in, whatever
///   theme provided the template that includes it: a theme that only brings its own `_mail.html` and `_footer.de.html`
///   gets the content of the default templates inside its layout.
///
/// The layers are compiled once, when the themes are built: the files of the themes that `T` falls back to are
/// registered a second time under the name of `T`, so that `{% extends %}` and `{% include %}` stay a plain lookup inside
/// one theme.
///
/// `Themes` owns the order: it says which theme a request is rendered in ([`render_theme`](Self::render_theme)), which
/// templates that theme finds ([`resolve`](Self::resolve)) and which assets ([`asset`](Self::asset)).
pub struct Themes {
    env: Environment<'static>,
    /// What a request rendered in a theme finds: the templates of the theme and of the themes it falls back to.
    entries: BTreeMap<(String, Template, String), Entry>,
    /// The layers of every theme by name, most specific first: the theme itself and the themes it falls back to.
    layers: BTreeMap<String, Vec<String>>,
    /// The theme a request is rendered in when it names none that is loaded (`templates.default_theme`).
    default_theme: String,
    names: BTreeSet<String>,
    assets: BTreeMap<String, BTreeMap<String, ThemeAsset>>,
}

impl core::fmt::Debug for Themes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Themes")
            .field("themes", &self.names)
            .finish_non_exhaustive()
    }
}

/// The name a file of `theme` has in the template environment.
fn registered_name(theme: &str, file: &str) -> String {
    format!("{theme}/{file}")
}

impl Themes {
    /// Compiles `themes` (the built-in theme first, then the directories' themes in order; a later theme of the
    /// same name replaces an earlier one), layers them (see the type documentation: `default_theme` is the deployment's
    /// default theme, the first fallback of every theme but `default`) and renders every template of every theme with the
    /// sample models.
    ///
    /// # Errors
    ///
    /// A [`ThemeError`] for the first problem found.
    pub fn build(themes: Vec<ThemeFiles>, default_theme: &str, fuel: u64) -> Result<Self, ThemeError> {
        let mut by_name: BTreeMap<String, ThemeFiles> = BTreeMap::new();
        for theme in themes {
            by_name.insert(theme.name.clone(), theme);
        }
        // The pristine built-in theme stays as the last resort.
        let mut pristine = builtin();
        BUILTIN_THEME.clone_into(&mut pristine.name);
        by_name.insert(BUILTIN_THEME.to_owned(), pristine);
        by_name.entry(DEFAULT_THEME.to_owned()).or_insert_with(builtin);

        // The files of every theme as it wrote them.
        let mut env = environment(fuel);
        let mut own: OwnTemplates<'_> = BTreeMap::new();
        let mut assets: BTreeMap<String, BTreeMap<String, ThemeAsset>> = BTreeMap::new();
        for theme in by_name.values() {
            assets.insert(theme.name.clone(), theme.assets.clone());
            for (file, source) in &theme.files {
                let fail = |reason: String| ThemeError::File {
                    theme: theme.name.clone(),
                    file: file.clone(),
                    reason,
                };
                let kind = classify(file).map_err(fail)?;
                add_template(&mut env, theme, file, registered_name(&theme.name, file), source)?;
                if let FileKind::Template { template, locale, part } = kind {
                    own.entry((theme.name.clone(), template, locale))
                        .or_default()
                        .insert(part, (file.as_str(), source.as_str()));
                }
            }
        }
        check_required_parts(&own)?;

        // The layers: what a request rendered in each theme finds.
        let mut entries: BTreeMap<(String, Template, String), Entry> = BTreeMap::new();
        let mut layers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for theme in by_name.values() {
            let chain = layers_of(&by_name, &theme.name, default_theme);
            layer_partials(&mut env, &chain, theme)?;
            // A template comes as a whole from the first theme of the chain that provides it for the locale.
            let mut chosen: BTreeMap<(Template, &str), (&ThemeFiles, &Parts<'_>)> = BTreeMap::new();
            for provider in &chain {
                for ((owner, template, locale), parts) in &own {
                    if *owner == provider.name {
                        chosen.entry((*template, locale.as_str())).or_insert((provider, parts));
                    }
                }
            }
            for ((template, locale), (provider, parts)) in chosen {
                let entry = if provider.name == theme.name {
                    own_entry(&theme.name, parts)
                } else {
                    copy_entry(&mut env, provider, theme, parts)?
                };
                entries.insert((theme.name.clone(), template, locale.to_owned()), entry);
            }
            layers.insert(
                theme.name.clone(),
                chain.iter().map(|layer| layer.name.clone()).collect(),
            );
        }

        let themes = Self {
            env,
            entries,
            layers,
            default_theme: default_theme.to_owned(),
            names: by_name.keys().cloned().collect(),
            assets,
        };
        themes.check_renders()?;
        Ok(themes)
    }

    /// Whether a theme of this name is loaded.
    pub fn has_theme(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// The names of the loaded themes, sorted (the hidden built-in copy included).
    pub fn theme_names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    /// The theme a request for `requested` is rendered in: `requested` when it is loaded, else the deployment's default
    /// theme. The hidden built-in copy is nobody's choice: it is the last layer of every theme and is not requested by name.
    pub fn render_theme<'a>(&'a self, requested: &'a str) -> &'a str {
        if requested != BUILTIN_THEME && self.names.contains(requested) {
            requested
        } else {
            &self.default_theme
        }
    }

    /// Finds the parts for `template` in the theme a request for `requested` is rendered in ([`render_theme`](Self::render_theme)):
    /// locales are tried in the order of `locales` (most important first), and the themes it falls back to are part of
    /// that theme already (see the type documentation).
    pub fn resolve<'a>(
        &'a self,
        template: Template,
        locales: &'a [String],
        requested: &'a str,
    ) -> Option<Resolved<'a>> {
        let theme = self.render_theme(requested);
        locales.iter().find_map(|locale| {
            let key = (theme.to_owned(), template, locale.clone());
            self.entries
                .get_key_value(&key)
                .map(|((stored_theme, _, stored_locale), entry)| Resolved {
                    entry,
                    theme: stored_theme.as_str(),
                    locale: stored_locale.as_str(),
                })
        })
    }

    /// The asset `file` of the theme a request for `requested` is rendered in, or of the first theme it falls back to that
    /// has a file of that name (the layers of the theme, the built-in theme last), so a theme that ships no style sheet of
    /// its own gets the built-in one.
    pub fn asset(&self, requested: &str, file: &str) -> Option<ThemeAsset> {
        let layers = self.layers.get(self.render_theme(requested))?;
        layers
            .iter()
            .find_map(|layer| self.assets.get(layer).and_then(|files| files.get(file)))
            .cloned()
    }

    /// Renders one template of the environment.
    ///
    /// # Errors
    ///
    /// The engine's error.
    pub fn render(&self, name: &str, context: &Value) -> Result<String, minijinja::Error> {
        self.env.get_template(name)?.render(context)
    }

    /// Renders every template of every theme with the sample models, and checks that the layouts keep the content.
    fn check_renders(&self) -> Result<(), ThemeError> {
        let now = crate::renderer::sample_now();
        for ((theme, template, locale), entry) in &self.entries {
            let render_error = |reason: String| ThemeError::Render {
                theme: theme.clone(),
                template: template.name(),
                locale: locale.clone(),
                reason,
            };
            for model in template.sample_models() {
                let context = crate::renderer::context(&model, locale, theme, now).map_err(render_error)?;
                for part in [Part::Subject, Part::Html, Part::Text] {
                    let Some(name) = entry.part(part) else { continue };
                    match (part, layout_of(template.kind())) {
                        (Part::Html, Some(layout)) => {
                            if self
                                .drops_content(name, &context)
                                .map_err(|error| render_error(error.to_string()))?
                            {
                                return Err(ThemeError::Layout {
                                    theme: theme.clone(),
                                    layout,
                                    template: template.name(),
                                    locale: locale.clone(),
                                });
                            }
                        }
                        _ => {
                            self.render(name, &context)
                                .map_err(|error| render_error(error.to_string()))?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Renders an HTML part and says whether its layout left out the `content` block of the template: the engine drops a
    /// block that the layout does not render, without an error. A part without a content block (a complete page of its
    /// own) has nothing to lose.
    fn drops_content(&self, name: &str, context: &Value) -> Result<bool, minijinja::Error> {
        let mut rendered = self.env.get_template(name)?.render_captured(context.clone())?;
        let page = rendered.output().to_owned();
        // A block that cannot be rendered on its own is not the layout's fault: the page itself rendered.
        Ok(match rendered.with_state_mut(|state| state.render_block("content")) {
            Ok(block) => !block.trim().is_empty() && !page.contains(block.trim()),
            Err(_) => false,
        })
    }
}

/// The layout that wraps the HTML of the templates of a kind, if the kind has one.
const fn layout_of(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Mail => Some("_mail.html"),
        Kind::Page => Some("_page.html"),
        Kind::Snippet => None,
    }
}

/// Registers one file of `theme` as `registered`.
fn add_template(
    env: &mut Environment<'static>,
    theme: &ThemeFiles,
    file: &str,
    registered: String,
    source: &str,
) -> Result<(), ThemeError> {
    env.add_template_owned(registered, source.to_owned())
        .map_err(|error| ThemeError::File {
            theme: theme.name.clone(),
            file: file.to_owned(),
            reason: format!("the template does not compile: {error}"),
        })
}

/// The layers of `theme`, most specific first: the themes a request rendered in it looks in. Themes that are not loaded
/// are left out.
///
/// * an ordinary theme: itself, the deployment's default theme, `default` and the pristine built-in theme;
/// * `default`: itself and the pristine built-in theme. It does not follow the deployment's default theme: a tenant that
///   names `default` asked for the neutral theme, and a partial `default` that the deployment ships must not take on the
///   branding of another theme for what it lacks;
/// * the pristine built-in theme: itself.
fn layers_of<'a>(by_name: &'a BTreeMap<String, ThemeFiles>, theme: &str, default_theme: &str) -> Vec<&'a ThemeFiles> {
    let wanted: Vec<&str> = match theme {
        BUILTIN_THEME => vec![BUILTIN_THEME],
        DEFAULT_THEME => vec![DEFAULT_THEME, BUILTIN_THEME],
        _ => vec![theme, default_theme, DEFAULT_THEME, BUILTIN_THEME],
    };
    let mut layers: Vec<&ThemeFiles> = Vec::with_capacity(wanted.len());
    for name in wanted {
        if let Some(found) = by_name.get(name)
            && layers.iter().all(|layer| layer.name != found.name)
        {
            layers.push(found);
        }
    }
    layers
}

/// A template a theme provides must have all the parts its kind requires: a mail without its plain text, mixed with the
/// HTML of another theme, would be two different mails.
fn check_required_parts(own: &OwnTemplates<'_>) -> Result<(), ThemeError> {
    for ((theme, template, locale), parts) in own {
        let (subject, html, text) = template.required_parts();
        for (required, part) in [(subject, Part::Subject), (html, Part::Html), (text, Part::Text)] {
            if required && !parts.contains_key(&part) {
                return Err(ThemeError::Missing {
                    theme: theme.clone(),
                    template: template.name(),
                    locale: locale.clone(),
                    part: part.extension(),
                    file: format!("{}.{locale}.{}", template.name(), part.extension()),
                });
            }
        }
    }
    Ok(())
}

/// Gives `theme` the partials of the themes it falls back to (`chain`, the theme itself first): a partial that the theme
/// does not have comes from the first theme of the chain that does, under the name of `theme`.
fn layer_partials(env: &mut Environment<'static>, chain: &[&ThemeFiles], theme: &ThemeFiles) -> Result<(), ThemeError> {
    let mut have: BTreeSet<&str> = theme.files.keys().map(String::as_str).collect();
    for provider in chain.iter().filter(|provider| provider.name != theme.name) {
        for (file, source) in &provider.files {
            if matches!(classify(file), Ok(FileKind::Partial)) && have.insert(file.as_str()) {
                add_template(env, provider, file, registered_name(&theme.name, file), source)?;
            }
        }
    }
    Ok(())
}

/// The environment names of the parts of a template that `theme` provides itself.
fn own_entry(theme: &str, parts: &Parts<'_>) -> Entry {
    let mut entry = Entry::default();
    for (part, (file, _source)) in parts {
        entry.set(*part, registered_name(theme, file));
    }
    entry
}

/// Registers the parts of a template of the theme `source` under the name of `theme` too, so that the partials it
/// includes are looked up in `theme`.
fn copy_entry(
    env: &mut Environment<'static>,
    source: &ThemeFiles,
    theme: &ThemeFiles,
    parts: &Parts<'_>,
) -> Result<Entry, ThemeError> {
    let mut copy = Entry::default();
    for (part, (file, text)) in parts {
        let registered = registered_name(&theme.name, file);
        add_template(env, source, file, registered.clone(), text)?;
        copy.set(*part, registered);
    }
    Ok(copy)
}

/// The environment all themes share: strict undefined behavior, auto-escaping by file extension, a render
/// budget, no debug output (error messages must not echo model values), partials resolved inside the theme of
/// the including template, and the date helpers.
fn environment(fuel: u64) -> Environment<'static> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.set_auto_escape_callback(|name| {
        if std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
        {
            AutoEscape::Html
        } else {
            AutoEscape::None
        }
    });
    env.set_fuel(Some(fuel));
    env.set_debug(false);
    env.set_path_join_callback(|name, parent| {
        if name.contains('/') {
            return name.into();
        }
        match parent.split_once('/') {
            Some((theme, _)) => format!("{theme}/{name}").into(),
            None => name.into(),
        }
    });
    env.set_formatter(|out, state, value| {
        if matches!(state.auto_escape(), AutoEscape::Html)
            && !value.is_safe()
            && let Some(text) = value.as_str()
        {
            return out
                .write_str(&escape_html(text))
                .map_err(|_| minijinja::Error::from(ErrorKind::WriteFailure));
        }
        minijinja::escape_formatter(out, state, value)
    });
    env.add_function("when", when);
    env.add_filter("multiline", multiline);
    env
}

/// Escapes the characters that can end a text node or a double-quoted or single-quoted attribute value. Unlike the
/// default escaping of the engine it leaves `/` alone, so URLs and zone names stay readable in the source of a mail.
fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// `when(start, end)`: the localized description of an event's time. `start` and `end` are objects with `date`
/// (`2027-01-12`), `time` (`10:00` or null for all-day values) and `zone` (a zone name or null); `end` may be null.
#[expect(
    clippy::needless_pass_by_value,
    reason = "template functions receive their arguments by value"
)]
fn when(state: &minijinja::State<'_, '_>, start: Value, end: Value) -> Result<String, minijinja::Error> {
    let language = state
        .lookup("locale")
        .and_then(|locale| locale.as_str().map(str::to_owned))
        .unwrap_or_default();
    let start = moment(&start)?;
    let end = if end.is_none() || end.is_undefined() {
        None
    } else {
        Some(moment(&end)?)
    };
    Ok(format_when(&language, &start, end.as_ref()))
}

fn moment(value: &Value) -> Result<Moment, minijinja::Error> {
    let invalid = |detail: String| minijinja::Error::new(ErrorKind::InvalidOperation, detail);
    let text = |key: &str| -> Result<Option<String>, minijinja::Error> {
        let attribute = value.get_attr(key)?;
        if attribute.is_none() || attribute.is_undefined() {
            Ok(None)
        } else {
            attribute
                .as_str()
                .map(|text| Some(text.to_owned()))
                .ok_or_else(|| invalid(format!("`{key}` of an event time must be text")))
        }
    };
    let date = text("date")?.ok_or_else(|| invalid("an event time needs a `date`".to_owned()))?;
    let day = Day::parse(&date).map_err(|error| invalid(error.to_string()))?;
    let time = text("time")?
        .map(|time| TimeOfDay::parse(&time).map_err(|error| invalid(error.to_string())))
        .transpose()?;
    Ok(Moment {
        day,
        time,
        zone: text("zone")?,
    })
}

/// `text | multiline`: HTML-escapes the text and turns line breaks into `<br>`. The result is marked safe; `null`
/// gives an empty result.
#[expect(
    clippy::needless_pass_by_value,
    reason = "template filters receive their arguments by value"
)]
fn multiline(text: Value) -> Result<Value, minijinja::Error> {
    if text.is_none() || text.is_undefined() {
        return Ok(Value::from_safe_string(String::new()));
    }
    let Some(text) = text.as_str() else {
        return Err(minijinja::Error::new(
            ErrorKind::InvalidOperation,
            "`multiline` needs text",
        ));
    };
    let lines: Vec<String> = text.lines().map(escape_html).collect();
    Ok(Value::from_safe_string(lines.join("<br>\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(theme: &str, entries: &[(&str, &str)]) -> ThemeFiles {
        ThemeFiles {
            name: theme.to_owned(),
            origin: "test".to_owned(),
            files: entries
                .iter()
                .map(|(name, source)| ((*name).to_owned(), (*source).to_owned()))
                .collect(),
            assets: BTreeMap::new(),
        }
    }

    fn render_sample(themes: &Themes, theme: &str, template: Template, locale: &str, part: Part) -> String {
        let entry = &themes.entries[&(theme.to_owned(), template, locale.to_owned())];
        let context =
            crate::renderer::context(&template.sample_model(), locale, theme, crate::renderer::sample_now()).unwrap();
        themes.render(entry.part(part).unwrap(), &context).unwrap()
    }

    /// The context of the feed snippet, which needs no model.
    fn context_of(theme: &str, locale: &str) -> Value {
        crate::renderer::context(&serde_json::json!({}), locale, theme, crate::renderer::sample_now()).unwrap()
    }

    #[test]
    fn file_names_are_classified() {
        assert_eq!(
            classify("imip_request.de.html"),
            Ok(FileKind::Template {
                template: Template::ImipRequest,
                locale: "de".to_owned(),
                part: Part::Html
            })
        );
        assert_eq!(
            classify("rsvp_page.en-gb.subject"),
            Ok(FileKind::Template {
                template: Template::RsvpPage,
                locale: "en-GB".to_owned(),
                part: Part::Subject
            })
        );
        assert_eq!(classify("_mail.html"), Ok(FileKind::Partial));
        assert_eq!(classify("_footer.de.txt"), Ok(FileKind::Partial));
        for ignored in [
            ".gitkeep",
            "README.md",
            "notes.txt",
            "logo.png",
            "a.b.c.d",
            "imip_request.de.pdf",
            "imip_request.html",
        ] {
            assert_eq!(classify(ignored), Ok(FileKind::Ignored), "{ignored}");
        }
        for bad in [
            "imip_requst.de.html",
            "imip_request.d.html",
            "imip_request.german!.txt",
            "notes.en.txt",
        ] {
            assert!(classify(bad).is_err(), "{bad}");
        }
        assert!(classify("_a b.html").unwrap_err().contains("partial"));
    }

    /// The `(template, locale)` pairs that the files of a theme provide, read from the file names.
    fn provided(theme: &ThemeFiles) -> BTreeSet<(Template, String)> {
        theme
            .files
            .keys()
            .filter_map(|file| match classify(file) {
                Ok(FileKind::Template { template, locale, .. }) => Some((template, locale)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_builtin_theme_compiles_renders_and_provides_every_template_in_both_languages() {
        let themes = Themes::build(vec![builtin()], DEFAULT_THEME, 200_000).unwrap();
        assert!(themes.has_theme("default") && themes.has_theme("@builtin"));
        let provided = provided(&builtin());
        for template in Template::ALL {
            for locale in ["de", "en"] {
                assert!(
                    provided.contains(&(template, locale.to_owned())),
                    "{template:?} {locale}"
                );
            }
        }
        assert_eq!(provided.len(), Template::ALL.len() * 2);
        assert_eq!(themes.theme_names().collect::<Vec<_>>(), vec!["@builtin", "default"]);
    }

    #[test]
    fn assets_fall_back_from_the_theme_to_the_built_in_files() {
        let mut corporate = files("corporate", &[]);
        corporate.assets.insert(
            "logo.png".to_owned(),
            crate::assets::asset("image/png", b"png".to_vec()),
        );
        let mut replaced = files("default", &[]);
        replaced.assets.insert(
            "logo.png".to_owned(),
            crate::assets::asset("image/png", b"own".to_vec()),
        );
        let themes = Themes::build(vec![builtin(), corporate, replaced], DEFAULT_THEME, 200_000).unwrap();

        let logo = themes.asset("corporate", "logo.png").unwrap();
        assert_eq!(logo.body.as_ref(), b"png", "the requested theme comes first");
        let sheet = themes.asset("corporate", "page.css").unwrap();
        assert_eq!(
            sheet.content_type, "text/css; charset=utf-8",
            "the built-in sheet is the last resort"
        );
        assert_eq!(
            themes.asset("default", "logo.png").unwrap().body.as_ref(),
            b"own",
            "a directory theme named default replaces the built-in default"
        );
        assert_eq!(
            themes.asset("not-loaded", "logo.png").unwrap().body.as_ref(),
            b"own",
            "a theme that is not loaded is rendered in the deployment's default theme, and so are its assets"
        );
        assert!(themes.asset("corporate", "missing.css").is_none());
    }

    #[test]
    fn the_layers_of_every_theme_are_owned_by_the_themes() {
        let base = files("base", &[]);
        let acme = files("acme", &[]);
        let themes = Themes::build(vec![builtin(), base, acme], "base", 200_000).unwrap();
        let layers = |theme: &str| themes.layers[theme].iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(layers("acme"), vec!["acme", "base", "default", "@builtin"]);
        assert_eq!(
            layers("base"),
            vec!["base", "default", "@builtin"],
            "a theme that is the deployment's default is not its own fallback twice"
        );
        assert_eq!(
            layers("default"),
            vec!["default", "@builtin"],
            "the neutral theme does not follow the deployment's default theme"
        );
        assert_eq!(layers("@builtin"), vec!["@builtin"]);
        // The theme a request is rendered in: the one it names when that is loaded, else the deployment's default theme;
        // the hidden copy is never asked for by name.
        for (requested, expected) in [
            ("acme", "acme"),
            ("default", "default"),
            ("", "base"),
            ("not-loaded", "base"),
            ("@builtin", "base"),
        ] {
            assert_eq!(themes.render_theme(requested), expected, "{requested:?}");
        }
    }

    #[test]
    fn html_escaping_covers_the_markup_characters_and_keeps_slashes() {
        assert_eq!(
            escape_html("a & b < c > d \"e\" 'f' g/h"),
            "a &amp; b &lt; c &gt; d &quot;e&quot; &#x27;f&#x27; g/h"
        );
        let corporate = files(
            "corporate",
            &[
                (
                    "imip_cancel.en.html",
                    "<a href=\"{{ rsvp_url }}\">{{ event.summary }}</a>{{ event.description | multiline }}",
                ),
                ("imip_cancel.en.subject", "s"),
                ("imip_cancel.en.txt", "t"),
            ],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        assert_eq!(
            render_sample(&themes, "corporate", Template::ImipCancel, "en", Part::Html),
            "<a href=\"https://calendar.example.org/rsvp/dvh_rsvp_token\">Planning &lt;session&gt; &amp; coffee</a>Agenda:<br>\n1. Roadmap<br>\n2. Budget"
        );
    }

    #[test]
    fn partials_resolve_inside_the_theme_the_template_is_rendered_in() {
        let corporate = files(
            "corporate",
            &[
                ("_frame.txt", "[{{ locale }}|{{ theme }}] "),
                ("feed_busy.en.subject", "{% include \"_frame.txt\" %}Busy"),
            ],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        assert_eq!(
            render_sample(&themes, "corporate", Template::FeedBusy, "en", Part::Subject),
            "[en|corporate] Busy"
        );
    }

    #[test]
    fn auto_escaping_follows_the_file_extension() {
        let corporate = files(
            "corporate",
            &[
                ("imip_cancel.en.subject", "{{ event.summary }}"),
                ("imip_cancel.en.txt", "{{ event.summary }}"),
                ("imip_cancel.en.html", "<p>{{ event.summary }}</p>"),
            ],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        assert_eq!(
            render_sample(&themes, "corporate", Template::ImipCancel, "en", Part::Html),
            "<p>Planning &lt;session&gt; &amp; coffee</p>"
        );
        for part in [Part::Subject, Part::Text] {
            assert_eq!(
                render_sample(&themes, "corporate", Template::ImipCancel, "en", part),
                "Planning <session> & coffee"
            );
        }
    }

    #[test]
    fn a_theme_that_replaces_default_leaves_the_builtin_as_the_last_resort() {
        let partial = files("default", &[("feed_busy.en.subject", "Occupied")]);
        let themes = Themes::build(vec![builtin(), partial], DEFAULT_THEME, 200_000).unwrap();
        assert_eq!(
            render_sample(&themes, "default", Template::FeedBusy, "en", Part::Subject),
            "Occupied"
        );
        let locales = ["en".to_owned()];
        let resolved = themes.resolve(Template::ImipRequest, &locales, "default").unwrap();
        assert_eq!(
            resolved.theme, "default",
            "the request is rendered in the theme it named, although the template is the built-in one"
        );
        assert_eq!(resolved.locale, "en");
        let html = render_sample(&themes, "default", Template::ImipRequest, "en", Part::Html);
        assert!(html.contains("invites you to an event"), "{html}");
    }

    #[test]
    fn resolution_prefers_the_locale_over_the_theme() {
        let corporate = files("corporate", &[("feed_busy.en.subject", "Corporate busy")]);
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        let german_first = ["de".to_owned(), "en".to_owned()];
        let resolved = themes.resolve(Template::FeedBusy, &german_first, "corporate").unwrap();
        assert_eq!(
            (resolved.theme, resolved.locale),
            ("corporate", "de"),
            "German from the default theme beats English from the requested theme, and it is rendered in the requested one"
        );
        assert_eq!(
            themes
                .render(
                    resolved.entry.subject.as_deref().unwrap(),
                    &context_of("corporate", "de")
                )
                .unwrap(),
            "Beschäftigt"
        );
        let english = ["en".to_owned()];
        let resolved = themes.resolve(Template::FeedBusy, &english, "corporate").unwrap();
        assert_eq!((resolved.theme, resolved.locale), ("corporate", "en"));
        assert_eq!(
            themes
                .render(
                    resolved.entry.subject.as_deref().unwrap(),
                    &context_of("corporate", "en")
                )
                .unwrap(),
            "Corporate busy"
        );
        assert!(
            themes
                .resolve(Template::FeedBusy, &["fr".to_owned()], "corporate")
                .is_none()
        );
    }

    #[test]
    fn themes_that_do_not_compile_or_lack_parts_are_refused_with_the_file() {
        let broken = files("broken", &[("feed_busy.en.subject", "{% if %}")]);
        let error = Themes::build(vec![builtin(), broken], DEFAULT_THEME, 200_000)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("broken") && error.contains("feed_busy.en.subject") && error.contains("does not compile"),
            "{error}"
        );

        let incomplete = files(
            "incomplete",
            &[
                ("imip_request.en.subject", "Invitation"),
                ("imip_request.en.html", "<p>x</p>"),
            ],
        );
        let error = Themes::build(vec![builtin(), incomplete], DEFAULT_THEME, 200_000).unwrap_err();
        assert!(
            matches!(
                &error,
                ThemeError::Missing {
                    part: "txt",
                    template: "imip_request",
                    ..
                }
            ),
            "{error}"
        );
        assert!(error.to_string().contains("imip_request.en.txt"));

        let typo = files("typo", &[("imip_requst.en.txt", "x")]);
        let error = Themes::build(vec![builtin(), typo], DEFAULT_THEME, 200_000)
            .unwrap_err()
            .to_string();
        assert!(error.contains("imip_requst") && error.contains("known:"), "{error}");
    }

    #[test]
    fn templates_that_use_fields_the_application_does_not_provide_fail_at_startup() {
        let strict = files("strict", &[("feed_busy.en.subject", "{{ tenant.name }}")]);
        let error = Themes::build(vec![builtin(), strict], DEFAULT_THEME, 200_000)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("strict") && error.contains("feed_busy") && error.contains("does not render"),
            "{error}"
        );
        let missing_partial = files("lost", &[("feed_busy.en.subject", "{% include \"_nowhere.txt\" %}")]);
        assert!(Themes::build(vec![builtin(), missing_partial], DEFAULT_THEME, 200_000).is_err());
    }

    #[test]
    fn runaway_templates_run_out_of_fuel() {
        let endless = files(
            "endless",
            &[(
                "feed_busy.en.subject",
                "{% for a in range(1000) %}{% for b in range(1000) %}x{% endfor %}{% endfor %}",
            )],
        );
        let error = Themes::build(vec![builtin(), endless], DEFAULT_THEME, 10_000)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("endless") && error.contains("does not render"),
            "{error}"
        );
    }

    #[test]
    fn error_messages_never_echo_model_values() {
        let nosy = files(
            "nosy",
            &[
                ("imip_cancel.en.subject", "{{ event.summary.missing.deeper }}"),
                ("imip_cancel.en.txt", "x"),
            ],
        );
        let error = Themes::build(vec![builtin(), nosy], DEFAULT_THEME, 200_000)
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("Planning") && !error.contains("anna@example.org"),
            "{error}"
        );
    }

    /// A layout of a deployment: the blocks of the default layout (`title`, `content`) and the footer partial.
    const CORPORATE_MAIL: &str = "<html lang=\"{{ locale }}\"><body class=\"corporate\">{% block content %}{% endblock %}\
                                  <footer>{% include \"_footer.\" ~ locale ~ \".html\" %}</footer></body></html>";

    #[test]
    fn a_theme_that_brings_only_its_layout_wraps_the_default_content() {
        let corporate = files(
            "corporate",
            &[
                ("_mail.html", CORPORATE_MAIL),
                ("_footer.en.html", "<p>Corporate footer {{ year }}</p>"),
            ],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        let html = render_sample(&themes, "corporate", Template::ImipRequest, "en", Part::Html);
        assert!(html.contains("class=\"corporate\""), "the layout of the theme: {html}");
        assert!(
            html.contains("invites you to an event"),
            "the content of the default template, inside the layout: {html}"
        );
        assert!(
            html.contains("Corporate footer 2027"),
            "the footer of the theme, with the year: {html}"
        );
        assert!(!html.contains("Sent by"), "{html}");
        // The same template rendered in the default theme is untouched.
        let default = render_sample(&themes, "default", Template::ImipRequest, "en", Part::Html);
        assert!(
            default.contains("Sent by") && !default.contains("corporate"),
            "{default}"
        );
        // What the theme did not override still comes from the default theme, partial by partial: the text footer and the
        // German footer have no counterpart in the theme.
        let text = render_sample(&themes, "corporate", Template::ImipRequest, "en", Part::Text);
        assert!(text.contains("Sent by"), "{text}");
        let german = render_sample(&themes, "corporate", Template::ImipRequest, "de", Part::Html);
        assert!(german.contains("class=\"corporate\""), "{german}");
        assert!(
            german.contains("Gesendet von"),
            "the German footer of the default theme: {german}"
        );
    }

    #[test]
    fn pages_are_rendered_in_the_requested_theme_so_that_its_style_sheet_is_linked() {
        // A theme that ships only a style sheet is a theme.
        let branded = files("branded", &[]);
        let themes = Themes::build(vec![builtin(), branded], DEFAULT_THEME, 200_000).unwrap();
        let html = render_sample(&themes, "branded", Template::RsvpPage, "en", Part::Html);
        assert!(html.contains("/assets/branded/page.css"), "{html}");
        let default = render_sample(&themes, "default", Template::RsvpPage, "en", Part::Html);
        assert!(default.contains("/assets/default/page.css"), "{default}");
    }

    #[test]
    fn a_template_of_a_theme_finds_the_layout_of_the_default_theme() {
        let corporate = files(
            "corporate",
            &[
                ("imip_cancel.en.subject", "Cancelled: {{ event.summary }}"),
                ("imip_cancel.en.txt", "Cancelled {{ event.summary }}"),
                (
                    "imip_cancel.en.html",
                    "{% extends \"_mail.html\" %}{% block content %}<p>Corporate cancellation of {{ event.summary }}</p>{% endblock %}",
                ),
            ],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        let html = render_sample(&themes, "corporate", Template::ImipCancel, "en", Part::Html);
        assert!(html.contains("Corporate cancellation of Planning"), "{html}");
        assert!(html.contains("Sent by"), "the footer of the default layout: {html}");
        // The German cancellation is the default's.
        let german = render_sample(&themes, "corporate", Template::ImipCancel, "de", Part::Subject);
        assert!(!german.contains("Cancelled:"), "{german}");
    }

    #[test]
    fn the_default_theme_of_the_deployment_is_the_first_fallback_of_every_theme() {
        let base = files("base", &[("_footer.en.html", "<p>Base footer</p>")]);
        let acme = files("acme", &[("_unused.html", "x")]);
        let themes = Themes::build(vec![builtin(), base.clone(), acme.clone()], "base", 200_000).unwrap();
        let html = render_sample(&themes, "acme", Template::ImipRequest, "en", Part::Html);
        assert!(
            html.contains("Base footer"),
            "acme falls back to base before default: {html}"
        );
        // Without it the default theme is the fallback.
        let themes = Themes::build(vec![builtin(), base, acme], DEFAULT_THEME, 200_000).unwrap();
        let html = render_sample(&themes, "acme", Template::ImipRequest, "en", Part::Html);
        assert!(html.contains("Sent by") && !html.contains("Base footer"), "{html}");
    }

    #[test]
    fn a_tenant_that_names_default_never_gets_the_branding_of_the_deployments_default_theme() {
        // The deployment ships a partial `default` (only a footer) and makes `corporate` its default theme.
        let partial = files("default", &[("_footer.en.html", "<p>Neutral footer</p>")]);
        let corporate = files(
            "corporate",
            &[
                ("_mail.html", CORPORATE_MAIL),
                ("_footer.en.html", "<p>Corporate footer</p>"),
            ],
        );
        let themes = Themes::build(vec![builtin(), partial, corporate], "corporate", 200_000).unwrap();
        // What the partial `default` lacks (the layout) is the built-in one's, not corporate's.
        let neutral = render_sample(&themes, "default", Template::ImipRequest, "en", Part::Html);
        assert!(
            neutral.contains("Neutral footer") && !neutral.contains("corporate") && !neutral.contains("Corporate"),
            "{neutral}"
        );
        assert!(neutral.contains("invites you to an event"), "{neutral}");
        // The deployment's default theme still serves the tenants that name none, and the other themes follow it.
        let branded = render_sample(&themes, "corporate", Template::ImipRequest, "en", Part::Html);
        assert!(branded.contains("class=\"corporate\""), "{branded}");
        let other = files("other", &[]);
        let themes = Themes::build(
            vec![
                builtin(),
                files("default", &[("_footer.en.html", "<p>Neutral footer</p>")]),
                files("corporate", &[("_footer.en.html", "<p>Corporate footer</p>")]),
                other,
            ],
            "corporate",
            200_000,
        )
        .unwrap();
        let html = render_sample(&themes, "other", Template::ImipRequest, "en", Part::Html);
        assert!(
            html.contains("Corporate footer") && !html.contains("Neutral footer"),
            "an ordinary theme falls back to the deployment's default theme first: {html}"
        );
    }

    #[test]
    fn a_layout_without_a_content_block_is_refused_because_the_engine_would_drop_the_content() {
        let no_blocks = files("empty", &[("_mail.html", "<body>nothing to see</body>")]);
        let error = Themes::build(vec![builtin(), no_blocks], DEFAULT_THEME, 200_000).unwrap_err();
        let text = error.to_string();
        assert!(
            matches!(
                &error,
                ThemeError::Layout { theme, layout: "_mail.html", .. } if theme == "empty"
            ),
            "{text}"
        );
        assert!(
            text.contains("empty") && text.contains("_mail.html") && text.contains("content"),
            "the theme and the layout are named: {text}"
        );

        let no_page_blocks = files(
            "empty",
            &[("_page.html", "<!doctype html><title>x</title><main></main>")],
        );
        let error = Themes::build(vec![builtin(), no_page_blocks], DEFAULT_THEME, 200_000).unwrap_err();
        assert!(
            matches!(
                &error,
                ThemeError::Layout {
                    layout: "_page.html",
                    ..
                }
            ),
            "the page layout is checked as well: {error}"
        );

        // A layout that names the block but puts it where it is never rendered drops the content just as well.
        let skipped = files(
            "skipped",
            &[(
                "_mail.html",
                "<body>{% if false %}{% block content %}{% endblock %}{% endif %}</body>",
            )],
        );
        assert!(Themes::build(vec![builtin(), skipped], DEFAULT_THEME, 200_000).is_err());

        // The theme that is meant: the content block anywhere, a template of its own that needs no layout, and a layout
        // that does without a title.
        let fine = files(
            "fine",
            &[
                ("_mail.html", "<body>{% block content %}{% endblock %}</body>"),
                ("imip_cancel.en.subject", "Cancelled"),
                ("imip_cancel.en.txt", "Cancelled"),
                ("imip_cancel.en.html", "<p>{{ event.summary }}</p>"),
            ],
        );
        Themes::build(vec![builtin(), fine], DEFAULT_THEME, 200_000).unwrap();
    }

    #[test]
    fn a_layout_that_breaks_the_content_of_the_default_theme_fails_with_the_theme_and_the_template() {
        let broken = files(
            "broken",
            &[("_mail.html", "{{ missing.field }}{% block content %}{% endblock %}")],
        );
        let error = Themes::build(vec![builtin(), broken], DEFAULT_THEME, 200_000).unwrap_err();
        let text = error.to_string();
        assert!(
            matches!(&error, ThemeError::Render { theme, .. } if theme == "broken") && text.contains("does not render"),
            "{text}"
        );
        // A layout that does not compile names its file.
        let typo = files("typo", &[("_mail.html", "{% block content %}")]);
        let error = Themes::build(vec![builtin(), typo], DEFAULT_THEME, 200_000)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("typo") && error.contains("_mail.html") && error.contains("does not compile"),
            "{error}"
        );
    }

    #[test]
    fn the_reserved_variables_now_and_year_reach_every_template() {
        let corporate = files(
            "corporate",
            &[(
                "feed_busy.en.subject",
                "Busy {{ now.date }} {{ now.time }} {{ now.zone }} {{ year }} {{ now.year }}",
            )],
        );
        let themes = Themes::build(vec![builtin(), corporate], DEFAULT_THEME, 200_000).unwrap();
        assert_eq!(
            render_sample(&themes, "corporate", Template::FeedBusy, "en", Part::Subject),
            "Busy 2027-01-12 10:00 UTC 2027 2027"
        );
    }

    #[test]
    fn directories_are_read_into_themes_ignoring_everything_that_is_not_a_template() {
        let root = std::env::temp_dir().join(format!("davhaven-themes-{}-read", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let theme = root.join("corporate");
        std::fs::create_dir_all(theme.join("assets")).unwrap();
        std::fs::create_dir_all(root.join("Not A Theme")).unwrap();
        std::fs::write(theme.join("feed_busy.en.subject"), "Busy").unwrap();
        std::fs::write(theme.join("_p.txt"), "p").unwrap();
        std::fs::write(theme.join("README.md"), "docs").unwrap();
        std::fs::write(theme.join("assets").join("logo.svg"), "<svg/>").unwrap();
        std::fs::write(root.join("loose-file.txt"), "x").unwrap();
        let themes = read_dir(&root).unwrap();
        assert_eq!(themes.len(), 1);
        assert_eq!(themes[0].name, "corporate");
        assert_eq!(
            themes[0].assets.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["logo.svg"],
            "the assets of the theme are read with it"
        );
        assert_eq!(
            themes[0].files.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["_p.txt", "feed_busy.en.subject"]
        );
        std::fs::write(theme.join("imip_requst.en.txt"), "typo").unwrap();
        assert!(matches!(read_dir(&root), Err(ThemeError::File { .. })));
        std::fs::remove_file(theme.join("imip_requst.en.txt")).unwrap();
        std::fs::write(theme.join("feed_busy.de.subject"), vec![0xff, 0xfe]).unwrap();
        let error = read_dir(&root).unwrap_err().to_string();
        assert!(error.contains("UTF-8"), "{error}");
        std::fs::remove_file(theme.join("feed_busy.de.subject")).unwrap();
        std::fs::write(theme.join("feed_busy.fr.subject"), vec![b'x'; 300 * 1024]).unwrap();
        assert!(read_dir(&root).unwrap_err().to_string().contains("256 KiB"));
        drop(std::fs::remove_dir_all(&root));
        assert!(matches!(read_dir(&root), Err(ThemeError::Io { .. })));
    }

    /// Theme directories that are mounted from a `ConfigMap` or a secret hold links to the real files (and the theme
    /// directory itself may be a link): they are themes like any other, and a link that points nowhere is an
    /// error and not a template that quietly does not exist.
    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_followed_and_dangling_ones_are_errors() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("davhaven-themes-{}-links", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let store = root.join("store");
        std::fs::create_dir_all(store.join("assets")).unwrap();
        std::fs::write(store.join("feed_busy.en.subject"), "Busy").unwrap();
        std::fs::write(store.join("assets").join("logo.svg"), "<svg/>").unwrap();
        let themes_dir = root.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        // The theme directory is a link to a directory, the template is a link to a file, the assets directory
        // holds a link as well.
        let theme = themes_dir.join("corporate");
        symlink(&store, &theme).unwrap();
        let linked_file = themes_dir.join("mounted");
        std::fs::create_dir_all(&linked_file).unwrap();
        symlink(
            store.join("feed_busy.en.subject"),
            linked_file.join("feed_busy.en.subject"),
        )
        .unwrap();
        std::fs::create_dir_all(linked_file.join("assets")).unwrap();
        symlink(
            store.join("assets").join("logo.svg"),
            linked_file.join("assets").join("logo.svg"),
        )
        .unwrap();

        let themes = read_dir(&themes_dir).unwrap();
        let names: Vec<&str> = themes.iter().map(|theme| theme.name.as_str()).collect();
        assert_eq!(names, vec!["corporate", "mounted"]);
        for theme in &themes {
            assert_eq!(
                theme.files.get("feed_busy.en.subject").map(String::as_str),
                Some("Busy"),
                "{}",
                theme.name
            );
            assert!(theme.assets.contains_key("logo.svg"), "{}", theme.name);
        }

        // A link that points nowhere (the mount is not there yet) is not silently skipped.
        symlink(store.join("missing"), linked_file.join("feed_busy.de.subject")).unwrap();
        assert!(matches!(read_dir(&themes_dir), Err(ThemeError::Io { .. })));
        drop(std::fs::remove_dir_all(&root));
    }
}
