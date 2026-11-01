//! The static assets of the themes: the built-in style sheet and the files of the `assets/` directories of the
//! configured theme directories.
//!
//! The web surface answers every page with a strict `Content-Security-Policy` (`style-src 'self'`, no inline
//! styles, no scripts), so the pages load their style sheet from the server's own origin: `/assets/{theme}/page.css`.
//! The renderer holds every asset in memory (`TemplateRenderer::asset`); the web layer reaches it through the
//! application's `AssetService` and never touches the file system. Mails carry their styles inline: mail clients
//! ignore style sheets that are linked.
//!
//! # What a theme may ship
//!
//! `{theme_dir}/{theme}/assets/` is one flat directory. A file is accepted when
//!
//! * its name is 1 to 100 characters of letters, digits, `.`, `_` and `-` and does not start with a dot (files
//!   that start with a dot are ignored),
//! * it is a regular file (directories and symbolic links are skipped, so nothing outside the theme directory is
//!   ever read),
//! * its extension is one of [`MEDIA_TYPES`] (no scripts, no HTML) and
//! * it is at most [`MAX_ASSET_BYTES`] large; a theme has at most [`MAX_ASSETS_PER_THEME`] files.
//!
//! A file that breaks a rule fails the start of the server with its name, like a template that does not compile.
//! Serving never opens a file: the lookup is a map from the checked name to the bytes read at start-up.

use std::collections::BTreeMap;
use std::path::Path;

use bytes::Bytes;
use davhaven_domain::ETag;
use davhaven_ports::ThemeAsset;

use crate::theme::ThemeError;

/// The largest asset file, in bytes.
pub const MAX_ASSET_BYTES: u64 = 512 * 1024;

/// The most asset files of one theme.
pub const MAX_ASSETS_PER_THEME: usize = 64;

/// The longest asset file name, in bytes.
const MAX_NAME_BYTES: usize = 100;

/// The extensions a theme may ship and the media types they are served with. Scripts and HTML are not on the list:
/// the pages run without JavaScript, and a served HTML file would be a page of the server's own origin.
pub const MEDIA_TYPES: [(&str, &str); 9] = [
    ("css", "text/css; charset=utf-8"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("svg", "image/svg+xml"),
    ("ico", "image/x-icon"),
    ("woff2", "font/woff2"),
];

/// The media type of a file name, by its extension (case-insensitive); `None` for extensions that are not served.
pub fn media_type(name: &str) -> Option<&'static str> {
    let (_, extension) = name.rsplit_once('.')?;
    MEDIA_TYPES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(extension))
        .map(|(_, media_type)| *media_type)
}

/// Whether `name` is a plain asset file name: letters, digits, `.`, `_` and `-`, not starting with a dot.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An asset ready to be served.
pub fn asset(media_type: &'static str, body: Vec<u8>) -> ThemeAsset {
    let etag = ETag::from_bytes(&body);
    ThemeAsset {
        content_type: media_type,
        body: Bytes::from(body),
        etag,
    }
}

/// A file of the built-in theme.
struct Builtin {
    name: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

/// Every asset of the built-in theme.
const BUILTIN: [Builtin; 1] = [Builtin {
    name: "page.css",
    content_type: "text/css; charset=utf-8",
    body: include_bytes!("../themes/default/assets/page.css"),
}];

/// The assets of the built-in theme, by file name.
pub fn builtin() -> BTreeMap<String, ThemeAsset> {
    BUILTIN
        .iter()
        .map(|file| (file.name.to_owned(), asset(file.content_type, file.body.to_vec())))
        .collect()
}

/// Reads the `assets/` directory of the theme directory `theme_dir` (`theme` is its name, for messages). A theme
/// without an `assets/` directory has no assets.
///
/// # Errors
///
/// [`ThemeError::Io`] for unreadable files and [`ThemeError::File`] for files that break the rules of this module.
pub fn read_dir(theme: &str, theme_dir: &Path) -> Result<BTreeMap<String, ThemeAsset>, ThemeError> {
    let dir = theme_dir.join("assets");
    let io_error = |path: &Path, error: &std::io::Error| ThemeError::Io {
        path: path.to_path_buf(),
        kind: error.kind(),
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(io_error(&dir, &error)),
    };
    let mut entries: Vec<_> = entries
        .collect::<Result<_, _>>()
        .map_err(|error| io_error(&dir, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut assets = BTreeMap::new();
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let fail = |reason: &str| ThemeError::File {
            theme: theme.to_owned(),
            file: format!("assets/{name}"),
            reason: reason.to_owned(),
        };
        if name.starts_with('.') {
            continue;
        }
        // `metadata` follows symbolic links: a ConfigMap or secret mount exposes its files as links, and a theme
        // whose logo is silently missing is worse than a refused start. A dangling link is an error.
        if !std::fs::metadata(&path)
            .map_err(|error| io_error(&path, &error))?
            .is_file()
        {
            continue;
        }
        if !is_valid_name(&name) {
            return Err(fail(
                "asset names may only contain letters, digits, `.`, `_` and `-` (at most 100 characters)",
            ));
        }
        let Some(content_type) = media_type(&name) else {
            let known: Vec<&str> = MEDIA_TYPES.iter().map(|(extension, _)| *extension).collect();
            return Err(fail(&format!(
                "this kind of file is not served (known extensions: {})",
                known.join(", ")
            )));
        };
        let size = std::fs::metadata(&path).map_err(|error| io_error(&path, &error))?.len();
        if size > MAX_ASSET_BYTES {
            return Err(fail("the file is larger than 512 KiB"));
        }
        if assets.len() >= MAX_ASSETS_PER_THEME {
            return Err(fail("a theme may have at most 64 asset files"));
        }
        let body = std::fs::read(&path).map_err(|error| io_error(&path, &error))?;
        assets.insert(name, asset(content_type, body));
    }
    Ok(assets)
}

#[cfg(test)]
mod tests;
