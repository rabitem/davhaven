//! Helpers for adapter configuration structs.
//!
//! Every adapter owns its configuration struct (`Deserialize + JsonSchema`, `deny_unknown_fields`, a default for
//! every key) and validates it when the plugin is built (`ENGINEERING_RULES` R3). The conventions shared by all of
//! them live here: secrets are never inline-only, they are read from a file named by a `*_file` key
//! (`password_file`, `secret_file`, `url_file`), and the content of such a file never appears in an error.

use std::io::Read as _;
use std::path::Path;

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::PluginError;

/// The largest secret file the adapters read (a database URL or key is far smaller).
const MAX_SECRET_FILE_BYTES: usize = 64 * 1024;

/// Reads a secret from the file named by the `key` option of `plugin`.
///
/// The file content is the secret; one trailing line break (as editors and `echo` leave) is removed and nothing
/// else is trimmed. Empty files, files larger than 64 KiB and files that are not valid UTF-8 are refused.
///
/// The bytes of the file are read into one buffer that is wiped when it goes, on the error paths too, and the secret is
/// built from a slice of it: no copy of a key is left behind in memory that nobody wipes. (The buffer has the largest size
/// a secret file may have, plus one byte, from the start, so reading never grows it and so never copies it to a new
/// allocation that the old one's wipe would not reach.)
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming `plugin` and `key`. The message contains the file path but never the
/// content of the file.
pub fn read_secret_file(plugin: &str, key: &str, path: &Path) -> Result<SecretString, PluginError> {
    let fail = |reason: &str| PluginError::invalid_config(plugin, format!("`{key}` ({}): {reason}", path.display()));
    let unreadable = |error: &std::io::Error| fail(&format!("cannot read the file ({})", error.kind()));
    let file = std::fs::File::open(path).map_err(|error| unreadable(&error))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_FILE_BYTES + 1));
    let limit = u64::try_from(MAX_SECRET_FILE_BYTES + 1).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(&error))?;
    if bytes.len() > MAX_SECRET_FILE_BYTES {
        return Err(fail("the file is larger than 64 KiB"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| fail("the file is not valid UTF-8"))?;
    let secret = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .map_or(text, |stripped| stripped);
    if secret.is_empty() {
        return Err(fail("the file is empty"));
    }
    Ok(SecretString::from(secret))
}

/// Resolves a secret that is given either inline (`inline`) or by file (`file`), as `database.url` and
/// `database.url_file` are.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] when both or neither are set, or when the file cannot be read (see
/// [`read_secret_file`]). `inline_key` and `file_key` name the options in the message.
pub fn resolve_secret(
    plugin: &str,
    inline_key: &str,
    inline: Option<&SecretString>,
    file_key: &str,
    file: Option<&Path>,
) -> Result<SecretString, PluginError> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(PluginError::invalid_config(
            plugin,
            format!("set either `{inline_key}` or `{file_key}`, not both"),
        )),
        (Some(value), None) => Ok(value.clone()),
        (None, Some(path)) => read_secret_file(plugin, file_key, path),
        (None, None) => Err(PluginError::invalid_config(
            plugin,
            format!("`{inline_key}` or `{file_key}` is required"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;

    use secrecy::ExposeSecret;

    use super::*;

    /// A file in the temp directory that is removed when the test ends.
    struct TempFile(PathBuf);

    impl TempFile {
        fn with(name: &str, content: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!("davhaven-ports-{}-{name}", std::process::id()));
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(content).unwrap();
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.0));
        }
    }

    #[test]
    fn one_trailing_line_break_is_removed() {
        for (name, content, expected) in [
            ("plain", "s3cret", "s3cret"),
            ("lf", "s3cret\n", "s3cret"),
            ("crlf", "s3cret\r\n", "s3cret"),
            ("two", "s3cret\n\n", "s3cret\n"),
            ("inner", " a b \n", " a b "),
        ] {
            let file = TempFile::with(name, content.as_bytes());
            let secret = read_secret_file("smtp", "password_file", &file.0).unwrap();
            assert_eq!(secret.expose_secret(), expected, "{name}");
        }
    }

    #[test]
    fn the_size_limit_is_exact() {
        let at_the_limit = TempFile::with("at-limit", &vec![b'a'; MAX_SECRET_FILE_BYTES]);
        let secret = read_secret_file("smtp", "password_file", &at_the_limit.0).unwrap();
        assert_eq!(secret.expose_secret().len(), MAX_SECRET_FILE_BYTES);
        let over = TempFile::with("over-limit", &vec![b'a'; MAX_SECRET_FILE_BYTES + 1]);
        let shown = read_secret_file("smtp", "password_file", &over.0)
            .unwrap_err()
            .to_string();
        assert!(shown.contains("larger than 64 KiB"), "{shown}");
    }

    #[test]
    fn unusable_files_are_refused_without_leaking_their_content() {
        let mut not_utf8 = b"hunter2".to_vec();
        not_utf8.push(0xff);
        let empty = TempFile::with("empty", b"");
        let only_newline = TempFile::with("newline", b"\n");
        let binary = TempFile::with("binary", &not_utf8);
        let big = TempFile::with("big", &vec![b'a'; 70_000]);
        for file in [&empty, &only_newline, &binary, &big] {
            let shown = read_secret_file("smtp", "password_file", &file.0)
                .unwrap_err()
                .to_string();
            assert!(shown.contains("smtp") && shown.contains("password_file"), "{shown}");
            assert!(!shown.contains("hunter2"), "{shown}");
        }
        let missing = std::env::temp_dir().join("davhaven-ports-does-not-exist");
        let error = read_secret_file("smtp", "password_file", &missing).unwrap_err();
        assert!(
            error.to_string().contains("cannot read the file") && error.to_string().contains("password_file"),
            "{error}"
        );
    }

    #[test]
    fn inline_and_file_secrets_are_exclusive() {
        let file = TempFile::with("exclusive", b"from-file\n");
        let inline = SecretString::from("inline");
        let both = resolve_secret("postgres", "url", Some(&inline), "url_file", Some(&file.0)).unwrap_err();
        assert!(both.to_string().contains("not both"), "{both}");
        let neither = resolve_secret("postgres", "url", None, "url_file", None).unwrap_err();
        assert!(neither.to_string().contains("is required"), "{neither}");
        let from_inline = resolve_secret("postgres", "url", Some(&inline), "url_file", None).unwrap();
        assert_eq!(from_inline.expose_secret(), "inline");
        let from_file = resolve_secret("postgres", "url", None, "url_file", Some(&file.0)).unwrap();
        assert_eq!(from_file.expose_secret(), "from-file");
    }
}
