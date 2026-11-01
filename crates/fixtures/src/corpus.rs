//! Loader for the iCalendar corpus of real client bodies (`testdata/corpus`).
//!
//! The files are compared byte for byte and keep their line endings (`.gitattributes` marks `testdata/**` as
//! binary), so they are read as they are. Client-flow scenarios send them as request bodies; the tests of the
//! `ical` crate parse every one of them.

use std::io;
use std::path::{Path, PathBuf};

/// The `testdata` directory of the repository: the corpus, the request bodies of the clients and the sharing documents.
/// Client-flow scenarios read their `body_file`s from below it.
pub fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// The directory of the corpus.
pub fn root() -> PathBuf {
    data_dir().join("corpus")
}

/// The text of the corpus file `name` (a path below the corpus directory with `/` as the separator, for example
/// `apple-macos-weekly-override.ics` or `imip/google-request.ics`), byte for byte.
///
/// # Errors
///
/// The error of reading the file; a name that leaves the corpus directory is refused with
/// [`io::ErrorKind::InvalidInput`].
pub fn read(name: &str) -> io::Result<String> {
    if name.split('/').any(|part| part == ".." || part.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a path below the corpus directory"),
        ));
    }
    std::fs::read_to_string(root().join(name))
}

/// The names of all corpus files, sorted, with `/` as the separator.
///
/// # Errors
///
/// The error of reading a directory.
pub fn names() -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    collect(&root(), "", &mut found)?;
    found.sort();
    Ok(found)
}

fn collect(dir: &Path, prefix: &str, out: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            collect(&path, &format!("{prefix}{name}/"), out)?;
        } else if path.extension().is_some_and(|extension| extension == "ics") {
            out.push(format!("{prefix}{name}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_corpus_is_listed_and_read_byte_for_byte() {
        let names = names().unwrap();
        assert!(
            names.contains(&"apple-macos-weekly-override.ics".to_owned()),
            "{names:?}"
        );
        assert!(names.contains(&"imip/google-request.ics".to_owned()));
        let text = read("apple-macos-weekly-override.ics").unwrap();
        assert!(text.starts_with("BEGIN:VCALENDAR\r\n"), "CRLF line endings are kept");
        assert!(read("lenient-lf-line-endings.ics").unwrap().contains("\nEND:VCALENDAR"));
        assert_eq!(names, {
            let mut sorted = names.clone();
            sorted.sort();
            sorted
        });
    }

    #[test]
    fn names_cannot_leave_the_corpus() {
        for bad in ["../README.md", "imip/../../x", "/etc/passwd", ""] {
            assert_eq!(read(bad).unwrap_err().kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
        assert_eq!(read("no-such-file.ics").unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}
