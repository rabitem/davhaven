//! The request and answer documents of the DAV collaboration flows.
//!
//! `testdata/dav/sharing` holds what CalendarServer clients send to share a calendar, answer an invitation, list the
//! notification collection and ask for the free time of people, and the documents the server writes in return. Several
//! test suites (the unit tests of `davhaven-app` and `davhaven-dav`, the protocol tests and the integration tests)
//! read them; this is the one place that knows where they are.

use std::io;

/// The text of a file of `testdata/dav/sharing`, byte for byte.
///
/// # Errors
///
/// The error of reading the file, which names a file that does not exist when a test asks for one by mistake.
pub fn sharing(name: &str) -> io::Result<String> {
    std::fs::read_to_string(crate::corpus::data_dir().join("dav/sharing").join(name))
}

/// The text of a request body of a real client in `testdata/dav` (for example `macos-propfind-home.xml`), byte for
/// byte. Names are plain file names; a path that leaves the directory is refused.
///
/// # Errors
///
/// The error of reading the file; a name with a separator or a dot segment is refused with
/// [`io::ErrorKind::InvalidInput`].
pub fn client(name: &str) -> io::Result<String> {
    if name.contains('/') || name.contains('\\') || name.starts_with('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a file name"),
        ));
    }
    std::fs::read_to_string(crate::corpus::data_dir().join("dav").join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documents_are_read_as_they_are_stored() {
        let notification = sharing("notification-invite.xml").unwrap();
        assert!(notification.contains("invite-notification"));
        assert!(sharing("there-is-no-such-file.xml").is_err());
        assert!(client("macos-propfind-home.xml").unwrap().contains("propfind"));
        assert_eq!(client("../README.md").unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
