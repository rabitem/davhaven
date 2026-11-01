//! Helpers the unit tests of several modules share.

/// The text of a file of `testdata/dav/sharing`: the request and answer documents of the collaboration flows,
/// kept byte for byte (see `testdata/dav/README.md`).
///
/// # Panics
///
/// When the file cannot be read: a test that names a fixture that is not there is a mistake.
pub(crate) fn fixture(name: &str) -> String {
    davhaven_fixtures::dav::sharing(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}
