//! The `ContentScanner` port for inline binary attachments.
//!
//! The application passes inline binary `ATTACH` content of iCalendar objects through every configured scanner
//! before it stores the object. The set is empty by default; a `ClamAV` adapter is a backlog item that becomes useful
//! with managed attachments.

use async_trait::async_trait;
use davhaven_domain::{MediaType, TenantId};

use crate::error::PortError;

/// What a scanner may know about the content it scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanContext {
    /// The tenant the content belongs to.
    pub tenant: TenantId,
    /// The declared media type (`FMTTYPE`), if any.
    pub content_type: Option<MediaType>,
}

/// The verdict of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanVerdict {
    /// Nothing found.
    Clean,
    /// The content is malicious; the text names the finding for operators.
    Infected(String),
}

/// Scans binary content.
#[async_trait]
pub trait ContentScanner: Send + Sync {
    /// The name of the scanner as selected in `plugins.content_scanners`.
    fn name(&self) -> &'static str;

    /// Scans `content`.
    ///
    /// # Errors
    ///
    /// `Unavailable` and `Timeout` when the scanning engine cannot be reached; the application then fails the write
    /// (fail closed) instead of storing unscanned content.
    async fn scan(&self, content: &[u8], context: &ScanContext) -> Result<ScanVerdict, PortError>;
}
