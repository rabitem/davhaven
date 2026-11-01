//! The `eicar` content scanner: the selectable fake next to the documented empty default set of the `ContentScanner` port.
//!
//! The application passes inline binary `ATTACH` content through every scanner of `plugins.content_scanners` before it
//! stores an object (PLAN 1.1). The set is empty by default, and a real scanner (`ClamAV`, in the roadmap) is an adapter
//! of its own. Until it exists this crate is the plugin of the kind that makes the scanning path testable
//! (`ENGINEERING_RULES` R2): it reports the EICAR anti-virus test string as infected and everything else as clean.
//!
//! It is a **fake**: a deployment that selected it would believe its uploads are scanned, so production mode refuses it.
//! Its descriptor says so (`PluginDescriptor::with_refused_in_production`): the plugin registry refuses to build it in
//! production and `davhaven config check` reports it from the same flag, so no list in the server knows it. It runs the
//! contract suite of its port like every implementation.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`scanner`] | [`EicarScanner`](scanner::EicarScanner) and the test string it looks for ([`EICAR`](scanner::EICAR)) |
//! | [`config`] | the (empty) table of the plugin |
//! | [`plugin`] | `register`, the plugin descriptor |

#![forbid(unsafe_code)]

pub mod config;
pub mod plugin;
pub mod scanner;
