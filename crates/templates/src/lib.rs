//! Implementation of the `TemplateRenderer` port based on `minijinja`.
//!
//! Templates render with strict undefined behaviour and auto-escaping; themes are directories that override the
//! built-in default theme, which ships German and English templates.

#![forbid(unsafe_code)]

pub mod assets;
pub mod catalog;
pub mod config;
pub mod locale;
pub mod plugin;
pub mod renderer;
pub mod theme;
