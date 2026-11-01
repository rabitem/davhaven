use super::*;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("davhaven-assets-{}-{name}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_built_in_style_sheet_is_found_by_its_name_only() {
    let assets = builtin();
    let sheet = assets.get("page.css").unwrap();
    assert_eq!(sheet.content_type, "text/css; charset=utf-8");
    assert!(sheet.body.starts_with(b":root{"));
    assert_eq!(sheet.etag, ETag::from_bytes(&sheet.body));
    assert_eq!(assets.len(), 1);
    for other in ["", "page", "page.css/", "Page.css", "../page.css", "default/page.css"] {
        assert!(!assets.contains_key(other), "{other:?}");
    }
}

#[test]
fn the_style_sheet_loads_nothing_from_anywhere_else() {
    let sheet = builtin().remove("page.css").unwrap();
    let css = core::str::from_utf8(&sheet.body).unwrap();
    for forbidden in [
        "@import",
        "url(",
        "http:",
        "https:",
        "expression(",
        "javascript:",
        "@font-face",
    ] {
        assert!(!css.contains(forbidden), "{forbidden}");
    }
    assert!(
        css.contains("prefers-color-scheme:dark"),
        "the dark scheme is part of the sheet"
    );
    assert!(css.contains(":focus-visible"), "focus stays visible");
}

#[test]
fn every_page_of_the_default_theme_links_the_style_sheet_of_the_theme_it_renders_in() {
    let layout = include_str!("../../themes/default/_page.html");
    assert!(
        layout.contains(r#"<link rel="stylesheet" href="/assets/{{ theme }}/page.css">"#),
        "a theme that copies the layout finds its own sheet, and the others fall back to the built-in one"
    );
    assert!(!layout.contains("<style"), "inline styles are blocked by the page CSP");
    assert!(!layout.contains("style=\""), "so are style attributes");
}

#[test]
fn media_types_follow_the_extension_and_scripts_are_not_served() {
    for (name, expected) in [
        ("page.css", "text/css; charset=utf-8"),
        ("logo.PNG", "image/png"),
        ("a.b.jpeg", "image/jpeg"),
        ("x.jpg", "image/jpeg"),
        ("x.gif", "image/gif"),
        ("x.webp", "image/webp"),
        ("logo.svg", "image/svg+xml"),
        ("favicon.ico", "image/x-icon"),
        ("font.woff2", "font/woff2"),
    ] {
        assert_eq!(media_type(name), Some(expected), "{name}");
    }
    for refused in ["app.js", "page.html", "page.htm", "x.xml", "x.php", "noextension", "x."] {
        assert_eq!(media_type(refused), None, "{refused} must not be served");
    }
    assert_eq!(MEDIA_TYPES.len(), 9);
}

#[test]
fn asset_names_are_plain() {
    for good in ["page.css", "logo-2.min.png", "a_b.svg", "A1.ico"] {
        assert!(is_valid_name(good), "{good}");
    }
    let long = "a".repeat(101);
    for bad in [
        "",
        ".hidden",
        "a/b",
        "a b",
        "ä.css",
        "a\\b.css",
        "a\0.css",
        long.as_str(),
    ] {
        assert!(!is_valid_name(bad), "{bad:?}");
    }
}

#[test]
fn a_theme_without_assets_has_none() {
    let root = scratch("none");
    assert!(read_dir("corporate", &root).unwrap().is_empty());
    drop(std::fs::remove_dir_all(&root));
}

#[test]
fn the_files_of_a_theme_are_read_with_their_types_and_validators() {
    let root = scratch("read");
    let assets = root.join("assets");
    std::fs::create_dir_all(assets.join("a-directory")).unwrap();
    std::fs::write(assets.join("page.css"), "body{color:#123}").unwrap();
    std::fs::write(assets.join("logo.svg"), "<svg/>").unwrap();
    std::fs::write(assets.join(".DS_Store"), "junk").unwrap();
    let read = read_dir("corporate", &root).unwrap();
    assert_eq!(
        read.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["logo.svg", "page.css"]
    );
    let sheet = &read["page.css"];
    assert_eq!(sheet.body.as_ref(), b"body{color:#123}");
    assert_eq!(sheet.content_type, "text/css; charset=utf-8");
    assert_eq!(sheet.etag, ETag::from_bytes(b"body{color:#123}"));
    assert_ne!(read["logo.svg"].etag, sheet.etag);
    drop(std::fs::remove_dir_all(&root));
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_followed_because_mounts_expose_their_files_that_way() {
    // The theme directories are the operator's own (a ConfigMap or secret mount shows its files as links): a link
    // to a file is a file, a link to a directory is skipped like a directory, and the rules for names, types and
    // sizes apply to what the link points at.
    let root = scratch("links");
    let store = scratch("links-store");
    std::fs::write(store.join("mounted.css"), "body{}").unwrap();
    std::fs::create_dir_all(store.join("a-directory")).unwrap();
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    std::os::unix::fs::symlink(store.join("mounted.css"), assets.join("linked.css")).unwrap();
    std::os::unix::fs::symlink(store.join("a-directory"), assets.join("linked-dir")).unwrap();
    std::fs::write(assets.join("page.css"), "ok").unwrap();
    let read = read_dir("corporate", &root).unwrap();
    assert_eq!(
        read.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["linked.css", "page.css"]
    );
    assert_eq!(read["linked.css"].body.as_ref(), b"body{}");

    // A link whose target is gone (the mount is not there) is an error, not a logo that is quietly missing.
    std::os::unix::fs::symlink(store.join("missing.png"), assets.join("logo.png")).unwrap();
    assert!(matches!(read_dir("corporate", &root), Err(ThemeError::Io { .. })));
    drop(std::fs::remove_dir_all(&root));
    drop(std::fs::remove_dir_all(&store));
}

#[test]
fn files_that_break_the_rules_stop_the_start_with_their_name() {
    let root = scratch("rules");
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    for (name, body, expected) in [
        ("app.js", vec![b'x'], "not served"),
        ("index.html", vec![b'x'], "not served"),
        ("my logo.png", vec![b'x'], "letters, digits"),
        ("big.png", vec![b'x'; 600 * 1024], "512 KiB"),
    ] {
        std::fs::write(assets.join(name), body).unwrap();
        let error = read_dir("corporate", &root).unwrap_err().to_string();
        assert!(
            error.contains("corporate") && error.contains(name) && error.contains(expected),
            "{name}: {error}"
        );
        std::fs::remove_file(assets.join(name)).unwrap();
    }
    for index in 0..=MAX_ASSETS_PER_THEME {
        std::fs::write(assets.join(format!("f{index:03}.css")), "x").unwrap();
    }
    let error = read_dir("corporate", &root).unwrap_err().to_string();
    assert!(error.contains("at most 64"), "{error}");
    drop(std::fs::remove_dir_all(&root));
}
