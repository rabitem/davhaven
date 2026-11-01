//! Re-runs the build when a migration changes, because `sqlx::migrate!` embeds the files at compile time.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
