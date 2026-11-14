use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=REALM_VERSION");

    let Ok(version) = env::var("REALM_VERSION") else {
        return;
    };

    let version = version.trim();

    if version.is_empty() {
        return;
    }

    assert!(!version.chars().any(char::is_control), "invalid REALM_VERSION");

    println!("cargo:rustc-env=REALM_VERSION={version}");
}
