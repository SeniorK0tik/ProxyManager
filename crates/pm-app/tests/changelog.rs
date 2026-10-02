//! The changelog must describe the version being built (it becomes the release notes).

const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");

#[test]
fn changelog_has_section_for_current_version() {
    let heading = format!("## [{}] - ", env!("CARGO_PKG_VERSION"));
    assert!(
        CHANGELOG.lines().any(|l| l.starts_with(&heading)),
        "CHANGELOG.md has no `{heading}YYYY-MM-DD` section"
    );
}

#[test]
fn changelog_keeps_unreleased_section_and_links() {
    assert!(CHANGELOG.lines().any(|l| l == "## [Unreleased]"));
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        CHANGELOG.contains(&format!(
            "[{version}]: https://github.com/SeniorK0tik/ProxyManager/releases/tag/v{version}"
        )),
        "missing link reference for {version}"
    );
}
