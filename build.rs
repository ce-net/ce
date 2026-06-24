use std::process::Command;

// Stamp the git short SHA + build date into the binary so `ce --version` makes build drift between
// nodes VISIBLE (e.g. "0.1.1 (dd35dc6, 2026-06-24)"). Two nodes on the same semver but different
// commits were silently breaking the mesh; now you can see it. Falls back gracefully when git/date
// are unavailable (container builds), so it never breaks the build.
fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CE_GIT_HASH={sha}");

    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "?".to_string());
    println!("cargo:rustc-env=CE_BUILD_DATE={date}");

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
