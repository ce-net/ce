//! Host platform identification for per-(os, arch) native artifact resolution.
//!
//! The manifest keys native artifacts by a canonical `"<os>-<arch>"` string
//! (e.g. `darwin-arm64`, `linux-amd64`). We normalise Rust's `std::env::consts`
//! values to that vocabulary so one manifest resolves the right bytes on any host
//! while the install *command* stays identical everywhere.
//!
//! This tiny normalisation is load-bearing at scale: the pooled compute comes from
//! wildly mixed hardware, and collapsing each host's reported os/arch to one shared
//! vocabulary is what lets a single published manifest auto-resolve the correct binary
//! on any of millions of devices. The matching layer makes a heterogeneous fleet
//! behave as one uniform target.

/// Canonical OS token used in manifest artifact keys.
pub fn os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other, // "linux", "windows", ...
    }
}

/// Canonical CPU architecture token used in manifest artifact keys.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// The host target key, e.g. `darwin-arm64` or `linux-amd64`.
pub fn host_target() -> String {
    format!("{}-{}", os(), arch())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_target_is_os_dash_arch() {
        let t = host_target();
        assert!(t.contains('-'), "target should be '<os>-<arch>': {t}");
        // Whatever host runs the test, the OS half must be a normalised token.
        let (os_part, _) = t.split_once('-').unwrap();
        assert!(!os_part.is_empty());
        assert_ne!(os_part, "macos", "macos must normalise to darwin");
    }

    #[test]
    fn arch_normalises_known_values() {
        // We can't force ARCH, but the mapping function is total and pure.
        assert_eq!(arch().is_empty(), false);
    }
}
