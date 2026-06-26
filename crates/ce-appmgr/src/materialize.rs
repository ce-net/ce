//! Artifact materialization: turn a resolved manifest into a concrete, verified,
//! runnable thing on disk.
//!
//! Content-addressed tiers (`native`, `wasm`) are fetched from CE blobs — the same
//! sha256-keyed blob store the node and ce-hub expose at `/blobs/<hex>` — and the
//! sha256 digest is verified against the manifest before anything is written. The
//! `oci` tier needs no fetch at install time: the image reference is recorded and
//! `ce-container` pulls it on first run (M3). `recipe` builds are out of scope here
//! (built on the relay and promoted to a `native` artifact).
//!
//! No node/SDK dependency: this is plain reqwest + sha2 + std::fs so the agent can
//! materialize without pulling in libp2p or ce-rs.
//!
//! Content addressing is what makes artifact distribution trustless at fleet scale:
//! because the digest is verified before a byte is written, any of millions of nodes
//! can pull the identical artifact from whichever blob holder is nearest and still be
//! certain it is the published bytes — no trust in the source, automatic dedup of
//! popular artifacts, and corruption caught locally rather than spread.

use crate::manifest::{AppManifest, Runtime};
use crate::store::Store;
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The on-disk result of materializing an app's artifact for a host.
#[derive(Debug, Clone)]
pub enum Materialized {
    /// A native executable written and marked runnable.
    Native { bin_path: PathBuf, digest: String },
    /// A wasm module written to disk.
    Wasm { module_path: PathBuf, digest: String },
    /// An oci image reference; the image is pulled lazily at run time.
    Oci { image: String },
    /// A recipe-built app; building is deferred to the relay build path.
    Recipe { source: String },
}

impl Materialized {
    /// The content digest if this tier is content-addressed, else `None`.
    pub fn digest(&self) -> Option<&str> {
        match self {
            Materialized::Native { digest, .. } | Materialized::Wasm { digest, .. } => Some(digest),
            _ => None,
        }
    }
}

/// Lowercase-hex sha256 of a byte slice — matches the node's `/blobs` keying and
/// ce-rs `cid()`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Parse a manifest digest of the form `"<algo>:<hex>"` (e.g. `sha256:ab…`) into
/// its algorithm and hex halves. A bare hex string is treated as `sha256`.
pub fn parse_digest(d: &str) -> Result<(&str, &str)> {
    match d.split_once(':') {
        Some((algo, hex)) => {
            if hex.is_empty() {
                bail!("digest '{d}' has empty hex");
            }
            Ok((algo, hex))
        }
        None => {
            if d.is_empty() {
                bail!("empty digest");
            }
            Ok(("sha256", d))
        }
    }
}

/// Fetches content-addressed blobs from a CE blob store (ce-hub / node `/blobs`).
#[derive(Debug, Clone)]
pub struct BlobClient {
    base: String,
    client: reqwest::Client,
}

impl BlobClient {
    /// `base` is the blob-store origin (the ce-hub origin works: blobs live at
    /// `{base}/blobs/<hex>`).
    pub fn new(base: impl Into<String>) -> Self {
        BlobClient {
            base: base.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Fetch the blob named by `digest` and verify its content hash matches. Only
    /// sha256 is supported today (the node's blob keying); other algorithms error
    /// rather than silently skipping verification.
    pub async fn fetch_and_verify(&self, digest: &str) -> Result<Vec<u8>> {
        let (algo, hexhash) = parse_digest(digest)?;
        if algo != "sha256" {
            bail!("unsupported digest algorithm '{algo}' (only sha256)");
        }
        let url = format!("{}/blobs/{}", self.base, hexhash);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetching artifact blob {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("artifact blob {hexhash} not found at {url}"));
        }
        let bytes = resp
            .error_for_status()
            .with_context(|| format!("blob store error for {url}"))?
            .bytes()
            .await
            .context("reading artifact blob bytes")?
            .to_vec();
        let got = sha256_hex(&bytes);
        if got != hexhash {
            bail!("artifact digest mismatch: manifest says {hexhash}, blob hashes to {got}");
        }
        Ok(bytes)
    }
}

/// Materialize the artifact for `m` on `target`, writing content-addressed tiers
/// into the store's versioned dir. Idempotent: an already-present, correctly-hashed
/// file is not refetched.
pub async fn materialize(
    store: &Store,
    blobs: &BlobClient,
    m: &AppManifest,
    target: &str,
) -> Result<Materialized> {
    let vdir = store.version_dir(&m.app.name, &m.app.version.to_string());
    match m.app.runtime {
        Runtime::Native => {
            let digest = m
                .native_digest(target)
                .ok_or_else(|| anyhow!("'{}' has no native build for {target}", m.app.name))?
                .to_string();
            let bin = m
                .native
                .as_ref()
                .map(|n| n.bin.clone())
                .ok_or_else(|| anyhow!("native manifest missing [native].bin"))?;
            std::fs::create_dir_all(&vdir)?;
            let bin_path = vdir.join(&bin);
            // Skip refetch if the file is already present with the right hash.
            if !file_matches(&bin_path, &digest)? {
                let bytes = blobs.fetch_and_verify(&digest).await?;
                std::fs::write(&bin_path, &bytes)
                    .with_context(|| format!("writing {}", bin_path.display()))?;
                make_executable(&bin_path)?;
            }
            Ok(Materialized::Native { bin_path, digest })
        }
        Runtime::Wasm => {
            let w = m
                .wasm
                .as_ref()
                .ok_or_else(|| anyhow!("wasm manifest missing [wasm]"))?;
            let digest = w.artifact.clone();
            std::fs::create_dir_all(&vdir)?;
            let module_path = vdir.join(format!("{}.wasm", m.app.name));
            if !file_matches(&module_path, &digest)? {
                let bytes = blobs.fetch_and_verify(&digest).await?;
                std::fs::write(&module_path, &bytes)
                    .with_context(|| format!("writing {}", module_path.display()))?;
            }
            Ok(Materialized::Wasm { module_path, digest })
        }
        Runtime::Oci => {
            let image = m
                .oci
                .as_ref()
                .map(|o| o.image.clone())
                .ok_or_else(|| anyhow!("oci manifest missing [oci].image"))?;
            Ok(Materialized::Oci { image })
        }
        Runtime::Recipe => {
            let source = m
                .recipe
                .as_ref()
                .map(|r| r.source.clone())
                .ok_or_else(|| anyhow!("recipe manifest missing [recipe].source"))?;
            Ok(Materialized::Recipe { source })
        }
    }
}

/// True if `path` exists and its sha256 already equals the digest's hex (so a
/// re-materialize is a no-op).
fn file_matches(path: &std::path::Path, digest: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let (_, hexhash) = parse_digest(digest)?;
    let bytes = std::fs::read(path)?;
    Ok(sha256_hex(&bytes) == hexhash)
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // sha256("") = e3b0c442...
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_digest_forms() {
        assert_eq!(parse_digest("sha256:abcd").unwrap(), ("sha256", "abcd"));
        assert_eq!(parse_digest("deadbeef").unwrap(), ("sha256", "deadbeef"));
        assert!(parse_digest("sha256:").is_err());
        assert!(parse_digest("").is_err());
    }

    #[test]
    fn materialized_digest_accessor() {
        let n = Materialized::Native {
            bin_path: "/x".into(),
            digest: "sha256:aa".into(),
        };
        assert_eq!(n.digest(), Some("sha256:aa"));
        let o = Materialized::Oci { image: "img".into() };
        assert_eq!(o.digest(), None);
    }
}
