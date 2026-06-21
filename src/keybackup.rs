//! `ce key backup` / `ce key restore` — TTY-only encrypted custody of the Ed25519 node identity.
//!
//! Losing `<data_dir>/identity/node.key` (32 bytes) permanently loses this node's funds and name:
//! the chain has no recovery path. This module gives the operator two transcribable backups of that
//! seed and a guarded restore, and it deliberately keeps key material OFF the network:
//!
//!  - There is NO HTTP `/key/*` route and there never must be — a key-export endpoint would turn a
//!    same-host file-permission problem into a network-reachable exfiltration of identity for anyone
//!    holding the api.token. Backup/restore is a deliberate, interactive, same-host CLI action only.
//!  - The seed/mnemonic is printed to the TTY (or written to a file the operator names) and is
//!    NEVER logged through `tracing`/`println!` of secret bytes, never sent anywhere.
//!  - `restore` refuses to clobber an existing `node.key` without `--force`, showing the current
//!    node id first so the operator cannot silently destroy a funded running identity.
//!
//! Two backup forms:
//!  - Mnemonic: a CE-specific 33-word phrase (32 seed bytes, one word each, + a 1-word SHA256
//!    checksum) over a stable 256-word list. CE-specific (not BIP32/HD) — it only re-imports into
//!    `ce`; this is documented so nobody expects cross-wallet compatibility.
//!  - Encrypted keystore: HKDF-SHA256(passphrase, random salt) -> XChaCha20-Poly1305 over the 32
//!    bytes, written as JSON. The node_id is stored in clear (it is public) for verification.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};
use std::path::Path;

// 256 distinct CVC words: index = byte value. Generated, stable, CE-specific.
const MNEMONIC_WORDS: [&str; 256] = [
    "bab", "bac", "bad", "baf", "bag", "bah", "baj", "bak",
    "bal", "bam", "ban", "bap", "bar", "bas", "bat", "bav",
    "baw", "baz", "beb", "bec", "bed", "bef", "beg", "beh",
    "bej", "bek", "bel", "bem", "ben", "bep", "ber", "bes",
    "bet", "bev", "bew", "bez", "bib", "bic", "bid", "bif",
    "big", "bih", "bij", "bik", "bil", "bim", "bin", "bip",
    "bir", "bis", "bit", "biv", "biw", "biz", "bob", "boc",
    "bod", "bof", "bog", "boh", "boj", "bok", "bol", "bom",
    "bon", "bop", "bor", "bos", "bot", "bov", "bow", "boz",
    "bub", "buc", "bud", "buf", "bug", "buh", "buj", "buk",
    "bul", "bum", "bun", "bup", "bur", "bus", "but", "buv",
    "buw", "buz", "cab", "cac", "cad", "caf", "cag", "cah",
    "caj", "cak", "cal", "cam", "can", "cap", "car", "cas",
    "cat", "cav", "caw", "caz", "ceb", "cec", "ced", "cef",
    "ceg", "ceh", "cej", "cek", "cel", "cem", "cen", "cep",
    "cer", "ces", "cet", "cev", "cew", "cez", "cib", "cic",
    "cid", "cif", "cig", "cih", "cij", "cik", "cil", "cim",
    "cin", "cip", "cir", "cis", "cit", "civ", "ciw", "ciz",
    "cob", "coc", "cod", "cof", "cog", "coh", "coj", "cok",
    "col", "com", "con", "cop", "cor", "cos", "cot", "cov",
    "cow", "coz", "cub", "cuc", "cud", "cuf", "cug", "cuh",
    "cuj", "cuk", "cul", "cum", "cun", "cup", "cur", "cus",
    "cut", "cuv", "cuw", "cuz", "dab", "dac", "dad", "daf",
    "dag", "dah", "daj", "dak", "dal", "dam", "dan", "dap",
    "dar", "das", "dat", "dav", "daw", "daz", "deb", "dec",
    "ded", "def", "deg", "deh", "dej", "dek", "del", "dem",
    "den", "dep", "der", "des", "det", "dev", "dew", "dez",
    "dib", "dic", "did", "dif", "dig", "dih", "dij", "dik",
    "dil", "dim", "din", "dip", "dir", "dis", "dit", "div",
    "diw", "diz", "dob", "doc", "dod", "dof", "dog", "doh",
    "doj", "dok", "dol", "dom", "don", "dop", "dor", "dos",
    "dot", "dov", "dow", "doz", "dub", "duc", "dud", "duf",
];

/// One checksum byte over the 32 seed bytes (first byte of SHA256). Guards against transcription
/// errors on restore.
fn checksum_byte(seed: &[u8; 32]) -> u8 {
    Sha256::digest(seed)[0]
}

/// Encode a 32-byte seed as a 33-word CE mnemonic (32 seed words + 1 checksum word).
pub fn seed_to_mnemonic(seed: &[u8; 32]) -> String {
    let mut words: Vec<&str> = seed.iter().map(|&b| MNEMONIC_WORDS[b as usize]).collect();
    words.push(MNEMONIC_WORDS[checksum_byte(seed) as usize]);
    words.join(" ")
}

/// Decode a CE mnemonic back into the 32-byte seed, verifying the checksum word.
pub fn mnemonic_to_seed(phrase: &str) -> Result<[u8; 32]> {
    let idx = |w: &str| -> Result<u8> {
        MNEMONIC_WORDS
            .iter()
            .position(|&x| x == w)
            .map(|p| p as u8)
            .ok_or_else(|| anyhow!("unknown word '{w}' in mnemonic"))
    };
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 33 {
        bail!("mnemonic must be 33 words (got {})", words.len());
    }
    let mut seed = [0u8; 32];
    for (i, w) in words[..32].iter().enumerate() {
        seed[i] = idx(w)?;
    }
    let claimed = idx(words[32])?;
    if claimed != checksum_byte(&seed) {
        bail!("mnemonic checksum word does not match — re-check the words you typed");
    }
    Ok(seed)
}

/// Encrypted keystore JSON. `node_id` is stored in clear (public) so a restore can be verified
/// before the passphrase is even tried.
#[derive(Serialize, Deserialize)]
pub struct Keystore {
    pub version: u8,
    pub kdf: String,
    pub cipher: String,
    pub node_id: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// Derive a 32-byte symmetric key from a passphrase and salt via HKDF-SHA256.
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
    let mut key = [0u8; 32];
    // info binds the KDF to this purpose/version; `expand` only fails on absurd output lengths.
    let _ = hk.expand(b"ce-keystore-v1", &mut key);
    key
}

/// Encrypt a 32-byte seed into a keystore under `passphrase`.
pub fn encrypt_keystore(seed: &[u8; 32], node_id_hex: &str, passphrase: &str) -> Result<Keystore> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), seed.as_slice())
        .map_err(|_| anyhow!("keystore encryption failed"))?;
    Ok(Keystore {
        version: 1,
        kdf: "hkdf-sha256".into(),
        cipher: "xchacha20poly1305".into(),
        node_id: node_id_hex.to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Decrypt a keystore back into the 32-byte seed using `passphrase`.
pub fn decrypt_keystore(ks: &Keystore, passphrase: &str) -> Result<[u8; 32]> {
    let salt = hex::decode(&ks.salt_hex).map_err(|_| anyhow!("corrupt keystore salt"))?;
    let nonce = hex::decode(&ks.nonce_hex).map_err(|_| anyhow!("corrupt keystore nonce"))?;
    let ct = hex::decode(&ks.ciphertext_hex).map_err(|_| anyhow!("corrupt keystore ciphertext"))?;
    if nonce.len() != 24 {
        bail!("corrupt keystore nonce length");
    }
    let key = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| anyhow!("wrong passphrase or corrupt keystore"))?;
    pt.try_into().map_err(|_| anyhow!("decrypted seed is not 32 bytes"))
}

/// The scary, unmissable banner shown before any backup/restore that touches key material.
pub fn print_banner(action: &str) {
    eprintln!();
    eprintln!("  ============================================================");
    eprintln!("  !!  CE IDENTITY KEY {action}");
    eprintln!("  ============================================================");
    eprintln!("  This handles your node's SECRET key — the sole proof of");
    eprintln!("  ownership of this node's funds and name. Anyone who obtains");
    eprintln!("  it controls them. There is NO recovery if it is lost.");
    eprintln!();
    eprintln!("    - Run this only on a machine and terminal YOU trust.");
    eprintln!("    - Never paste the mnemonic or keystore into a chat or cloud.");
    eprintln!("    - Store the backup OFFLINE (paper / hardware), not next to");
    eprintln!("      the running node.");
    eprintln!("  ============================================================");
    eprintln!();
}

/// Require an interactive TTY for any secret-handling flow. Refuses to run in pipes/CI so secrets
/// never leak into scrollback, logs, or a redirected file by accident.
pub fn require_tty() -> Result<()> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        Ok(())
    } else {
        bail!(
            "ce key backup/restore is TTY-only — run it directly in an interactive terminal (not a \
             pipe, script, or CI) so secret key material is never captured. Refusing to continue."
        )
    }
}

/// Prompt on the TTY for a yes/no confirmation (default no).
pub fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{prompt} [y/N]: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Prompt on the TTY for a passphrase. Echo is not suppressed (no extra dependency); the banner
/// already warns to run on a trusted terminal. Returns the trimmed passphrase.
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    eprint!("{prompt}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let p = line.trim().to_string();
    if p.is_empty() {
        bail!("empty passphrase — aborting");
    }
    Ok(p)
}

/// Write the seed to `node.key` with chmod 600 (unix). Refuses to overwrite unless `force`.
pub fn write_node_key(identity_dir: &Path, seed: &[u8; 32], force: bool) -> Result<()> {
    let key_path = identity_dir.join("node.key");
    if key_path.exists() && !force {
        bail!(
            "{} already exists — refusing to overwrite the current identity without --force",
            key_path.display()
        );
    }
    std::fs::create_dir_all(identity_dir)?;
    std::fs::write(&key_path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_256_unique() {
        let set: std::collections::HashSet<_> = MNEMONIC_WORDS.iter().collect();
        assert_eq!(set.len(), 256, "mnemonic words must all be distinct");
    }

    #[test]
    fn mnemonic_roundtrip() {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let phrase = seed_to_mnemonic(&seed);
        assert_eq!(phrase.split_whitespace().count(), 33);
        assert_eq!(mnemonic_to_seed(&phrase).unwrap(), seed);
    }

    #[test]
    fn mnemonic_rejects_bad_checksum() {
        let seed = [9u8; 32];
        let phrase = seed_to_mnemonic(&seed);
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        // Corrupt the checksum word to a different valid word.
        words[32] = if words[32] == MNEMONIC_WORDS[0] { MNEMONIC_WORDS[1] } else { MNEMONIC_WORDS[0] };
        let corrupted = words.join(" ");
        assert!(mnemonic_to_seed(&corrupted).is_err());
    }

    #[test]
    fn mnemonic_rejects_wrong_length() {
        assert!(mnemonic_to_seed("bab bac bad").is_err());
    }

    #[test]
    fn keystore_roundtrip() {
        let seed = [42u8; 32];
        let ks = encrypt_keystore(&seed, "deadbeef", "correct horse battery staple").unwrap();
        assert_eq!(ks.node_id, "deadbeef");
        let back = decrypt_keystore(&ks, "correct horse battery staple").unwrap();
        assert_eq!(back, seed);
    }

    #[test]
    fn keystore_wrong_passphrase_fails() {
        let seed = [42u8; 32];
        let ks = encrypt_keystore(&seed, "deadbeef", "right").unwrap();
        assert!(decrypt_keystore(&ks, "wrong").is_err());
    }
}
