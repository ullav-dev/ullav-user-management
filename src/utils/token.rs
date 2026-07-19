//! Opaque high-entropy token helpers shared by any feature that mints a
//! random secret and stores only its hash (PATs, SSH key lookups don't need
//! this, but PAT/session/refresh-token creation does).
//!
//! `oauth2.rs` predates this module and keeps its own private copies of the
//! same two functions — left as-is to avoid an unrelated refactor of working
//! code; new features should use these instead of duplicating them again.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate `byte_len` random bytes, hex-encoded.
pub fn secure_hex_token(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// SHA-256 hex digest of `data` — used to store opaque tokens at rest without
/// keeping the raw secret (which would let anyone with DB access impersonate
/// every token holder).
pub fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}
