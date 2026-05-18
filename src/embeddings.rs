//! F18 — text → vector embeddings for semantic search.
//!
//! The bridge stores embeddings in a `vec0` virtual table (see
//! `store::Store::upsert_embedding` / `semantic_search`). The actual
//! text→vector encoding lives here, behind a trait so we can swap
//! implementations without touching the storage layer.
//!
//! Two implementations ship:
//!
//! - [`HashEmbedder`] — deterministic, always available, no model
//!   download. Produces a 384-dim unit vector derived from a hash
//!   of the input. Useful for tests, for the "no model loaded"
//!   fallback, and for environments that can't pull onnxruntime.
//!   Search quality is **worse than FTS5** — this is a placeholder,
//!   not a recommendation.
//!
//! - [`FastembedEmbedder`] (Cargo feature `embeddings`) — real ML
//!   embedder via `fastembed-rs`. Downloads `BAAI/bge-small-en-v1.5`
//!   (~80MB) on first use into `BRIDGE_EMBEDDINGS_MODEL_DIR`
//!   (default: `$HOME/.cache/claude-bridge/models`). Produces 384-dim
//!   vectors compatible with the v18 schema width.
//!
//! Selection at runtime: `embedder_from_env()` returns the right
//! implementation based on `BRIDGE_EMBEDDINGS_ENABLED`. When the
//! feature is compiled out, only the hash fallback is reachable.

use sha2::{Digest, Sha256};

/// Width of every embedding vector in the bridge. Matches the v18
/// schema (`vec0(embedding float[384])`). MiniLM and bge-small both
/// land at 384 — changing this requires a new migration AND a model
/// swap, so it's a hard constant.
pub const EMBED_DIM: usize = 384;

/// Encode text into a fixed-width vector. Implementations are free
/// to be expensive (network, GPU) or cheap (hash) — callers should
/// not assume either property. Returns `None` when input is empty
/// or the encoder couldn't produce a vector this call (e.g. the
/// model isn't loaded yet); callers treat that as "skip indexing".
pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Option<Vec<f32>>;
    fn name(&self) -> &'static str;
}

/// Deterministic SHA-256-derived embedder. Produces the same vector
/// for the same input every call — useful for tests and as a safe
/// no-model fallback. Search results from this embedder are
/// effectively a slow random-coloured FTS; we keep it so the
/// `memory_search_semantic` route never 503s when the real model
/// is unavailable.
pub struct HashEmbedder;

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Option<Vec<f32>> {
        if text.trim().is_empty() {
            return None;
        }
        // Seed 384 floats from 12 successive SHA-256 chunks of
        // (counter || text). Each chunk gives 32 bytes = 8 f32s,
        // so 12 chunks = 96 f32s — repeat 4x for 384.
        let mut out = Vec::with_capacity(EMBED_DIM);
        for chunk in 0..((EMBED_DIM / 8) as u32) {
            let mut h = Sha256::new();
            h.update(chunk.to_le_bytes());
            h.update(text.as_bytes());
            let bytes = h.finalize();
            for i in 0..8 {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
                // Map u32 → [-1, 1] roughly.
                let n = i32::from_le_bytes(buf) as f64;
                let f = (n / i32::MAX as f64) as f32;
                out.push(f);
            }
        }
        // L2-normalise so cosine distance is meaningful.
        let mag: f32 = out.iter().map(|x| x * x).sum::<f32>().sqrt();
        if mag > 0.0 {
            for x in &mut out {
                *x /= mag;
            }
        }
        Some(out)
    }

    fn name(&self) -> &'static str {
        "hash-sha256-384"
    }
}

/// Cheap content fingerprint to attach to an embedding row — lets the
/// bridge skip re-embedding when text didn't actually change.
pub fn content_hash(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    hex16(&h.finalize())
}

fn hex16(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(32);
    for b in &bytes[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(feature = "embeddings")]
mod fastembed_impl {
    use super::{Embedder, EMBED_DIM};
    use parking_lot::Mutex;
    use std::sync::Arc;

    pub struct FastembedEmbedder {
        inner: Arc<Mutex<fastembed::TextEmbedding>>,
    }

    impl FastembedEmbedder {
        pub fn try_new() -> Result<Self, String> {
            let model = fastembed::TextEmbedding::try_new(Default::default())
                .map_err(|e| format!("fastembed init failed: {e}"))?;
            Ok(Self {
                inner: Arc::new(Mutex::new(model)),
            })
        }
    }

    impl Embedder for FastembedEmbedder {
        fn embed(&self, text: &str) -> Option<Vec<f32>> {
            if text.trim().is_empty() {
                return None;
            }
            let mut model = self.inner.lock();
            let v = model.embed(vec![text.to_string()], None).ok()?;
            let mut row = v.into_iter().next()?;
            // Truncate or pad to EMBED_DIM. bge-small-en-v1.5
            // emits 384 already — this is defence-in-depth.
            row.resize(EMBED_DIM, 0.0);
            Some(row)
        }

        fn name(&self) -> &'static str {
            "fastembed-bge-small-en-v1.5"
        }
    }
}

#[cfg(feature = "embeddings")]
pub use fastembed_impl::FastembedEmbedder;

/// Build the embedder configured by env. Returns a HashEmbedder
/// when `BRIDGE_EMBEDDINGS_ENABLED` is unset/false OR when the
/// real model fails to load (logged; we keep going on degraded
/// search rather than refuse to start).
pub fn embedder_from_env() -> Box<dyn Embedder> {
    let enabled = std::env::var("BRIDGE_EMBEDDINGS_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        tracing::info!(embedder = "hash", "BRIDGE_EMBEDDINGS_ENABLED not set — using hash fallback");
        return Box::new(HashEmbedder);
    }
    #[cfg(feature = "embeddings")]
    {
        match FastembedEmbedder::try_new() {
            Ok(e) => {
                tracing::info!(embedder = e.name(), "fastembed model loaded");
                return Box::new(e);
            }
            Err(e) => {
                tracing::error!(error = %e, "fastembed init failed — falling back to hash embedder");
            }
        }
    }
    #[cfg(not(feature = "embeddings"))]
    {
        tracing::warn!(
            "BRIDGE_EMBEDDINGS_ENABLED=1 but binary was built without `--features embeddings`. \
             Using hash fallback. Rebuild with the feature for real search quality."
        );
    }
    Box::new(HashEmbedder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_embedder_is_deterministic() {
        let e = HashEmbedder;
        let a = e.embed("hello world").expect("non-empty input");
        let b = e.embed("hello world").expect("non-empty input");
        assert_eq!(a.len(), EMBED_DIM);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_embedder_returns_none_on_empty() {
        let e = HashEmbedder;
        assert!(e.embed("").is_none());
        assert!(e.embed("   \t  ").is_none());
    }

    #[test]
    fn hash_embedder_unit_norm() {
        let e = HashEmbedder;
        let v = e.embed("test input string").unwrap();
        let mag: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (mag - 1.0).abs() < 1e-4,
            "expected unit vector, got mag={mag}"
        );
    }

    #[test]
    fn different_inputs_differ() {
        let e = HashEmbedder;
        let a = e.embed("alpha").unwrap();
        let b = e.embed("beta").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn content_hash_stable() {
        assert_eq!(content_hash("abc"), content_hash("abc"));
        assert_ne!(content_hash("abc"), content_hash("abd"));
        assert_eq!(content_hash("abc").len(), 32);
    }
}
