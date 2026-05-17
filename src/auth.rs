//! Bearer-token authentication for the bridge HTTP surface.
//!
//! Designed to close finding `dc633d7c` (CRITICAL — no auth at
//! all + 0.0.0.0 default bind) and `cc3c33d6` (HIGH — `X-Bridge-
//! From` header trivially spoofable) in a single change.
//!
//! ## Model
//!
//! - Operators stamp the server's env with `BRIDGE_AUTH_TOKENS`,
//!   a CSV of `<sha256-hex>:<identity>` pairs. Hashes — not raw
//!   tokens — live in the env, so a leaked process listing or
//!   accidental `printenv > pastebin` doesn't surface live creds.
//! - Peers stamp THEIR shim env with `BRIDGE_AUTH_TOKEN` (singular)
//!   = the raw bearer token. The shim's reqwest client injects
//!   `Authorization: Bearer <token>` as a default header. The
//!   server hashes the bearer at request time and looks the digest
//!   up against the registry.
//! - The looked-up identity is injected into the request via an
//!   axum `Extension<AuthIdentity>` so downstream handlers (audit
//!   log, memory ownership, /resume rate-limit) read it directly
//!   without re-parsing the header.
//!
//! ## Permissive mode
//!
//! If `BRIDGE_AUTH_TOKENS` is unset/empty AND `BRIDGE_AUTH_ENFORCE`
//! is not `1`, the middleware logs SEVERE once at boot and passes
//! every request through, injecting `AuthIdentity::Anonymous`.
//! This keeps existing deployments working until the operator
//! flips the enforce flag — hard-bricking is worse than the
//! known-vuln window, and the warn is loud enough to catch in any
//! sensible log review.
//!
//! ## Why not JWT or mTLS
//!
//! Bridge is a small, fully-trusted-perimeter coordination layer;
//! per-peer pre-shared tokens are sufficient and have a much
//! shorter onboarding loop than minting JWTs or provisioning a CA.
//! mTLS is the planned upgrade — tracked as a follow-up in the
//! finding `dc633d7c` reopen conditions.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The identity attached to a request once auth resolves. Inserted
/// as a request-extension by `require_auth`. Downstream handlers
/// pattern-match on this to decide audit-log actor, memory-key
/// ownership, /resume rate-limit bucket, etc.
#[derive(Clone, Debug)]
pub enum AuthIdentity {
    /// Resolved to a known peer via the bearer-token registry.
    Peer(String),
    /// No registry configured AND enforce mode off, OR (when
    /// permissive) no bearer present. Downstream code that requires
    /// a strong identity (ownership checks) should refuse this
    /// variant; observability paths (audit-log actor) substitute
    /// the literal string `"anonymous"`.
    Anonymous,
}

impl AuthIdentity {
    /// Compact display for audit_log + rate-limit bucket keys.
    pub fn as_actor(&self) -> &str {
        match self {
            AuthIdentity::Peer(s) => s.as_str(),
            AuthIdentity::Anonymous => "anonymous",
        }
    }

    /// `true` when the identity is real (resolved from a bearer).
    /// Memory-ownership and rate-limit code uses this to refuse
    /// `Anonymous` when running in enforce mode.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthIdentity::Peer(_))
    }
}

/// Shared, immutable registry of `sha256(bearer) -> identity`.
/// Wrapped in `Arc` so cloning per-request is cheap.
#[derive(Clone, Debug)]
pub struct AuthState {
    hashes: Arc<HashMap<[u8; 32], String>>,
    /// True when the server is configured to reject unauthenticated
    /// requests outright. Distinct from `hashes.is_empty()` so an
    /// operator can configure an empty list and still hard-block —
    /// useful for "drain everything, no peer connects until I add
    /// tokens" maintenance windows.
    enforce: bool,
    /// Identities allowed to bypass memory-key ownership checks.
    /// Loaded from `BRIDGE_MEMORY_ADMINS` env CSV. Read directly by
    /// the memory handlers, not by the middleware — kept here so a
    /// single AuthState carries all auth-related config.
    pub memory_admins: Arc<Vec<String>>,
}

impl AuthState {
    /// Load from env: `BRIDGE_AUTH_TOKENS` = CSV of `<hex>:<name>`,
    /// `BRIDGE_AUTH_ENFORCE` = `"1"` to hard-block on missing/bad
    /// bearers (otherwise permissive + warn).
    /// `BRIDGE_MEMORY_ADMINS` = CSV of identities allowed to write
    /// any memory key regardless of original owner.
    ///
    /// Malformed entries are logged at WARN and skipped — a
    /// single typo doesn't lock the whole server out.
    pub fn from_env() -> Self {
        let raw = std::env::var("BRIDGE_AUTH_TOKENS").unwrap_or_default();
        let mut hashes: HashMap<[u8; 32], String> = HashMap::new();
        for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let Some((hex, identity)) = part.split_once(':') else {
                tracing::warn!(entry = %part, "BRIDGE_AUTH_TOKENS entry missing ':' — skipping");
                continue;
            };
            let identity = identity.trim();
            if identity.is_empty() {
                tracing::warn!(entry = %part, "BRIDGE_AUTH_TOKENS entry has empty identity — skipping");
                continue;
            }
            let Some(bytes) = decode_hex_32(hex.trim()) else {
                tracing::warn!(
                    entry = %part,
                    "BRIDGE_AUTH_TOKENS entry hex side must be 64 hex chars (sha256) — skipping"
                );
                continue;
            };
            // Last write wins on duplicate hashes — log so operators
            // notice if two entries collide accidentally (or
            // deliberately, e.g. rotating).
            if let Some(prev) = hashes.insert(bytes, identity.to_string()) {
                tracing::warn!(
                    prev = %prev,
                    new = %identity,
                    "BRIDGE_AUTH_TOKENS duplicate hash — last entry wins"
                );
            }
        }
        let enforce = std::env::var("BRIDGE_AUTH_ENFORCE")
            .ok()
            .as_deref()
            == Some("1");
        let memory_admins: Vec<String> = std::env::var("BRIDGE_MEMORY_ADMINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if hashes.is_empty() && !enforce {
            tracing::warn!(
                "SEVERE: BRIDGE_AUTH_TOKENS is empty and enforce mode off — \
                 every request is treated as Anonymous. The bridge is \
                 NETWORK-OPEN for every mutation endpoint reachable on \
                 the bound address. See finding dc633d7c. Set \
                 BRIDGE_AUTH_TOKENS=<sha256-hex>:<identity>,... in env, \
                 then set BRIDGE_AUTH_ENFORCE=1 once peers are configured."
            );
        } else if hashes.is_empty() && enforce {
            tracing::warn!(
                "SEVERE: BRIDGE_AUTH_TOKENS empty but enforce mode ON — \
                 NO peer can authenticate. Server will 401 every request \
                 until tokens are configured."
            );
        } else {
            tracing::info!(
                tokens = hashes.len(),
                enforce,
                admins = memory_admins.len(),
                "auth registry loaded"
            );
        }
        Self {
            hashes: Arc::new(hashes),
            enforce,
            memory_admins: Arc::new(memory_admins),
        }
    }

    /// Look up a bearer's sha256 hash against the registry in
    /// constant time. Returns the bound identity on hit. Constant
    /// time = each entry is compared to the target with
    /// `ConstantTimeEq`, and we walk the full map regardless of
    /// match — prevents an early-exit timing oracle from leaking
    /// the prefix of a present token.
    fn lookup(&self, hash: &[u8; 32]) -> Option<String> {
        let mut hit: Option<String> = None;
        for (stored, identity) in self.hashes.iter() {
            let eq: bool = stored.ct_eq(hash).into();
            if eq && hit.is_none() {
                hit = Some(identity.clone());
            }
        }
        hit
    }

    /// True if this identity is on the memory-admin allowlist.
    /// Used by `memory_set`/`memory_delete` to bypass the
    /// owner-must-match check (closes `0919a7db` with an escape
    /// hatch for ops cleanup).
    pub fn is_memory_admin(&self, identity: &str) -> bool {
        self.memory_admins.iter().any(|a| a == identity)
    }
}

/// Decode a 64-hex-char string into the 32-byte hash. None on
/// any non-hex char or wrong length.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// sha256 of a bearer token. Used at request time to look the
/// bearer up against the registry's stored hashes — server never
/// sees the raw token after this byte buffer dies.
pub fn hash_bearer(bearer: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bearer.as_bytes());
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Axum middleware: extract the bearer, validate, inject identity.
///
/// Behaviour matrix:
///
/// | registry | enforce | bearer | result               |
/// |----------|---------|--------|----------------------|
/// | empty    | off     | any    | Anonymous, 200       |
/// | empty    | ON      | any    | 401                  |
/// | non-empty| any     | none   | 401                  |
/// | non-empty| any     | known  | Peer(identity), 200  |
/// | non-empty| any     | unknown| 401                  |
pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);

    let identity = match (state.hashes.is_empty(), state.enforce, bearer) {
        // Empty registry + permissive: every request is anon.
        (true, false, _) => AuthIdentity::Anonymous,
        // Empty registry + enforce: lock everything out.
        (true, true, _) => return unauthorized("server in enforce mode without tokens configured"),
        // Non-empty registry, no bearer at all.
        (false, _, None) => return unauthorized("missing Authorization: Bearer"),
        // Non-empty registry, bearer present — check it.
        (false, _, Some(tok)) if tok.is_empty() => return unauthorized("empty bearer token"),
        (false, _, Some(tok)) => {
            let h = hash_bearer(tok);
            match state.lookup(&h) {
                Some(name) => AuthIdentity::Peer(name),
                None => return unauthorized("bearer token not recognised"),
            }
        }
    };
    // Insert the resolved identity as an extension so downstream
    // handlers and helpers read it from the request without
    // re-parsing headers.
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn unauthorized(reason: &'static str) -> Response {
    let body = serde_json::json!({
        "code": "unauthorized",
        "message": reason,
    })
    .to_string();
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_to_env_entry(token: &str, identity: &str) -> String {
        let h = hash_bearer(token);
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        format!("{hex}:{identity}")
    }

    #[test]
    fn hash_bearer_is_deterministic_and_full_width() {
        let a = hash_bearer("hello");
        let b = hash_bearer("hello");
        let c = hash_bearer("hello world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn registry_loads_from_env_format() {
        // Sketch a 2-token registry by hand to exercise the parser
        // without going through std::env::set_var (avoid global
        // state pollution between tests).
        let entry_a = token_to_env_entry("token-a", "alice");
        let entry_b = token_to_env_entry("token-b", "bob");
        let csv = format!("{entry_a},{entry_b}");
        // Mimic the env-parse loop inline so we don't pollute the
        // process env across parallel tests. Same shape as
        // `AuthState::from_env`'s inner loop.
        let mut hashes: HashMap<[u8; 32], String> = HashMap::new();
        for part in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (hex, identity) = part.split_once(':').unwrap();
            hashes.insert(decode_hex_32(hex).unwrap(), identity.to_string());
        }
        let state = AuthState {
            hashes: Arc::new(hashes),
            enforce: true,
            memory_admins: Arc::new(Vec::new()),
        };
        assert_eq!(
            state.lookup(&hash_bearer("token-a")).as_deref(),
            Some("alice")
        );
        assert_eq!(
            state.lookup(&hash_bearer("token-b")).as_deref(),
            Some("bob")
        );
        assert_eq!(state.lookup(&hash_bearer("not-a-token")), None);
    }

    #[test]
    fn decode_hex_32_round_trip() {
        let input = [0x12u8, 0x34, 0xab, 0xcd]
            .iter()
            .cycle()
            .take(32)
            .copied()
            .collect::<Vec<u8>>();
        let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
        let decoded = decode_hex_32(&hex).expect("valid hex");
        assert_eq!(decoded[..], input[..]);
        // Wrong length and bad char both produce None.
        assert!(decode_hex_32("deadbeef").is_none());
        assert!(decode_hex_32(&"z".repeat(64)).is_none());
    }

    #[test]
    fn identity_actor_string_and_authenticated_flag() {
        let peer = AuthIdentity::Peer("alice".into());
        let anon = AuthIdentity::Anonymous;
        assert_eq!(peer.as_actor(), "alice");
        assert_eq!(anon.as_actor(), "anonymous");
        assert!(peer.is_authenticated());
        assert!(!anon.is_authenticated());
    }

    #[test]
    fn memory_admins_allowlist() {
        let state = AuthState {
            hashes: Arc::new(HashMap::new()),
            enforce: false,
            memory_admins: Arc::new(vec!["ops".into(), "rust-dev".into()]),
        };
        assert!(state.is_memory_admin("ops"));
        assert!(state.is_memory_admin("rust-dev"));
        assert!(!state.is_memory_admin("alice"));
        assert!(!state.is_memory_admin(""));
    }
}
