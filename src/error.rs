//! Typed error layer for HTTP handlers.
//!
//! The original handlers return `Result<T, (StatusCode, String)>`.
//! That works but loses structure: every error reaches the wire as
//! an opaque string, so tracing spans, response shape, and metrics
//! can't tell a bad-request from a validation failure from a store
//! error.
//!
//! `ApiError` is the typed replacement. It implements
//! [`axum::response::IntoResponse`] so it can be returned directly,
//! and has a `From<(StatusCode, String)>` impl so existing tuple
//! errors keep working — handlers can migrate incrementally without
//! a big-bang rewrite.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("payload too large: {actual} > {max} bytes")]
    PayloadTooLarge { actual: usize, max: usize },

    #[error("validation failed on `{field}`: {reason}")]
    ValidationFailed { field: String, reason: String },

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limited; retry in {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),

    /// Generic 5xx fallback. Use sparingly — prefer a typed variant.
    /// The message is shown to the client; do NOT leak sensitive
    /// state through this — log details via `tracing` instead.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Wire shape for error responses. Stable across variants so clients
/// can pattern-match on `code` rather than parsing the message.
#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::PayloadTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
            }
            ApiError::ValidationFailed { .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, "validation_failed")
            }
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Store(_) | ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        // Log server-side errors at warn level so a flood is visible
        // without flipping log level. 4xx stays at debug — client
        // errors are routine and shouldn't drown out signal.
        if status.is_server_error() {
            tracing::warn!(?status, code, error = %self, "api error");
        } else {
            tracing::debug!(?status, code, error = %self, "api error");
        }
        let body = ErrorBody {
            code,
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

/// Conversion from the legacy tuple-shape so existing handlers can
/// be migrated to `ApiResult<T>` one at a time. Statuses outside the
/// typed variant set fall back to `Internal` (preserving the 5xx
/// behaviour callers expected).
impl From<(StatusCode, String)> for ApiError {
    fn from((status, msg): (StatusCode, String)) -> Self {
        match status {
            StatusCode::BAD_REQUEST => ApiError::BadRequest(msg),
            StatusCode::NOT_FOUND => ApiError::NotFound(msg),
            StatusCode::FORBIDDEN => ApiError::Forbidden(msg),
            StatusCode::UNPROCESSABLE_ENTITY => ApiError::ValidationFailed {
                field: "unknown".into(),
                reason: msg,
            },
            // Numeric match — StatusCode constants aren't const
            // pattern-matchable on stable.
            s if s == StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge {
                actual: 0,
                max: 0,
            },
            s if s == StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited {
                retry_after_secs: 0,
            },
            _ => ApiError::Internal(msg),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
