use std::sync::Arc;

use tonic::metadata::MetadataMap;
use tonic::{Request, Status};
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::redis::sessions;
use sanchr_server_crypto::jwt::JwtError;

use crate::server::AppState;

/// Represents an authenticated user extracted from a valid JWT + active session.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub device_id: i32,
}

/// Authenticate an incoming gRPC request by validating the JWT bearer token
/// and confirming the session exists in Redis.
///
/// Expects the `authorization` metadata header in the form `Bearer <token>`.
pub async fn authenticate<T>(
    state: &Arc<AppState>,
    request: &Request<T>,
) -> Result<AuthenticatedUser, Status> {
    authenticate_metadata(state, request.metadata()).await
}

/// Authenticate using only the metadata map. Useful for streaming RPCs where
/// the `Request<Streaming<T>>` is not `Send`.
pub async fn authenticate_metadata(
    state: &Arc<AppState>,
    metadata: &MetadataMap,
) -> Result<AuthenticatedUser, Status> {
    // --- Extract bearer token from metadata ---
    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("missing or invalid authorization header"))?;

    // --- Validate JWT ---
    let claims = state.jwt.validate_token(token).map_err(|e| match e {
        JwtError::Expired => Status::unauthenticated("token expired"),
        JwtError::ValidationError(msg) => {
            Status::unauthenticated(format!("invalid token: {}", msg))
        }
        JwtError::CreationError(msg) => internal_status("jwt error", msg),
    })?;

    // --- Check session exists in Redis ---
    let session = sessions::validate_session(&state.redis, &claims.jti)
        .await
        .map_err(|e| internal_status("session check failed", e))?
        .ok_or_else(|| Status::unauthenticated("session expired or revoked"))?;

    let (user_id, device_id) = session;

    Ok(AuthenticatedUser { user_id, device_id })
}
