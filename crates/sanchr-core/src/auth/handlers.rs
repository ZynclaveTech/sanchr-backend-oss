use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;

use sanchr_common::errors::AppError;
use sanchr_db::postgres::{devices, pending_registrations, refresh_tokens, settings, users};
use sanchr_db::redis::{rate_limit, sessions};
use sanchr_server_crypto::otp;
use sanchr_server_crypto::password::{self, PasswordHasherConfig};

use crate::server::AppState;

// ---------------------------------------------------------------------------
// Result types returned by handlers
// ---------------------------------------------------------------------------

pub struct RegisterResult {
    /// Registration now stages a pending registration. The user row is
    /// materialized only after OTP verification succeeds.
    pub user: Option<users::UserRow>,
}

pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: String,
    pub user: users::UserRow,
    pub device_id: i32,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_phone(phone: &str) -> Result<(), AppError> {
    if !phone.starts_with('+') || phone.len() < 8 {
        return Err(AppError::InvalidInput(
            "phone must start with '+' and be at least 8 characters".into(),
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::InvalidInput(
            "display_name must be between 1 and 100 characters".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::InvalidInput(
            "password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of a UTF-8 string and return the raw bytes.
/// Used to store and look up refresh tokens without persisting the raw value.
fn sha256_bytes(input: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

fn password_hasher_config(state: &AppState) -> PasswordHasherConfig {
    PasswordHasherConfig {
        memory_cost: state.config.auth.argon2_memory,
        iterations: state.config.auth.argon2_iterations,
        parallelism: state.config.auth.argon2_parallelism,
    }
}

fn generate_otp_code(state: &AppState, phone: &str) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    otp::generate_otp(
        &state.config.auth.otp_secret,
        phone,
        now,
        state.config.auth.otp_ttl,
    )
    .map_err(|e| AppError::Internal(e.to_string()))
}

/// OSS integration seam for OTP delivery.
///
/// This function intentionally does not send anything. Public users are
/// expected to replace this with their own SMS, voice, email, or other
/// out-of-band delivery integration.
fn send_otp_dummy(phone: &str, otp_code: &str) {
    tracing::info!(
        phone = phone,
        otp_len = otp_code.len(),
        "OTP generated; replace send_otp_dummy with your own delivery provider"
    );
}

fn issue_otp(state: &AppState, phone: &str, existing_user: bool) -> Result<(), AppError> {
    let otp_code = generate_otp_code(state, phone)?;

    if state.config.auth.dev_mode {
        let message = if existing_user {
            "[DEV] OTP generated for existing user"
        } else {
            "[DEV] OTP generated"
        };
        tracing::info!(phone = phone, otp = %otp_code, "{message}");
    } else {
        send_otp_dummy(phone, &otp_code);
    }

    Ok(())
}

async fn resolve_user_after_otp(
    state: &Arc<AppState>,
    phone: &str,
) -> Result<users::UserRow, AppError> {
    if let Some(existing_user) = users::find_by_phone(&state.pg_pool, phone).await? {
        return Ok(existing_user);
    }

    let pending = pending_registrations::take_pending_registration(&state.pg_pool, phone)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let created_user = users::create_user(
        &state.pg_pool,
        &pending.phone_number,
        &pending.display_name,
        pending.email.as_deref(),
        &pending.password_hash,
    )
    .await?;

    ensure_user_settings_row(state, created_user.id).await?;
    Ok(created_user)
}

fn verify_otp_code(state: &AppState, phone: &str, otp_code: &str) -> Result<(), AppError> {
    if state.config.auth.dev_mode && otp_code == "999999" {
        tracing::info!(phone = phone, "[DEV] Static OTP accepted");
        return Ok(());
    }

    let now = Utc::now().timestamp();
    otp::verify_otp(
        &state.config.auth.otp_secret,
        phone,
        otp_code,
        now,
        state.config.auth.otp_ttl,
    )
    .map_err(|_| AppError::Unauthorized("invalid or expired OTP".into()))
}

/// Create access + refresh tokens and persist the session.
///
/// - Access session → Redis (short-lived TTL, used by auth middleware)
/// - Refresh token hash → Postgres `refresh_tokens` table (explicit
///   rotation/revocation, sole source of truth for token refresh)
async fn create_tokens_and_session(
    state: &AppState,
    user_id: &Uuid,
    device_id: i32,
) -> Result<(String, String), AppError> {
    let (access_token, jti) = state
        .jwt
        .create_access_token(
            user_id,
            device_id,
            state.config.auth.access_token_ttl as i64,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_hash = sha256_bytes(&refresh_token);

    // Persist refresh token hash in Postgres (authoritative store).
    refresh_tokens::create_refresh_token(&state.pg_pool, *user_id, device_id, &refresh_hash)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Persist access session in Redis (short-lived, checked by auth middleware).
    sessions::create_session(
        &state.redis,
        &jti,
        user_id,
        device_id,
        state.config.auth.access_token_ttl as i64,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((access_token, refresh_token))
}

/// Verify the registration-lock PIN when the feature is enabled for a user.
///
/// If registration lock is not enabled the check is a no-op. When enabled, the
/// caller must supply the correct PIN; an empty or wrong PIN is rejected.
async fn check_registration_lock(
    state: &AppState,
    user_id: Uuid,
    registration_lock_pin: &str,
) -> Result<(), AppError> {
    let row = settings::get_settings(&state.pg_pool, user_id)
        .await
        .map_err(|e| AppError::Internal(format!("failed to load settings: {e}")))?;

    if !row.registration_lock_enabled.unwrap_or(false) {
        return Ok(());
    }

    let stored_hash = row
        .registration_lock_pin_hash
        .as_deref()
        .ok_or_else(|| AppError::Internal("registration lock enabled but no PIN hash".into()))?;

    if registration_lock_pin.is_empty() {
        return Err(AppError::Unauthorized(
            "registration_lock_pin_required".into(),
        ));
    }

    password::verify_password(registration_lock_pin, stored_hash)
        .map_err(|_| AppError::Unauthorized("invalid registration lock PIN".into()))?;

    Ok(())
}

async fn ensure_user_settings_row(state: &Arc<AppState>, user_id: Uuid) -> Result<(), AppError> {
    sqlx::query("INSERT INTO user_settings (user_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(user_id)
        .execute(&state.pg_pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn handle_register(
    state: &Arc<AppState>,
    phone: &str,
    name: &str,
    password_raw: &str,
    email: Option<&str>,
) -> Result<RegisterResult, AppError> {
    // --- Validate inputs ---
    validate_phone(phone)?;
    validate_name(name)?;
    validate_password(password_raw)?;

    // --- Rate limit ---
    let rate_key = format!("rate:register:{}", phone);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 5, 900).await?;

    // --- Check phone not already registered ---
    // Generate an OTP for an existing verified user so they can still log in via
    // the OTP flow, without revealing whether the phone already has an account.
    if users::find_by_phone(&state.pg_pool, phone).await?.is_some() {
        tracing::info!(
            phone = phone,
            "registration attempted for existing phone, generating OTP for login"
        );
        issue_otp(state, phone, true)?;

        return Ok(RegisterResult { user: None });
    }

    // --- Hash password ---
    let pw_config = password_hasher_config(state);
    let password_hash = password::hash_password(password_raw, &pw_config)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let expires_at = Utc::now() + Duration::seconds(state.config.auth.otp_ttl as i64);
    pending_registrations::upsert_pending_registration(
        &state.pg_pool,
        phone,
        name,
        email,
        &password_hash,
        expires_at,
    )
    .await?;

    issue_otp(state, phone, false)?;

    crate::observability::metrics::record_auth_event("register");

    Ok(RegisterResult { user: None })
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_verify_otp(
    state: &Arc<AppState>,
    phone: &str,
    otp_code: &str,
    device_name: Option<&str>,
    platform: &str,
    installation_id: Option<&str>,
    supports_delivery_ack: bool,
    registration_lock_pin: &str,
) -> Result<AuthResult, AppError> {
    // --- Rate limit ---
    let rate_key = format!("rate:verify_otp:{}", phone);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 5, 900).await?;

    // --- Verify OTP ---
    verify_otp_code(state, phone, otp_code)?;

    let user = resolve_user_after_otp(state, phone).await?;

    ensure_user_settings_row(state, user.id).await?;

    // --- Registration lock check ---
    check_registration_lock(state, user.id, registration_lock_pin).await?;

    // --- Register device ---
    let device = devices::upsert_device(
        &state.pg_pool,
        &user.id,
        device_name,
        platform,
        installation_id,
        supports_delivery_ack,
    )
    .await?;

    // --- Create tokens ---
    let (access_token, refresh_token) =
        create_tokens_and_session(state, &user.id, device.device_id).await?;

    crate::observability::metrics::record_auth_event("verify_otp");

    Ok(AuthResult {
        access_token,
        refresh_token,
        user,
        device_id: device.device_id,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_login(
    state: &Arc<AppState>,
    phone: &str,
    password_raw: &str,
    device_name: Option<&str>,
    platform: &str,
    installation_id: Option<&str>,
    supports_delivery_ack: bool,
    registration_lock_pin: &str,
) -> Result<AuthResult, AppError> {
    // --- Rate limit ---
    let rate_key = format!("rate:login:{}", phone);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 5, 900).await?;

    // --- Find user ---
    let user = users::find_by_phone(&state.pg_pool, phone)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".into()))?;

    // --- Verify password ---
    password::verify_password(password_raw, &user.password_hash)
        .map_err(|_| AppError::Unauthorized("invalid credentials".into()))?;

    // --- Registration lock check ---
    check_registration_lock(state, user.id, registration_lock_pin).await?;

    // --- Register device ---
    let device = devices::upsert_device(
        &state.pg_pool,
        &user.id,
        device_name,
        platform,
        installation_id,
        supports_delivery_ack,
    )
    .await?;

    // --- Create tokens ---
    let (access_token, refresh_token) =
        create_tokens_and_session(state, &user.id, device.device_id).await?;

    crate::observability::metrics::record_auth_event("login");

    Ok(AuthResult {
        access_token,
        refresh_token,
        user,
        device_id: device.device_id,
    })
}

pub async fn handle_refresh_token(
    state: &Arc<AppState>,
    refresh_token: &str,
) -> Result<AuthResult, AppError> {
    // --- Hash the incoming token and validate against Postgres ---
    let token_hash = sha256_bytes(refresh_token);
    let row = refresh_tokens::validate_refresh_token(&state.pg_pool, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Unauthorized("invalid or expired refresh token".into()))?;

    let user_id = row.user_id;
    let device_id = row.device_id;

    // --- Generate new tokens ---
    let (access_token, jti) = state
        .jwt
        .create_access_token(
            &user_id,
            device_id,
            state.config.auth.access_token_ttl as i64,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let new_refresh_token = Uuid::new_v4().to_string();
    let new_hash = sha256_bytes(&new_refresh_token);

    // --- Atomically rotate: delete old, insert new in Postgres ---
    refresh_tokens::rotate_refresh_token(
        &state.pg_pool,
        &token_hash,
        &new_hash,
        user_id,
        device_id,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // --- Persist new access session in Redis ---
    sessions::create_session(
        &state.redis,
        &jti,
        &user_id,
        device_id,
        state.config.auth.access_token_ttl as i64,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // --- Fetch user row ---
    let user = users::find_by_id(&state.pg_pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    crate::observability::metrics::record_auth_event("refresh_token");

    Ok(AuthResult {
        access_token,
        refresh_token: new_refresh_token,
        user,
        device_id,
    })
}

pub async fn handle_logout(
    state: &Arc<AppState>,
    refresh_token: &str,
    access_token_jti: Option<&str>,
) -> Result<(), AppError> {
    // Best-effort revoke access session first when caller is authenticated.
    if let Some(jti) = access_token_jti {
        sessions::revoke_session(&state.redis, jti)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // Soft-revoke the refresh token in Postgres (authoritative store).
    let token_hash = sha256_bytes(refresh_token);
    refresh_tokens::revoke_refresh_token(&state.pg_pool, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    crate::observability::metrics::record_auth_event("logout");

    Ok(())
}

/// Hard-delete the authenticated user's account.
///
/// Order of operations:
///   1. Look up the user row to capture the phone number for
///      `pending_registrations` cleanup (the row is gone after step 3).
///   2. Revoke every Redis session/refresh token for the user so any
///      in-flight access tokens are immediately rejected by the auth
///      middleware. This is best-effort and runs before the DB delete so
///      that, in the worst case, the user is still gone from Postgres even
///      if Redis is briefly unavailable.
///   3. Delete the `users` row. FK CASCADE handles user_devices,
///      user_settings, identity/signed/one_time/kyber pre-keys, contacts
///      (both `user_id` and `contact_user_id` sides), conversation
///      participants, media_objects, and backup_objects.
///   4. Drop any leftover `pending_registrations` row keyed by the same
///      phone number so the user can immediately re-register.
pub async fn handle_delete_account(state: &Arc<AppState>, user_id: Uuid) -> Result<(), AppError> {
    // 1. Capture phone number before the row is deleted.
    let user = users::find_by_id(&state.pg_pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;
    let phone = user.phone_number.clone();

    // 2. Revoke all Redis sessions/refresh tokens for the user.
    sessions::revoke_all_sessions_for_user(&state.redis, &user_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // 3. Delete the user (cascades via FKs).
    users::delete_user(&state.pg_pool, &user_id).await?;

    // 4. Clean up any pending_registrations rows for this phone.
    pending_registrations::delete_by_phone(&state.pg_pool, &phone).await?;

    tracing::info!(user_id = %user_id, "account deleted");
    crate::observability::metrics::record_auth_event("delete_account");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_phone_valid() {
        assert!(validate_phone("+15550001234").is_ok());
        assert!(validate_phone("+4412345678").is_ok());
    }

    #[test]
    fn validate_phone_missing_plus() {
        assert!(validate_phone("15550001234").is_err());
    }

    #[test]
    fn validate_phone_too_short() {
        assert!(validate_phone("+123").is_err());
    }

    #[test]
    fn validate_phone_empty() {
        assert!(validate_phone("").is_err());
    }

    #[test]
    fn validate_name_valid() {
        assert!(validate_name("Alice").is_ok());
        assert!(validate_name("A").is_ok());
    }

    #[test]
    fn validate_name_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn validate_name_too_long() {
        let long = "a".repeat(101);
        assert!(validate_name(&long).is_err());
    }

    #[test]
    fn validate_name_exactly_100() {
        let name = "a".repeat(100);
        assert!(validate_name(&name).is_ok());
    }

    #[test]
    fn validate_password_valid() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("12345678").is_ok());
    }

    #[test]
    fn validate_password_too_short() {
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("").is_err());
    }

    #[test]
    fn validate_password_exactly_8() {
        assert!(validate_password("12345678").is_ok());
    }
}
