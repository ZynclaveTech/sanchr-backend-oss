use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::auth::auth_service_server::AuthService;
use sanchr_proto::auth::{
    AuthResponse, DeleteAccountRequest, DeleteAccountResponse, LoginRequest, LogoutRequest,
    LogoutResponse, RefreshTokenRequest, RegisterRequest, RequestChallengeRequest,
    RequestChallengeResponse, User, VerifyOtpRequest,
};

use crate::auth::handlers::{self, AuthResult};
use crate::middleware::auth;
use crate::server::AppState;

/// gRPC service implementation.
pub struct AuthServiceImpl {
    pub state: Arc<AppState>,
}

// ---------------------------------------------------------------------------
// Helper: convert AuthResult -> AuthResponse proto
// ---------------------------------------------------------------------------

fn auth_response_from_result(result: AuthResult) -> AuthResponse {
    let user = User {
        id: result.user.id.to_string(),
        phone_number: result.user.phone_number.clone(),
        display_name: result.user.display_name.clone(),
        email: result.user.email.clone().unwrap_or_default(),
        avatar_url: result.user.avatar_url.clone().unwrap_or_default(),
        status_text: result.user.status_text.clone().unwrap_or_default(),
        created_at: result.user.created_at.to_rfc3339(),
    };

    AuthResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        user: Some(user),
        device_id: result.device_id,
    }
}

// ---------------------------------------------------------------------------
// AuthService trait impl
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();

        let email = if req.email.is_empty() {
            None
        } else {
            Some(req.email.as_str())
        };

        let challenge_proof = req
            .challenge_proof
            .as_ref()
            .map(|p| (p.challenge_id.as_str(), p.solution.as_str()));

        let result = handlers::handle_register(
            &self.state,
            &req.phone_number,
            &req.display_name,
            &req.password,
            email,
            challenge_proof,
        )
        .await
        .map_err(Status::from)?;

        // Register returns empty tokens; the user must verify OTP first.
        // For existing users, handle_register returns None to prevent
        // user enumeration.
        let user = result.user.map(|u| User {
            id: u.id.to_string(),
            phone_number: u.phone_number,
            display_name: u.display_name,
            email: u.email.unwrap_or_default(),
            avatar_url: u.avatar_url.unwrap_or_default(),
            status_text: u.status_text.unwrap_or_default(),
            created_at: u.created_at.to_rfc3339(),
        });

        Ok(Response::new(AuthResponse {
            access_token: String::new(),
            refresh_token: String::new(),
            user,
            device_id: 0,
        }))
    }

    async fn verify_otp(
        &self,
        request: Request<VerifyOtpRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        let device = req.device.unwrap_or_default();

        let result = handlers::handle_verify_otp(
            &self.state,
            &req.phone_number,
            &req.otp_code,
            if device.device_name.is_empty() {
                None
            } else {
                Some(device.device_name.as_str())
            },
            if device.platform.is_empty() {
                "unknown"
            } else {
                &device.platform
            },
            if device.installation_id.is_empty() {
                None
            } else {
                Some(device.installation_id.as_str())
            },
            device.supports_delivery_ack,
            &req.registration_lock_pin,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(auth_response_from_result(result)))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        let device = req.device.unwrap_or_default();

        let result = handlers::handle_login(
            &self.state,
            &req.phone_number,
            &req.password,
            if device.device_name.is_empty() {
                None
            } else {
                Some(device.device_name.as_str())
            },
            if device.platform.is_empty() {
                "unknown"
            } else {
                &device.platform
            },
            if device.installation_id.is_empty() {
                None
            } else {
                Some(device.installation_id.as_str())
            },
            device.supports_delivery_ack,
            &req.registration_lock_pin,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(auth_response_from_result(result)))
    }

    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();

        let result = handlers::handle_refresh_token(&self.state, &req.refresh_token)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(auth_response_from_result(result)))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        // Require valid auth so the current access session can be revoked too.
        let _user = auth::authenticate(&self.state, &request).await?;

        let access_token_jti = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|token| self.state.jwt.validate_token(token).ok())
            .map(|claims| claims.jti);

        let req = request.into_inner();

        handlers::handle_logout(&self.state, &req.refresh_token, access_token_jti.as_deref())
            .await
            .map_err(Status::from)?;

        Ok(Response::new(LogoutResponse {}))
    }

    async fn delete_account(
        &self,
        request: Request<DeleteAccountRequest>,
    ) -> Result<Response<DeleteAccountResponse>, Status> {
        // Authentication is enforced via the Bearer token; the request body
        // is intentionally empty for now (a confirmation field is reserved
        // in the proto for future use).
        let user = auth::authenticate_metadata(&self.state, request.metadata()).await?;

        handlers::handle_delete_account(&self.state, user.user_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(DeleteAccountResponse { success: true }))
    }

    async fn request_challenge(
        &self,
        request: Request<RequestChallengeRequest>,
    ) -> Result<Response<RequestChallengeResponse>, Status> {
        let req = request.into_inner();

        let provider = self
            .state
            .challenge_provider
            .as_ref()
            .ok_or_else(|| Status::unavailable("challenge system is not enabled"))?;

        let challenge = provider
            .issue(&req.phone_number)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(RequestChallengeResponse {
            challenge_type: challenge.challenge_type,
            challenge_id: challenge.challenge_id,
            challenge_data: challenge.challenge_data,
            expires_at: challenge.expires_at,
        }))
    }
}
