use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::settings::settings_service_server::SettingsService;
use sanchr_proto::settings::{
    GetSettingsRequest, GetStorageUsageRequest, ProfileResponse, SetRegistrationLockRequest,
    SetRegistrationLockResponse, StorageUsageResponse, ToggleSanchrModeRequest,
    UpdateProfileRequest, UpdateSettingsRequest, UserSettings,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct SettingsServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl SettingsService for SettingsServiceImpl {
    async fn get_settings(
        &self,
        request: Request<GetSettingsRequest>,
    ) -> Result<Response<UserSettings>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let settings = handlers::handle_get_settings(&self.state, user.user_id).await?;

        Ok(Response::new(settings))
    }

    async fn update_settings(
        &self,
        request: Request<UpdateSettingsRequest>,
    ) -> Result<Response<UserSettings>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let settings = req
            .settings
            .ok_or_else(|| Status::invalid_argument("settings field is required"))?;

        let updated =
            handlers::handle_update_settings(&self.state, user.user_id, &settings).await?;

        Ok(Response::new(updated))
    }

    async fn update_profile(
        &self,
        request: Request<UpdateProfileRequest>,
    ) -> Result<Response<ProfileResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let profile = handlers::handle_update_profile(
            &self.state,
            user.user_id,
            &req.display_name,
            &req.avatar_url,
            &req.status_text,
            &req.profile_key,
            &req.encrypted_display_name,
            &req.encrypted_bio,
            &req.encrypted_avatar_url,
        )
        .await?;

        Ok(Response::new(profile))
    }

    async fn toggle_sanchr_mode(
        &self,
        request: Request<ToggleSanchrModeRequest>,
    ) -> Result<Response<UserSettings>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let settings =
            handlers::handle_toggle_sanchr_mode(&self.state, user.user_id, req.enabled).await?;

        Ok(Response::new(settings))
    }

    async fn get_storage_usage(
        &self,
        request: Request<GetStorageUsageRequest>,
    ) -> Result<Response<StorageUsageResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let usage = handlers::handle_get_storage_usage(&self.state, user.user_id).await?;

        Ok(Response::new(usage))
    }

    async fn set_registration_lock(
        &self,
        request: Request<SetRegistrationLockRequest>,
    ) -> Result<Response<SetRegistrationLockResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let resp = handlers::handle_set_registration_lock(
            &self.state,
            user.user_id,
            req.enabled,
            &req.pin,
        )
        .await?;

        Ok(Response::new(resp))
    }
}
