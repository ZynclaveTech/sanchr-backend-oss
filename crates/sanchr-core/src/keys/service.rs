use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use sanchr_proto::keys::key_service_server::KeyService;
use sanchr_proto::keys::{
    GetPreKeyBundleRequest, GetPreKeyCountRequest, GetUserDevicesRequest, GetUserDevicesResponse,
    KeyBundle, PreKeyBundleResponse, PreKeyCountResponse, RemoveDeviceRequest,
    RemoveDeviceResponse, UploadKeyBundleResponse, UploadOneTimePreKeysRequest,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct KeyServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl KeyService for KeyServiceImpl {
    async fn upload_key_bundle(
        &self,
        request: Request<KeyBundle>,
    ) -> Result<Response<UploadKeyBundleResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let bundle = request.into_inner();

        let signed_pre_key = bundle
            .signed_pre_key
            .ok_or_else(|| Status::invalid_argument("missing signed_pre_key"))?;
        let kyber_pre_key = bundle
            .kyber_pre_key
            .ok_or_else(|| Status::invalid_argument("missing kyber_pre_key"))?;

        if bundle.device_id != 0 && bundle.device_id != user.device_id {
            return Err(Status::invalid_argument(
                "device_id does not match authenticated device",
            ));
        }

        handlers::handle_upload_key_bundle(
            &self.state,
            handlers::UploadKeyBundleParams {
                user_id: user.user_id,
                device_id: user.device_id,
                registration_id: bundle.registration_id,
                identity_public_key: bundle.identity_public_key,
                signed_pre_key,
                kyber_pre_key,
                one_time_pre_keys: bundle.one_time_pre_keys,
            },
        )
        .await?;

        Ok(Response::new(UploadKeyBundleResponse {}))
    }

    async fn get_pre_key_bundle(
        &self,
        request: Request<GetPreKeyBundleRequest>,
    ) -> Result<Response<PreKeyBundleResponse>, Status> {
        // Authenticate the caller (any authenticated user can fetch bundles)
        auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let target_user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let response = handlers::handle_get_pre_key_bundle(
            &self.state,
            &self.state.stream_mgr,
            target_user_id,
            req.device_id,
        )
        .await?;

        Ok(Response::new(response))
    }

    async fn upload_one_time_pre_keys(
        &self,
        request: Request<UploadOneTimePreKeysRequest>,
    ) -> Result<Response<PreKeyCountResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let count = handlers::handle_upload_one_time_pre_keys(
            &self.state,
            user.user_id,
            user.device_id,
            req.keys,
        )
        .await?;

        Ok(Response::new(PreKeyCountResponse { count }))
    }

    async fn get_pre_key_count(
        &self,
        request: Request<GetPreKeyCountRequest>,
    ) -> Result<Response<PreKeyCountResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let count =
            handlers::handle_get_pre_key_count(&self.state, user.user_id, user.device_id).await?;

        Ok(Response::new(PreKeyCountResponse { count }))
    }

    async fn get_user_devices(
        &self,
        request: Request<GetUserDevicesRequest>,
    ) -> Result<Response<GetUserDevicesResponse>, Status> {
        auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let target_user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let devices = handlers::handle_get_user_devices(&self.state, target_user_id).await?;

        Ok(Response::new(GetUserDevicesResponse { devices }))
    }

    async fn remove_device(
        &self,
        request: Request<RemoveDeviceRequest>,
    ) -> Result<Response<RemoveDeviceResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let success = handlers::handle_remove_device(
            &self.state,
            user.user_id,
            user.device_id,
            req.device_id,
        )
        .await?;

        Ok(Response::new(RemoveDeviceResponse { success }))
    }
}
