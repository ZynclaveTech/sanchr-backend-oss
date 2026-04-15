use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::media::media_service_server::MediaService;
use sanchr_proto::media::{
    ConfirmUploadRequest, ConfirmUploadResponse, GetDownloadUrlRequest, GetUploadUrlRequest,
    PresignedUrlResponse,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct MediaServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl MediaService for MediaServiceImpl {
    async fn get_upload_url(
        &self,
        request: Request<GetUploadUrlRequest>,
    ) -> Result<Response<PresignedUrlResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response = handlers::handle_get_upload_url(
            &self.state,
            user.user_id,
            req.file_size,
            &req.content_type,
            &req.sha256_hash,
            req.purpose(),
        )
        .await?;

        Ok(Response::new(response))
    }

    async fn get_download_url(
        &self,
        request: Request<GetDownloadUrlRequest>,
    ) -> Result<Response<PresignedUrlResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response =
            handlers::handle_get_download_url(&self.state, user.user_id, &req.media_id).await?;

        Ok(Response::new(response))
    }

    async fn confirm_upload(
        &self,
        request: Request<ConfirmUploadRequest>,
    ) -> Result<Response<ConfirmUploadResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response = handlers::handle_confirm_upload(
            &self.state,
            user.user_id,
            &req.media_id,
            req.file_size,
        )
        .await?;

        Ok(Response::new(response))
    }
}
