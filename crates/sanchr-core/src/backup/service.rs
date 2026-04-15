use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::backup::backup_service_server::BackupService;
use sanchr_proto::backup::{
    CommitBackupRequest, CommitBackupResponse, CreateBackupUploadRequest,
    CreateBackupUploadResponse, DeleteBackupRequest, DeleteBackupResponse,
    GetBackupDownloadRequest, GetBackupDownloadResponse, ListBackupsRequest, ListBackupsResponse,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct BackupServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl BackupService for BackupServiceImpl {
    async fn create_backup_upload(
        &self,
        request: Request<CreateBackupUploadRequest>,
    ) -> Result<Response<CreateBackupUploadResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response = handlers::handle_create_backup_upload(
            &self.state,
            handlers::CreateBackupUploadParams {
                owner_id: user.user_id,
                byte_size: req.byte_size,
                sha256_hash: &req.sha256_hash,
                opaque_metadata: &req.opaque_metadata,
                reserved_forward_secrecy_metadata: &req.reserved_forward_secrecy_metadata,
                lineage_id: if req.lineage_id.is_empty() {
                    None
                } else {
                    Some(req.lineage_id.as_str())
                },
                format_version: req.format_version,
            },
        )
        .await?;

        Ok(Response::new(response))
    }

    async fn commit_backup(
        &self,
        request: Request<CommitBackupRequest>,
    ) -> Result<Response<CommitBackupResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response = handlers::handle_commit_backup(
            &self.state,
            user.user_id,
            &req.backup_id,
            req.byte_size,
            &req.sha256_hash,
        )
        .await?;

        Ok(Response::new(response))
    }

    async fn list_backups(
        &self,
        request: Request<ListBackupsRequest>,
    ) -> Result<Response<ListBackupsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let response = handlers::handle_list_backups(&self.state, user.user_id).await?;
        Ok(Response::new(response))
    }

    async fn get_backup_download(
        &self,
        request: Request<GetBackupDownloadRequest>,
    ) -> Result<Response<GetBackupDownloadResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response =
            handlers::handle_get_backup_download(&self.state, user.user_id, &req.backup_id).await?;

        Ok(Response::new(response))
    }

    async fn delete_backup(
        &self,
        request: Request<DeleteBackupRequest>,
    ) -> Result<Response<DeleteBackupResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let response =
            handlers::handle_delete_backup(&self.state, user.user_id, &req.backup_id).await?;

        Ok(Response::new(response))
    }
}
