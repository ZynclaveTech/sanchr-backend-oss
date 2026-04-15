use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::vault::vault_service_server::VaultService;
use sanchr_proto::vault::{
    CreateVaultItemRequest, DeleteVaultItemRequest, DeleteVaultItemResponse, GetVaultItemRequest,
    GetVaultItemsRequest, GetVaultItemsResponse, VaultItem,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct VaultServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl VaultService for VaultServiceImpl {
    async fn create_vault_item(
        &self,
        request: Request<CreateVaultItemRequest>,
    ) -> Result<Response<VaultItem>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();
        let item = handlers::handle_create_vault_item(&self.state, user.user_id, &req).await?;
        Ok(Response::new(item))
    }

    async fn get_vault_items(
        &self,
        request: Request<GetVaultItemsRequest>,
    ) -> Result<Response<GetVaultItemsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();
        let response = handlers::handle_get_vault_items(&self.state, user.user_id, &req).await?;
        Ok(Response::new(response))
    }

    async fn get_vault_item(
        &self,
        request: Request<GetVaultItemRequest>,
    ) -> Result<Response<VaultItem>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();
        let item =
            handlers::handle_get_vault_item(&self.state, user.user_id, &req.vault_item_id).await?;
        Ok(Response::new(item))
    }

    async fn delete_vault_item(
        &self,
        request: Request<DeleteVaultItemRequest>,
    ) -> Result<Response<DeleteVaultItemResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();
        let response =
            handlers::handle_delete_vault_item(&self.state, user.user_id, &req.vault_item_id)
                .await?;
        Ok(Response::new(response))
    }
}
