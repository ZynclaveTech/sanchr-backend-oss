use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use sanchr_proto::contacts::contact_service_server::ContactService;
use sanchr_proto::contacts::{
    BlockContactRequest, BlockContactResponse, GetBlockedListRequest, GetBlockedListResponse,
    GetContactsRequest, GetContactsResponse, SyncContactsRequest, SyncContactsResponse,
    UnblockContactRequest, UnblockContactResponse,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct ContactServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl ContactService for ContactServiceImpl {
    async fn sync_contacts(
        &self,
        request: Request<SyncContactsRequest>,
    ) -> Result<Response<SyncContactsResponse>, Status> {
        let _user = auth::authenticate(&self.state, &request).await?;
        Err(Status::failed_precondition(
            "legacy hash-based contact sync is disabled in OSS; use DiscoveryService (Bloom + OPRF)",
        ))
    }

    async fn get_contacts(
        &self,
        request: Request<GetContactsRequest>,
    ) -> Result<Response<GetContactsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let contacts = handlers::handle_get_contacts(&self.state, user.user_id).await?;

        Ok(Response::new(GetContactsResponse { contacts }))
    }

    async fn block_contact(
        &self,
        request: Request<BlockContactRequest>,
    ) -> Result<Response<BlockContactResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let contact_user_id = Uuid::parse_str(&req.contact_user_id)
            .map_err(|_| Status::invalid_argument("invalid contact_user_id"))?;

        handlers::handle_block_contact(&self.state, user.user_id, contact_user_id).await?;

        Ok(Response::new(BlockContactResponse {}))
    }

    async fn unblock_contact(
        &self,
        request: Request<UnblockContactRequest>,
    ) -> Result<Response<UnblockContactResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let contact_user_id = Uuid::parse_str(&req.contact_user_id)
            .map_err(|_| Status::invalid_argument("invalid contact_user_id"))?;

        handlers::handle_unblock_contact(&self.state, user.user_id, contact_user_id).await?;

        Ok(Response::new(UnblockContactResponse {}))
    }

    async fn get_blocked_list(
        &self,
        request: Request<GetBlockedListRequest>,
    ) -> Result<Response<GetBlockedListResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let blocked_user_ids = handlers::handle_get_blocked_list(&self.state, user.user_id).await?;

        Ok(Response::new(GetBlockedListResponse { blocked_user_ids }))
    }
}
