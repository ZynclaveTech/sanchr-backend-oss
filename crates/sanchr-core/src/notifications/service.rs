use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_proto::notifications::notification_service_server::NotificationService;
use sanchr_proto::notifications::{
    RegisterPushTokenRequest, RegisterPushTokenResponse, SetConversationNotificationPrefsRequest,
    SetConversationNotificationPrefsResponse, UpdateNotificationPrefsRequest,
    UpdateNotificationPrefsResponse,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

pub struct NotificationServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl NotificationService for NotificationServiceImpl {
    async fn register_push_token(
        &self,
        request: Request<RegisterPushTokenRequest>,
    ) -> Result<Response<RegisterPushTokenResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        handlers::handle_register_push_token(
            &self.state,
            user.user_id,
            user.device_id,
            &req.token,
            &req.platform,
            &req.voip_token,
        )
        .await?;

        Ok(Response::new(RegisterPushTokenResponse {}))
    }

    async fn update_notification_prefs(
        &self,
        request: Request<UpdateNotificationPrefsRequest>,
    ) -> Result<Response<UpdateNotificationPrefsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        handlers::handle_update_notification_prefs(&self.state, user.user_id, &req).await?;

        Ok(Response::new(UpdateNotificationPrefsResponse {}))
    }

    async fn set_conversation_notification_prefs(
        &self,
        request: Request<SetConversationNotificationPrefsRequest>,
    ) -> Result<Response<SetConversationNotificationPrefsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        handlers::handle_set_conversation_notification_prefs(
            &self.state,
            user.user_id,
            user.device_id,
            &req,
        )
        .await?;

        Ok(Response::new(SetConversationNotificationPrefsResponse {}))
    }
}
