use std::sync::Arc;

use aws_sdk_s3::types::ObjectCannedAcl;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::media as pg_media;
use sanchr_proto::media::{ConfirmUploadResponse, MediaPurpose, PresignedUrlResponse};

use crate::server::AppState;

/// Maximum upload size: 100 MiB.
const MAX_UPLOAD_SIZE: i64 = 104_857_600;

fn media_purpose_name(purpose: MediaPurpose) -> &'static str {
    match purpose {
        MediaPurpose::Attachment => "attachment",
        MediaPurpose::Avatar => "avatar",
    }
}

fn display_url_for_media(state: &AppState, storage_key: &str, purpose: &str) -> String {
    if purpose == "avatar" {
        state
            .config
            .storage
            .cdn_base_url
            .as_deref()
            .map(|cdn| format!("{}/{}", cdn.trim_end_matches('/'), storage_key))
            .unwrap_or_default()
    } else {
        String::new()
    }
}

/// Generate an S3 presigned PUT URL for the client to upload encrypted media.
pub async fn handle_get_upload_url(
    state: &Arc<AppState>,
    user_id: Uuid,
    file_size: i64,
    content_type: &str,
    sha256_hash: &str,
    purpose: MediaPurpose,
) -> Result<PresignedUrlResponse, Status> {
    if file_size <= 0 {
        return Err(Status::invalid_argument("file_size must be positive"));
    }
    if file_size > MAX_UPLOAD_SIZE {
        return Err(Status::invalid_argument(format!(
            "file_size exceeds maximum of {} bytes",
            MAX_UPLOAD_SIZE
        )));
    }

    let is_public = purpose == MediaPurpose::Avatar;
    let media_id = Uuid::new_v4();
    let media_id_str = media_id.to_string();
    let key = if is_public {
        format!("avatars/{}/{}", user_id, media_id_str)
    } else {
        format!("media/{}/{}", user_id, media_id_str)
    };
    let ttl = state.config.storage.presigned_url_ttl;

    let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
        .expires_in(std::time::Duration::from_secs(ttl))
        .build()
        .map_err(|e| internal_status("presigning config error", e))?;

    let mut put = state
        .s3
        .put_object()
        .bucket(&state.config.storage.bucket)
        .key(&key)
        .content_type(content_type)
        .content_length(file_size);

    if is_public {
        put = put.acl(ObjectCannedAcl::PublicRead);
    }

    let presigned = put
        .presigned(presigning_config)
        .await
        .map_err(|e| internal_status("presigned PUT failed", e))?;

    pg_media::insert_media_object(
        &state.pg_pool,
        media_id,
        user_id,
        media_purpose_name(purpose),
        &key,
        content_type,
        file_size,
        sha256_hash,
    )
    .await
    .map_err(|e| internal_status("failed to persist media object", e))?;

    let display_url = display_url_for_media(state, &key, media_purpose_name(purpose));

    Ok(PresignedUrlResponse {
        url: presigned.uri().to_string(),
        media_id: media_id_str,
        expires_in: ttl as i64,
        display_url,
    })
}

/// Generate an S3 presigned GET URL for the client to download encrypted media.
///
/// Any authenticated user may obtain a download URL for a confirmed media_id.
/// The media is E2EE so the server cannot read it regardless of who requests
/// the URL. The media_id UUID (128-bit) lives inside a sealed Signal message,
/// so only recipients know it — possession is sufficient authorization.
pub async fn handle_get_download_url(
    state: &Arc<AppState>,
    user_id: Uuid,
    media_id: &str,
) -> Result<PresignedUrlResponse, Status> {
    if media_id.is_empty() {
        return Err(Status::invalid_argument("media_id is required"));
    }

    let media_uuid =
        Uuid::parse_str(media_id).map_err(|_| Status::invalid_argument("invalid media_id"))?;

    // Fetch the confirmed media object without an owner check.
    //
    // Rationale: media is always E2EE — the server cannot read its contents
    // regardless of who requests the presigned URL. The media_id is a 128-bit
    // UUID that only conversation participants know (it's inside the sealed
    // Signal message), so possessing it is sufficient proof of authorization.
    // Restricting to owner_id would block receivers from downloading media
    // sent by other participants.
    //
    // We still require the row to be confirmed (upload completed) to avoid
    // issuing download URLs for phantom objects.
    let media = match pg_media::get_confirmed_media_object(&state.pg_pool, media_uuid).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            tracing::warn!(
                target: "security",
                %user_id,
                %media_uuid,
                "download url requested for unknown or unconfirmed media_id"
            );
            return Err(Status::not_found("media not found"));
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch media metadata for download url");
            return Err(Status::unavailable(
                "media metadata temporarily unavailable",
            ));
        }
    };

    let ttl = state.config.storage.presigned_url_ttl;

    let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
        .expires_in(std::time::Duration::from_secs(ttl))
        .build()
        .map_err(|e| internal_status("presigning config error", e))?;

    let presigned = state
        .s3
        .get_object()
        .bucket(&state.config.storage.bucket)
        .key(&media.storage_key)
        .presigned(presigning_config)
        .await
        .map_err(|e| internal_status("presigned GET failed", e))?;

    Ok(PresignedUrlResponse {
        url: presigned.uri().to_string(),
        media_id: media_id.to_string(),
        expires_in: ttl as i64,
        display_url: display_url_for_media(state, &media.storage_key, &media.purpose),
    })
}

/// Optionally verify the upload landed in S3 via a HEAD request.
pub async fn handle_confirm_upload(
    state: &Arc<AppState>,
    user_id: Uuid,
    media_id: &str,
    file_size: i64,
) -> Result<ConfirmUploadResponse, Status> {
    if media_id.is_empty() {
        return Err(Status::invalid_argument("media_id is required"));
    }

    let media_uuid =
        Uuid::parse_str(media_id).map_err(|_| Status::invalid_argument("invalid media_id"))?;
    let media = pg_media::get_media_object(&state.pg_pool, user_id, media_uuid)
        .await
        .map_err(|e| internal_status("failed to fetch media metadata", e))?
        .ok_or_else(|| Status::not_found("media object not found"))?;

    // HEAD request to verify the object exists.
    let head = state
        .s3
        .head_object()
        .bucket(&state.config.storage.bucket)
        .key(&media.storage_key)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "object not found in S3");
            Status::not_found("object not found")
        })?;

    if file_size != media.file_size {
        return Err(Status::invalid_argument(
            "file_size does not match pending upload",
        ));
    }

    let object_size = head.content_length().unwrap_or_default();
    if object_size != media.file_size {
        return Err(Status::failed_precondition(
            "uploaded object size does not match expected file_size",
        ));
    }

    pg_media::mark_media_confirmed(&state.pg_pool, user_id, media_uuid)
        .await
        .map_err(|e| internal_status("failed to confirm media metadata", e))?;

    Ok(ConfirmUploadResponse {
        media_id: media_id.to_string(),
    })
}
