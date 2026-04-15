use std::sync::Arc;

use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::backups as pg_backups;
use sanchr_proto::backup::{
    BackupMetadata, CommitBackupResponse, CreateBackupUploadResponse, DeleteBackupResponse,
    GetBackupDownloadResponse, ListBackupsResponse,
};

use crate::server::AppState;

const MAX_BACKUP_SIZE: i64 = 536_870_912;
pub const MAX_BACKUP_LIST_PAGE_SIZE: i64 = 100;

pub struct CreateBackupUploadParams<'a> {
    pub owner_id: Uuid,
    pub byte_size: i64,
    pub sha256_hash: &'a str,
    pub opaque_metadata: &'a [u8],
    pub reserved_forward_secrecy_metadata: &'a [u8],
    pub lineage_id: Option<&'a str>,
    pub format_version: i32,
}

fn backup_object_key(owner_id: Uuid, lineage_id: Uuid, backup_id: Uuid) -> String {
    format!("backups/{owner_id}/{lineage_id}/{backup_id}.bin")
}

fn to_proto(row: pg_backups::BackupObjectRow) -> BackupMetadata {
    BackupMetadata {
        backup_id: row.backup_id.to_string(),
        lineage_id: row.lineage_id.to_string(),
        format_version: row.format_version,
        byte_size: row.byte_size,
        sha256_hash: row.sha256_hash,
        opaque_metadata: row.opaque_metadata,
        reserved_forward_secrecy_metadata: row.reserved_forward_secrecy_metadata,
        created_at: row.created_at.to_rfc3339(),
        committed_at: row
            .committed_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
    }
}

pub async fn handle_create_backup_upload(
    state: &Arc<AppState>,
    params: CreateBackupUploadParams<'_>,
) -> Result<CreateBackupUploadResponse, Status> {
    let owner_id = params.owner_id;
    let byte_size = params.byte_size;
    let sha256_hash = params.sha256_hash;
    let opaque_metadata = params.opaque_metadata;
    let reserved_forward_secrecy_metadata = params.reserved_forward_secrecy_metadata;
    let format_version = params.format_version;

    if byte_size <= 0 {
        return Err(Status::invalid_argument("byte_size must be positive"));
    }
    if byte_size > MAX_BACKUP_SIZE {
        return Err(Status::invalid_argument(format!(
            "byte_size exceeds maximum of {MAX_BACKUP_SIZE} bytes"
        )));
    }
    if sha256_hash.is_empty() {
        return Err(Status::invalid_argument("sha256_hash is required"));
    }
    if opaque_metadata.is_empty() {
        return Err(Status::invalid_argument("opaque_metadata is required"));
    }
    if format_version <= 0 {
        return Err(Status::invalid_argument("format_version must be positive"));
    }

    let backup_id = Uuid::new_v4();
    let lineage_id = match params.lineage_id.filter(|value| !value.is_empty()) {
        Some(value) => {
            Uuid::parse_str(value).map_err(|_| Status::invalid_argument("invalid lineage_id"))?
        }
        None => Uuid::new_v4(),
    };
    let object_key = backup_object_key(owner_id, lineage_id, backup_id);
    let ttl = state.config.storage.presigned_url_ttl;

    let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
        .expires_in(std::time::Duration::from_secs(ttl))
        .build()
        .map_err(|e| internal_status("presigning config error", e))?;

    let presigned = state
        .s3
        .put_object()
        .bucket(&state.config.storage.bucket)
        .key(&object_key)
        .content_type("application/octet-stream")
        .content_length(byte_size)
        .presigned(presigning_config)
        .await
        .map_err(|e| internal_status("presigned PUT failed", e))?;

    pg_backups::insert_pending_backup(
        &state.pg_pool,
        backup_id,
        owner_id,
        lineage_id,
        format_version,
        &object_key,
        byte_size,
        sha256_hash,
        opaque_metadata,
        reserved_forward_secrecy_metadata,
    )
    .await
    .map_err(|e| internal_status("failed to persist backup metadata", e))?;

    Ok(CreateBackupUploadResponse {
        backup_id: backup_id.to_string(),
        lineage_id: lineage_id.to_string(),
        upload_url: presigned.uri().to_string(),
        expires_in: ttl as i64,
    })
}

pub async fn handle_commit_backup(
    state: &Arc<AppState>,
    owner_id: Uuid,
    backup_id: &str,
    byte_size: i64,
    sha256_hash: &str,
) -> Result<CommitBackupResponse, Status> {
    let backup_id =
        Uuid::parse_str(backup_id).map_err(|_| Status::invalid_argument("invalid backup_id"))?;
    let backup = pg_backups::get_backup(&state.pg_pool, owner_id, backup_id)
        .await
        .map_err(|e| internal_status("failed to fetch backup metadata", e))?
        .ok_or_else(|| Status::not_found("backup not found"))?;

    if backup.byte_size != byte_size {
        return Err(Status::invalid_argument(
            "byte_size does not match pending backup",
        ));
    }
    if backup.sha256_hash != sha256_hash {
        return Err(Status::invalid_argument(
            "sha256_hash does not match pending backup",
        ));
    }

    let head = state
        .s3
        .head_object()
        .bucket(&state.config.storage.bucket)
        .key(&backup.object_key)
        .send()
        .await
        .map_err(|e| Status::not_found(format!("backup object not found in S3: {e}")))?;
    let object_size = head.content_length().unwrap_or_default();
    if object_size != backup.byte_size {
        return Err(Status::failed_precondition(
            "uploaded backup size does not match expected byte_size",
        ));
    }

    let committed = pg_backups::commit_backup(&state.pg_pool, owner_id, backup_id)
        .await
        .map_err(|e| internal_status("failed to commit backup metadata", e))?;

    Ok(CommitBackupResponse {
        backup: Some(to_proto(committed)),
    })
}

pub async fn handle_list_backups(
    state: &Arc<AppState>,
    owner_id: Uuid,
) -> Result<ListBackupsResponse, Status> {
    let backups =
        pg_backups::list_committed_backups(&state.pg_pool, owner_id, MAX_BACKUP_LIST_PAGE_SIZE)
            .await
            .map_err(|e| internal_status("failed to list backups", e))?;

    Ok(ListBackupsResponse {
        backups: backups.into_iter().map(to_proto).collect(),
    })
}

pub async fn handle_get_backup_download(
    state: &Arc<AppState>,
    owner_id: Uuid,
    backup_id: &str,
) -> Result<GetBackupDownloadResponse, Status> {
    let backup_id =
        Uuid::parse_str(backup_id).map_err(|_| Status::invalid_argument("invalid backup_id"))?;
    let backup = pg_backups::get_backup(&state.pg_pool, owner_id, backup_id)
        .await
        .map_err(|e| internal_status("failed to fetch backup metadata", e))?
        .ok_or_else(|| Status::not_found("backup not found"))?;

    if !backup.is_committed {
        return Err(Status::failed_precondition("backup upload not committed"));
    }

    let ttl = state.config.storage.presigned_url_ttl;
    let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
        .expires_in(std::time::Duration::from_secs(ttl))
        .build()
        .map_err(|e| internal_status("presigning config error", e))?;

    let presigned = state
        .s3
        .get_object()
        .bucket(&state.config.storage.bucket)
        .key(&backup.object_key)
        .presigned(presigning_config)
        .await
        .map_err(|e| internal_status("presigned GET failed", e))?;

    Ok(GetBackupDownloadResponse {
        backup_id: backup.backup_id.to_string(),
        download_url: presigned.uri().to_string(),
        expires_in: ttl as i64,
        backup: Some(to_proto(backup)),
    })
}

pub async fn handle_delete_backup(
    state: &Arc<AppState>,
    owner_id: Uuid,
    backup_id: &str,
) -> Result<DeleteBackupResponse, Status> {
    let backup_id =
        Uuid::parse_str(backup_id).map_err(|_| Status::invalid_argument("invalid backup_id"))?;
    let backup = pg_backups::delete_backup(&state.pg_pool, owner_id, backup_id)
        .await
        .map_err(|e| internal_status("failed to delete backup metadata", e))?
        .ok_or_else(|| Status::not_found("backup not found"))?;

    state
        .s3
        .delete_object()
        .bucket(&state.config.storage.bucket)
        .key(&backup.object_key)
        .send()
        .await
        .map_err(|e| internal_status("failed to delete backup object", e))?;

    Ok(DeleteBackupResponse {})
}
