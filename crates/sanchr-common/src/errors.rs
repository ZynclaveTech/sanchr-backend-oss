use std::fmt::Display;

use thiserror::Error;
use tonic::{Code, Status};
use tracing::error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited")]
    RateLimited,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<AppError> for Status {
    fn from(err: AppError) -> Self {
        match err {
            AppError::NotFound(msg) => Status::new(Code::NotFound, msg),
            AppError::InvalidInput(msg) => Status::new(Code::InvalidArgument, msg),
            AppError::Unauthorized(msg) => Status::new(Code::Unauthenticated, msg),
            AppError::Conflict(msg) => Status::new(Code::AlreadyExists, msg),
            AppError::RateLimited => Status::new(Code::ResourceExhausted, "rate limited"),
            AppError::Internal(msg) => {
                error!(error = %msg, "internal application error");
                Status::new(Code::Internal, "internal server error")
            }
            AppError::Database(err) => {
                error!(error = %err, "database error");
                Status::new(Code::Internal, "internal server error")
            }
        }
    }
}

pub fn internal_status(context: &'static str, err: impl Display) -> Status {
    error!(context, error = %err, "internal grpc error");
    Status::new(Code::Internal, "internal server error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn not_found_maps_to_grpc_not_found() {
        let status: Status = AppError::NotFound("user".into()).into();
        assert_eq!(status.code(), Code::NotFound);
        assert_eq!(status.message(), "user");
    }

    #[test]
    fn invalid_input_maps_to_invalid_argument() {
        let status: Status = AppError::InvalidInput("bad field".into()).into();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "bad field");
    }

    #[test]
    fn unauthorized_maps_to_unauthenticated() {
        let status: Status = AppError::Unauthorized("bad token".into()).into();
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(status.message(), "bad token");
    }

    #[test]
    fn conflict_maps_to_already_exists() {
        let status: Status = AppError::Conflict("duplicate".into()).into();
        assert_eq!(status.code(), Code::AlreadyExists);
        assert_eq!(status.message(), "duplicate");
    }

    #[test]
    fn rate_limited_maps_to_resource_exhausted() {
        let status: Status = AppError::RateLimited.into();
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[test]
    fn internal_hides_details() {
        let status: Status = AppError::Internal("secret db error".into()).into();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "internal server error");
    }

    #[test]
    fn internal_message_is_never_exposed() {
        let sensitive = "password=hunter2 host=prod-db";
        let status: Status = AppError::Internal(sensitive.into()).into();
        assert_eq!(status.code(), Code::Internal);
        assert!(
            !status.message().contains("hunter2"),
            "sensitive data must not leak"
        );
        assert!(
            !status.message().contains("prod-db"),
            "sensitive data must not leak"
        );
    }

    #[test]
    fn internal_status_hides_details() {
        let status = internal_status("database write failed", "password=hunter2 host=prod-db");
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "internal server error");
    }

    #[test]
    fn database_error_maps_to_internal() {
        // Construct a sqlx::Error via its RowNotFound variant (no DB connection needed).
        let sqlx_err = sqlx::Error::RowNotFound;
        let app_err = AppError::Database(sqlx_err);
        let status: Status = app_err.into();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "internal server error");
    }

    #[test]
    fn database_error_from_impl() {
        // Verify the From<sqlx::Error> impl produces AppError::Database.
        let sqlx_err = sqlx::Error::RowNotFound;
        let app_err = AppError::from(sqlx_err);
        assert!(matches!(app_err, AppError::Database(_)));
    }

    #[test]
    fn database_hides_details() {
        let sqlx_err = sqlx::Error::RowNotFound;
        let status: Status = AppError::Database(sqlx_err).into();
        // The raw sqlx message must not appear in the gRPC status message.
        assert_eq!(status.message(), "internal server error");
    }
}
