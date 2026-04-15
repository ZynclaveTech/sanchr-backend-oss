use prost::Message;
use sanchr_proto::ekf::EkfRotationNeeded;
use tracing::info;

const EKF_ROTATION_SUBJECT_PREFIX: &str = "ekf.rotation";

pub async fn publish_rotation_needed(
    nats: &async_nats::Client,
    user_id: &str,
    key_class: &str,
    entry_id: String,
    expired_at_ms: i64,
) -> Result<(), async_nats::PublishError> {
    let event = EkfRotationNeeded {
        user_id: user_id.to_string(),
        key_class: key_class.to_string(),
        expired_at: expired_at_ms,
        entry_id,
    };
    let payload = event.encode_to_vec();
    let subject = format!("{}.{}", EKF_ROTATION_SUBJECT_PREFIX, user_id);
    nats.publish(subject, payload.into()).await?;
    info!(
        user_id,
        key_class, "published EKF rotation_needed notification"
    );
    Ok(())
}
