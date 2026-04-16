pub mod auth {
    tonic::include_proto!("sanchr.auth");
}
pub mod keys {
    tonic::include_proto!("sanchr.keys");
}
pub mod messaging {
    tonic::include_proto!("sanchr.messaging");
}
pub mod contacts {
    tonic::include_proto!("sanchr.contacts");
}
pub mod settings {
    tonic::include_proto!("sanchr.settings");
}
#[allow(clippy::doc_lazy_continuation)]
pub mod vault {
    tonic::include_proto!("sanchr.vault");
}
pub mod media {
    tonic::include_proto!("sanchr.media");
}
pub mod notifications {
    tonic::include_proto!("sanchr.notifications");
}
pub mod calling {
    tonic::include_proto!("sanchr.calling");
}
pub mod backup {
    tonic::include_proto!("sanchr.backup");
}
pub mod backup_payload {
    tonic::include_proto!("sanchr.backup_payload");
}
pub mod discovery {
    tonic::include_proto!("sanchr.discovery");
}
pub mod ekf {
    tonic::include_proto!("sanchr.ekf");
}
pub mod sealed_sender {
    tonic::include_proto!("sanchr.sealed_sender");
}
