use sanchr_common::config::CallingConfig;
use sanchr_server_crypto::turn_creds::generate_turn_credentials;

/// Build a complete set of TURN credentials for a user.
///
/// Returns `(urls, username, credential, ttl)`.
pub fn get_turn_credentials(
    config: &CallingConfig,
    user_id: &str,
) -> (Vec<String>, String, String, u64) {
    tracing::debug!(
        turn_servers_count = config.turn_servers.len(),
        turn_servers = ?config.turn_servers,
        turn_secret_len = config.turn_secret.len(),
        turn_credential_ttl = config.turn_credential_ttl,
        user_id,
        "turn::get_turn_credentials: building credentials"
    );

    let (username, credential, ttl) =
        generate_turn_credentials(&config.turn_secret, user_id, config.turn_credential_ttl);

    tracing::debug!(
        username,
        credential_len = credential.len(),
        ttl,
        urls = ?config.turn_servers,
        "turn::get_turn_credentials: credentials generated"
    );

    (config.turn_servers.clone(), username, credential, ttl)
}
