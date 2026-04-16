use fred::clients::Client;
use fred::error::Error;
use fred::interfaces::{KeysInterface, SetsInterface};
use fred::types::Expiration;
use uuid::Uuid;

/// Key for the per-user set of active session identifiers. Used to revoke
/// every session for a user (e.g. on account deletion) without having to SCAN
/// the entire keyspace.
fn user_sessions_key(user_id: &Uuid) -> String {
    format!("user:{}:sessions", user_id)
}

/// Encoded member format in the user-sessions set.
fn session_member(jti: &str) -> String {
    format!("session:{}", jti)
}

/// Store an access session in Redis.
///
/// - `session:{jti}` → `"user_id:device_id"` with `access_ttl` seconds TTL
/// - `user:{user_id}:sessions` Set containing `session:{jti}` so all of a
///   user's sessions can be revoked at once. The set TTL is refreshed on each
///   new session to match the access-token lifetime.
///
/// Refresh tokens are stored exclusively in Postgres (`refresh_tokens` table).
pub async fn create_session(
    client: &Client,
    access_token_jti: &str,
    user_id: &Uuid,
    device_id: i32,
    access_ttl: i64,
) -> Result<(), Error> {
    let value = format!("{}:{}", user_id, device_id);

    let session_key = format!("session:{}", access_token_jti);
    client
        .set::<(), _, _>(
            &session_key,
            value,
            Some(Expiration::EX(access_ttl)),
            None,
            false,
        )
        .await?;

    // Track this session in the per-user set so we can revoke everything at
    // once on account deletion.
    let user_key = user_sessions_key(user_id);
    client
        .sadd::<(), _, _>(&user_key, session_member(access_token_jti))
        .await?;
    client.expire::<(), _>(&user_key, access_ttl, None).await?;

    Ok(())
}

/// Revoke every active session for a user. Best-effort: any stale members in
/// the index are still issued a DEL (which is a no-op on missing keys), and
/// the index itself is removed at the end.
pub async fn revoke_all_sessions_for_user(client: &Client, user_id: &Uuid) -> Result<(), Error> {
    let user_key = user_sessions_key(user_id);
    let members: Vec<String> = client.smembers(&user_key).await?;

    for member in &members {
        // Each member is a fully-qualified key (`session:{jti}`). Delete directly.
        client.del::<(), _>(member).await?;
    }

    client.del::<(), _>(&user_key).await?;
    Ok(())
}

fn parse_session_value(raw: &str) -> Option<(Uuid, i32)> {
    let mut parts = raw.splitn(2, ':');
    let user_id: Uuid = parts.next()?.parse().ok()?;
    let device_id: i32 = parts.next()?.parse().ok()?;
    Some((user_id, device_id))
}

/// Validate an access token by its JTI. Returns `(user_id, device_id)` if found.
pub async fn validate_session(client: &Client, jti: &str) -> Result<Option<(Uuid, i32)>, Error> {
    let key = format!("session:{}", jti);
    let raw: Option<String> = client.get(&key).await?;
    Ok(raw.as_deref().and_then(parse_session_value))
}

/// Delete an access-token session by JTI.
pub async fn revoke_session(client: &Client, jti: &str) -> Result<(), Error> {
    let key = format!("session:{}", jti);
    client.del::<(), _>(&key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_session_value_valid() {
        let uuid = Uuid::new_v4();
        let input = format!("{}:42", uuid);
        let result = parse_session_value(&input);
        assert_eq!(result, Some((uuid, 42)));
    }

    #[test]
    fn parse_session_value_invalid_uuid() {
        let result = parse_session_value("not-a-uuid:1");
        assert!(result.is_none());
    }

    #[test]
    fn parse_session_value_invalid_device() {
        let uuid = Uuid::new_v4();
        let input = format!("{}:abc", uuid);
        let result = parse_session_value(&input);
        assert!(result.is_none());
    }

    #[test]
    fn parse_session_value_missing_colon() {
        let result = parse_session_value("just-a-string");
        assert!(result.is_none());
    }

    #[test]
    fn parse_session_value_empty() {
        let result = parse_session_value("");
        assert!(result.is_none());
    }
}
