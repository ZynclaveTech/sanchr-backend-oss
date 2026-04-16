use fred::prelude::*;

/// Set typing indicator with 5-second TTL.
pub async fn set_typing(
    client: &Client,
    conversation_id: &str,
    user_id: &str,
) -> Result<(), Error> {
    let key = format!("typing:{}", conversation_id);
    // Add user to set with 5s individual expiry via separate key
    let member_key = format!("typing:{}:{}", conversation_id, user_id);
    client
        .set::<(), _, _>(&member_key, "1", Some(Expiration::EX(5)), None, false)
        .await?;
    // Also add to the set for easy lookup
    client.sadd::<(), _, _>(&key, user_id).await?;
    client.expire::<(), _>(&key, 10, None).await?; // Set TTL slightly longer
    Ok(())
}

/// Clear typing indicator.
pub async fn clear_typing(
    client: &Client,
    conversation_id: &str,
    user_id: &str,
) -> Result<(), Error> {
    let key = format!("typing:{}", conversation_id);
    let member_key = format!("typing:{}:{}", conversation_id, user_id);
    client.srem::<(), _, _>(&key, user_id).await?;
    client.del::<(), _>(&member_key).await?;
    Ok(())
}

/// Get all users currently typing in a conversation.
/// Filters out expired members by checking their individual keys.
pub async fn get_typing(client: &Client, conversation_id: &str) -> Result<Vec<String>, Error> {
    let key = format!("typing:{}", conversation_id);
    let members: Vec<String> = client.smembers(&key).await?;

    let mut active = Vec::new();
    for member in &members {
        let member_key = format!("typing:{}:{}", conversation_id, member);
        let exists: bool = client.exists(&member_key).await?;
        if exists {
            active.push(member.clone());
        } else {
            // Clean up expired member from set
            let _ = client.srem::<(), _, _>(&key, member.as_str()).await;
        }
    }

    Ok(active)
}
