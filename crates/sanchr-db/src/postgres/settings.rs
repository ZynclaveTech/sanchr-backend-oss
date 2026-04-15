use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSettingsRow {
    pub user_id: Uuid,
    pub read_receipts: Option<bool>,
    pub online_status_visible: Option<bool>,
    pub typing_indicator: Option<bool>,
    pub profile_photo_visibility: Option<String>,
    pub sanchr_mode_enabled: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub screen_lock_timeout: Option<i32>,
    pub screenshot_protection: Option<bool>,
    pub biometric_lock: Option<bool>,
    pub message_notifications: Option<bool>,
    pub group_notifications: Option<bool>,
    pub call_notifications: Option<bool>,
    pub notification_sound: Option<String>,
    pub notification_vibrate: Option<bool>,
    pub show_preview: Option<bool>,
    pub theme: Option<String>,
    pub font_size: Option<String>,
    pub chat_wallpaper: Option<String>,
    pub auto_download_wifi: Option<String>,
    pub auto_download_mobile: Option<String>,
    pub auto_download_roaming: Option<String>,
    pub low_data_mode: Option<bool>,
    #[sqlx(default)]
    pub registration_lock_enabled: Option<bool>,
    #[sqlx(default)]
    pub registration_lock_pin_hash: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProfileInfo {
    pub id: Uuid,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    // Encrypted profile blobs — None means the client hasn't sent them yet.
    pub profile_key: Option<Vec<u8>>,
    pub encrypted_display_name: Option<Vec<u8>>,
    pub encrypted_bio: Option<Vec<u8>>,
    pub encrypted_avatar_url: Option<Vec<u8>>,
}

/// Fetch the settings row for a user. Returns an error if the row is missing.
pub async fn get_settings(pool: &PgPool, user_id: Uuid) -> Result<UserSettingsRow, sqlx::Error> {
    sqlx::query_as::<_, UserSettingsRow>(
        r#"
        SELECT * FROM user_settings
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

/// Overwrite all mutable fields of a settings row and return the updated row.
pub async fn update_settings(
    pool: &PgPool,
    user_id: Uuid,
    settings: &UserSettingsRow,
) -> Result<UserSettingsRow, sqlx::Error> {
    sqlx::query_as::<_, UserSettingsRow>(
        r#"
        UPDATE user_settings SET
            read_receipts           = $2,
            online_status_visible   = $3,
            typing_indicator        = $4,
            profile_photo_visibility = $5,
            sanchr_mode_enabled       = $6,
            screen_lock_enabled     = $7,
            screen_lock_timeout     = $8,
            screenshot_protection   = $9,
            biometric_lock          = $10,
            message_notifications   = $11,
            group_notifications     = $12,
            call_notifications      = $13,
            notification_sound      = $14,
            notification_vibrate    = $15,
            show_preview            = $16,
            theme                   = $17,
            font_size               = $18,
            chat_wallpaper          = $19,
            auto_download_wifi      = $20,
            auto_download_mobile    = $21,
            auto_download_roaming   = $22,
            low_data_mode           = $23,
            updated_at              = now()
        WHERE user_id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(settings.read_receipts)
    .bind(settings.online_status_visible)
    .bind(settings.typing_indicator)
    .bind(&settings.profile_photo_visibility)
    .bind(settings.sanchr_mode_enabled)
    .bind(settings.screen_lock_enabled)
    .bind(settings.screen_lock_timeout)
    .bind(settings.screenshot_protection)
    .bind(settings.biometric_lock)
    .bind(settings.message_notifications)
    .bind(settings.group_notifications)
    .bind(settings.call_notifications)
    .bind(&settings.notification_sound)
    .bind(settings.notification_vibrate)
    .bind(settings.show_preview)
    .bind(&settings.theme)
    .bind(&settings.font_size)
    .bind(&settings.chat_wallpaper)
    .bind(&settings.auto_download_wifi)
    .bind(&settings.auto_download_mobile)
    .bind(&settings.auto_download_roaming)
    .bind(settings.low_data_mode)
    .fetch_one(pool)
    .await
}

/// Atomically enable Sanchr Mode and all related privacy protections.
pub async fn activate_sanchr_mode(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserSettingsRow, sqlx::Error> {
    sqlx::query_as::<_, UserSettingsRow>(
        r#"
        UPDATE user_settings SET
            sanchr_mode_enabled     = true,
            screenshot_protection = true,
            show_preview          = false,
            online_status_visible = false,
            read_receipts         = false,
            typing_indicator      = false,
            updated_at            = now()
        WHERE user_id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

/// Atomically disable Sanchr Mode and restore default privacy settings.
pub async fn deactivate_sanchr_mode(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserSettingsRow, sqlx::Error> {
    sqlx::query_as::<_, UserSettingsRow>(
        r#"
        UPDATE user_settings SET
            sanchr_mode_enabled     = false,
            screenshot_protection = false,
            show_preview          = true,
            online_status_visible = true,
            read_receipts         = true,
            typing_indicator      = true,
            updated_at            = now()
        WHERE user_id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

/// Notification preference fields.
pub struct NotificationPrefs<'a> {
    pub message_notifications: bool,
    pub group_notifications: bool,
    pub call_notifications: bool,
    pub notification_sound: &'a str,
    pub vibrate: bool,
    pub show_preview: bool,
}

/// Update only notification-related preferences for a user.
pub async fn update_notification_prefs(
    pool: &PgPool,
    user_id: Uuid,
    prefs: &NotificationPrefs<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE user_settings SET
            message_notifications = $2,
            group_notifications   = $3,
            call_notifications    = $4,
            notification_sound    = $5,
            notification_vibrate  = $6,
            show_preview          = $7,
            updated_at            = now()
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .bind(prefs.message_notifications)
    .bind(prefs.group_notifications)
    .bind(prefs.call_notifications)
    .bind(prefs.notification_sound)
    .bind(prefs.vibrate)
    .bind(prefs.show_preview)
    .execute(pool)
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    status_text: Option<&str>,
    profile_key: Option<&[u8]>,
    encrypted_display_name: Option<&[u8]>,
    encrypted_bio: Option<&[u8]>,
    encrypted_avatar_url: Option<&[u8]>,
) -> Result<ProfileInfo, sqlx::Error> {
    sqlx::query_as::<_, ProfileInfo>(
        r#"
        UPDATE users SET
            display_name            = COALESCE($2,  display_name),
            avatar_url              = COALESCE($3,  avatar_url),
            status_text             = COALESCE($4,  status_text),
            profile_key             = COALESCE($5,  profile_key),
            encrypted_display_name  = COALESCE($6,  encrypted_display_name),
            encrypted_bio           = COALESCE($7,  encrypted_bio),
            encrypted_avatar_url    = COALESCE($8,  encrypted_avatar_url),
            updated_at              = now()
        WHERE id = $1
        RETURNING id,
                  display_name,
                  avatar_url,
                  status_text,
                  profile_key,
                  encrypted_display_name,
                  encrypted_bio,
                  encrypted_avatar_url
        "#,
    )
    .bind(user_id)
    .bind(display_name)
    .bind(avatar_url)
    .bind(status_text)
    .bind(profile_key)
    .bind(encrypted_display_name)
    .bind(encrypted_bio)
    .bind(encrypted_avatar_url)
    .fetch_one(pool)
    .await
}

/// Atomically update the registration-lock state.
pub async fn set_registration_lock(
    pool: &PgPool,
    user_id: Uuid,
    enabled: bool,
    pin_hash: Option<&str>,
) -> Result<UserSettingsRow, sqlx::Error> {
    sqlx::query_as::<_, UserSettingsRow>(
        r#"
        UPDATE user_settings SET
            registration_lock_enabled  = $2,
            registration_lock_pin_hash = $3,
            updated_at                 = now()
        WHERE user_id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(enabled)
    .bind(pin_hash)
    .fetch_one(pool)
    .await
}
