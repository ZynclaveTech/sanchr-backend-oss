use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// UserId
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for UserId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<UserId> for Uuid {
    fn from(id: UserId) -> Self {
        id.0
    }
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub i32);

impl DeviceId {
    pub fn inner(&self) -> i32 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i32> for DeviceId {
    fn from(id: i32) -> Self {
        Self(id)
    }
}

impl From<DeviceId> for i32 {
    fn from(id: DeviceId) -> Self {
        id.0
    }
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }
}

impl FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ios" => Ok(Platform::Ios),
            "android" => Ok(Platform::Android),
            other => Err(format!("unknown platform: {other}")),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // UserId
    // -----------------------------------------------------------------------

    #[test]
    fn user_id_roundtrip() {
        let uuid = Uuid::new_v4();
        let uid = UserId::from(uuid);
        let back: Uuid = uid.into();
        assert_eq!(uuid, back);
    }

    #[test]
    fn user_id_display() {
        let uuid = Uuid::new_v4();
        let uid = UserId(uuid);
        assert_eq!(uid.to_string(), uuid.to_string());
    }

    #[test]
    fn user_id_equality() {
        let uuid = Uuid::new_v4();
        let a = UserId(uuid);
        let b = UserId(uuid);
        assert_eq!(a, b);
    }

    #[test]
    fn user_id_new_is_unique() {
        let a = UserId::new();
        let b = UserId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn user_id_inner() {
        let uuid = Uuid::new_v4();
        let uid = UserId(uuid);
        assert_eq!(uid.inner(), uuid);
    }

    #[test]
    fn user_id_default_is_valid_uuid() {
        let uid = UserId::default();
        // default() calls new() which produces a v4 UUID; just ensure it isn't nil.
        assert_ne!(uid.inner(), Uuid::nil());
    }

    #[test]
    fn user_id_serde_roundtrip() {
        let uid = UserId::new();
        let json = serde_json::to_string(&uid).unwrap();
        let back: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(uid, back);
    }

    // -----------------------------------------------------------------------
    // DeviceId
    // -----------------------------------------------------------------------

    #[test]
    fn device_id_roundtrip() {
        let did = DeviceId::from(42);
        let back: i32 = did.into();
        assert_eq!(42, back);
    }

    #[test]
    fn device_id_inner() {
        let did = DeviceId(7);
        assert_eq!(did.inner(), 7);
    }

    #[test]
    fn device_id_display() {
        let did = DeviceId(99);
        assert_eq!(did.to_string(), "99");
    }

    #[test]
    fn device_id_equality() {
        let a = DeviceId(1);
        let b = DeviceId(1);
        let c = DeviceId(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn device_id_negative_value() {
        let did = DeviceId::from(-1);
        let back: i32 = did.into();
        assert_eq!(-1, back);
    }

    // -----------------------------------------------------------------------
    // Platform
    // -----------------------------------------------------------------------

    #[test]
    fn platform_from_str_lowercase() {
        assert_eq!(Platform::from_str("ios").unwrap(), Platform::Ios);
        assert_eq!(Platform::from_str("android").unwrap(), Platform::Android);
    }

    #[test]
    fn platform_from_str_uppercase() {
        assert_eq!(Platform::from_str("IOS").unwrap(), Platform::Ios);
        assert_eq!(Platform::from_str("ANDROID").unwrap(), Platform::Android);
    }

    #[test]
    fn platform_from_str_mixed_case() {
        assert_eq!(Platform::from_str("Ios").unwrap(), Platform::Ios);
        assert_eq!(Platform::from_str("Android").unwrap(), Platform::Android);
    }

    #[test]
    fn platform_from_str_unknown_returns_err() {
        assert!(Platform::from_str("windows").is_err());
        assert!(Platform::from_str("").is_err());
        assert!(Platform::from_str("web").is_err());
    }

    #[test]
    fn platform_as_str() {
        assert_eq!(Platform::Ios.as_str(), "ios");
        assert_eq!(Platform::Android.as_str(), "android");
    }

    #[test]
    fn platform_display() {
        assert_eq!(Platform::Ios.to_string(), "ios");
        assert_eq!(Platform::Android.to_string(), "android");
    }

    #[test]
    fn platform_serde_roundtrip() {
        let json = serde_json::to_string(&Platform::Ios).unwrap();
        assert_eq!(json, "\"ios\"");
        let back: Platform = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Platform::Ios);
    }

    #[test]
    fn platform_android_serde_roundtrip() {
        let json = serde_json::to_string(&Platform::Android).unwrap();
        assert_eq!(json, "\"android\"");
        let back: Platform = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Platform::Android);
    }

    #[test]
    fn platform_equality() {
        assert_eq!(Platform::Ios, Platform::Ios);
        assert_eq!(Platform::Android, Platform::Android);
        assert_ne!(Platform::Ios, Platform::Android);
    }
}
