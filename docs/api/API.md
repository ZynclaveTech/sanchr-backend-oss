# Sanchr gRPC API Reference

Auto-generated from proto files. Run `make docs` to regenerate.

## Services

### auth
```protobuf
service AuthService {
  // Register initiates account creation. Issues an OTP to the provided phone
  // number. If the server has challenge enforcement enabled, a valid
  // ChallengeProof must be included.
  //
  // Rate limit: 5 requests per 15 minutes per phone number.
  // Auth: none required.
  // Errors: INVALID_ARGUMENT (bad phone format), RESOURCE_EXHAUSTED (rate
  //   limited), ALREADY_EXISTS (phone already registered).
  rpc Register(RegisterRequest) returns (AuthResponse);

  // VerifyOTP completes registration by validating the one-time password sent
  // to the user's phone. On success, returns access and refresh tokens.
  //
  // Rate limit: 10 attempts per phone number per OTP issuance.
  // Auth: none required.
  // Errors: INVALID_ARGUMENT (wrong OTP), NOT_FOUND (no pending registration),
  //   RESOURCE_EXHAUSTED (too many attempts), PERMISSION_DENIED (registration
  //   lock active and no valid PIN provided).
  rpc VerifyOTP(VerifyOTPRequest) returns (AuthResponse);

  // Login authenticates a returning user with phone number and password.
  // Returns fresh access and refresh tokens.
  //
  // Rate limit: 10 attempts per 15 minutes per phone number.
  // Auth: none required.
  // Errors: UNAUTHENTICATED (wrong credentials), NOT_FOUND (unknown phone),
  //   PERMISSION_DENIED (registration lock active and no valid PIN provided).
  rpc Login(LoginRequest) returns (AuthResponse);

  // RefreshToken exchanges a valid refresh token for a new access/refresh
  // token pair. The old refresh token is revoked on success.
  //
  // Auth: none required (the refresh token itself is the credential).
  // Errors: UNAUTHENTICATED (expired or revoked token).
  rpc RefreshToken(RefreshTokenRequest) returns (AuthResponse);

  // Logout revokes the given refresh token, ending the session for that
  // device. The access token remains valid until its short TTL expires.
  //
  // Auth: Bearer token required.
  // Errors: UNAUTHENTICATED (invalid token).
  rpc Logout(LogoutRequest) returns (LogoutResponse);

  // DeleteAccount permanently removes the user's account and all associated
  // data (keys, messages, vault items, contacts, backups). This action is
  // irreversible.
  //
  // Auth: Bearer token required.
  // Errors: UNAUTHENTICATED (invalid token).
```

### backup
```protobuf
service BackupService {
  // CreateBackupUpload initiates a new backup by generating a presigned
  // upload URL. The client encrypts the backup locally and PUTs it to
  // the returned URL, then calls CommitBackup to finalize.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (byte_size <= 0), RESOURCE_EXHAUSTED (quota).
  rpc CreateBackupUpload(CreateBackupUploadRequest) returns (CreateBackupUploadResponse);

  // CommitBackup finalizes a backup after the client has successfully
  // uploaded the encrypted blob. The server verifies size and hash match
  // the values from CreateBackupUpload.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown backup_id), FAILED_PRECONDITION (size or
  //   hash mismatch).
  rpc CommitBackup(CommitBackupRequest) returns (CommitBackupResponse);

  // ListBackups returns all committed backups for the authenticated user,
  // ordered by creation time (newest first).
  //
  // Auth: Bearer token required.
  rpc ListBackups(ListBackupsRequest) returns (ListBackupsResponse);

  // GetBackupDownload generates a presigned GET URL for downloading a
  // specific backup blob.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown backup_id).
  rpc GetBackupDownload(GetBackupDownloadRequest) returns (GetBackupDownloadResponse);

  // DeleteBackup permanently removes a backup blob and its metadata. This
  // action is irreversible.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown backup_id).
  rpc DeleteBackup(DeleteBackupRequest) returns (DeleteBackupResponse);
}

// BackupMetadata describes a committed backup.
message BackupMetadata {
  // Server-assigned backup UUID.
  string backup_id = 1;
  // Client-generated lineage identifier. All backups of the same account
  // share a lineage_id, enabling the client to identify the backup chain.
  string lineage_id = 2;
  // Client-defined format version for forward compatibility.
  int32 format_version = 3;
  // Size of the encrypted backup blob in bytes.
  int64 byte_size = 4;
```

### backup_payload
```protobuf
```

### calling
```protobuf
service CallSignalingService {
  // InitiateCall starts a new voice or video call to the specified recipient.
  // The server creates a call record and pushes a CallOfferEvent to the
  // recipient via their MessageStream.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown recipient), PERMISSION_DENIED (blocked),
  //   ALREADY_EXISTS (active call with same recipient).
  rpc InitiateCall(CallOffer) returns (CallResponse);

  // CallStream is a bidirectional streaming RPC for exchanging real-time
  // call signaling data (ICE candidates, SDP answers, call control events).
  // Both caller and callee open a stream for the duration of the call.
  //
  // Auth: Bearer token required.
  rpc CallStream(stream CallSignal) returns (stream CallSignal);

  // EndCall terminates an active call with a specified reason. Triggers
  // a CallLifecycleEvent to all participants.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown call_id).
  rpc EndCall(EndCallRequest) returns (EndCallResponse);

  // GetCallHistory returns the user's recent call log entries, ordered
  // by start time (newest first).
  //
  // Auth: Bearer token required.
  rpc GetCallHistory(GetCallHistoryRequest) returns (GetCallHistoryResponse);

  // GetTurnCredentials returns short-lived TURN server credentials for
  // NAT traversal during calls.
  //
  // Auth: Bearer token required.
  rpc GetTurnCredentials(GetTurnCredentialsRequest) returns (TurnCredentials);
}

// CallOffer initiates a call to a recipient.
message CallOffer {
  // UUID of the recipient (kept for backward compat; unused when
  // delivery_token is set).
  string recipient_id = 1;
  // Call type: "voice" or "video".
  string call_type = 2;
  reserved 3;                 // was sdp_offer -- do not reuse
  reserved "sdp_offer";
  reserved 4;                 // was srtp_key_params -- do not reuse
  reserved "srtp_key_params";
  // Sealed-sender delivery token for anonymous routing.
  bytes delivery_token = 5;
```

### contacts
```protobuf
service ContactService {
  // SyncContacts performs privacy-preserving contact discovery. The client
  // sends truncated SHA-256 hashes of phone numbers from the device's address
  // book; the server returns matching registered users with their profiles.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (empty phone_hashes list).
  rpc SyncContacts(SyncContactsRequest) returns (SyncContactsResponse);

  // GetContacts returns the authenticated user's full contact list, including
  // blocked and favorited status.
  //
  // Auth: Bearer token required.
  rpc GetContacts(GetContactsRequest) returns (GetContactsResponse);

  // BlockContact prevents a user from sending messages, calls, or seeing
  // the blocker's online status. Idempotent: blocking an already-blocked
  // contact is a no-op.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown user).
  rpc BlockContact(BlockContactRequest) returns (BlockContactResponse);

  // UnblockContact reverses a previous block. Idempotent.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown user).
  rpc UnblockContact(UnblockContactRequest) returns (UnblockContactResponse);

  // GetBlockedList returns the UUIDs of all users blocked by the
  // authenticated user.
  //
  // Auth: Bearer token required.
  rpc GetBlockedList(GetBlockedListRequest) returns (GetBlockedListResponse);
}

message SyncContactsRequest {
  // Truncated SHA-256 hashes of E.164 phone numbers from the device address book.
  repeated bytes phone_hashes = 1;
}

message SyncContactsResponse {
  // Registered users whose phone hash matched the input.
  repeated MatchedContact matches = 1;
}

// MatchedContact represents a registered user discovered during contact sync.
message MatchedContact {
  // Server-assigned user UUID.
  string user_id      = 1;
```

### discovery
```protobuf
service DiscoveryService {
  // OprfDiscover performs an OPRF evaluation on blinded phone number points.
  // The client blinds each phone number locally, sends the blinded points,
  // and the server evaluates them with its OPRF key without learning the
  // inputs. The client then unblinds to obtain deterministic tokens for
  // matching against the registered set.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (empty blinded_points list).
  rpc OprfDiscover(OprfDiscoverRequest) returns (OprfDiscoverResponse);

  // GetBloomFilter returns a Bloom filter of all registered phone numbers,
  // parameterized with a daily-rotating salt. Clients can perform local
  // membership tests before issuing OPRF queries, reducing server load.
  //
  // Auth: Bearer token required.
  rpc GetBloomFilter(GetBloomFilterRequest) returns (GetBloomFilterResponse);

  // GetRegisteredSet returns the full set of OPRF-evaluated registered
  // phone tokens. Clients compare their unblinded OPRF outputs against
  // these elements to identify registered contacts.
  //
  // Auth: Bearer token required.
  rpc GetRegisteredSet(GetRegisteredSetRequest) returns (GetRegisteredSetResponse);
}

message OprfDiscoverRequest {
  // Ristretto255 points, each representing a blinded phone number hash.
  repeated bytes blinded_points = 1;
}

message OprfDiscoverResponse {
  // OPRF-evaluated Ristretto255 points, in the same order as the request.
  repeated bytes evaluated_points = 1;
}

message GetBloomFilterRequest {}

// GetBloomFilterResponse contains a probabilistic data structure for fast
// local membership testing of registered phone numbers.
message GetBloomFilterResponse {
  // Raw Bloom filter bit array.
  bytes filter_bits = 1;
  // Number of hash functions used by the filter.
  uint32 num_hashes = 2;
  // Total number of bits in the filter.
  uint64 num_bits = 3;
  // Daily-rotating salt used to compute Bloom filter entries. Clients must
  // use this salt when hashing phone numbers for membership tests.
  bytes daily_salt = 4;
```

### ekf
```protobuf
```

### keys
```protobuf
service KeyService {
  // UploadKeyBundle publishes the device's identity key, signed pre-key,
  // Kyber pre-key, and initial batch of one-time pre-keys. Called once
  // during device registration and when rotating the signed pre-key.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (malformed keys or missing fields).
  rpc UploadKeyBundle(KeyBundle) returns (UploadKeyBundleResponse);

  // GetPreKeyBundle fetches the public key material needed to establish a
  // Signal Protocol session with a specific user device. Consumes one
  // one-time pre-key from the target's pool (if available).
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown user or device).
  rpc GetPreKeyBundle(GetPreKeyBundleRequest) returns (PreKeyBundleResponse);

  // UploadOneTimePreKeys replenishes the device's one-time pre-key pool on
  // the server. Called when the client receives a PreKeyCountLow warning.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (empty keys list or duplicate key IDs).
  rpc UploadOneTimePreKeys(UploadOneTimePreKeysRequest) returns (PreKeyCountResponse);

  // GetPreKeyCount returns the number of remaining one-time pre-keys stored
  // on the server for the authenticated device.
  //
  // Auth: Bearer token required.
  rpc GetPreKeyCount(GetPreKeyCountRequest) returns (PreKeyCountResponse);

  // GetUserDevices lists all registered devices for a given user, including
  // platform, key capability, and last-active timestamps.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown user).
  rpc GetUserDevices(GetUserDevicesRequest) returns (GetUserDevicesResponse);

  // RemoveDevice unregisters a device from the authenticated user's account
  // and deletes its key material from the server.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown device), PERMISSION_DENIED (device belongs
  //   to another user).
  rpc RemoveDevice(RemoveDeviceRequest) returns (RemoveDeviceResponse);
}

// SignedPreKey is a Curve25519 pre-key signed by the device's identity key.
message SignedPreKey {
  // Monotonically increasing key identifier.
  int32 key_id = 1;
```

### media
```protobuf
service MediaService {
  // GetUploadUrl generates a presigned PUT URL for uploading an encrypted
  // media blob to object storage. The returned media_id must be confirmed
  // via ConfirmUpload after the PUT succeeds.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (file_size <= 0 or unsupported content_type),
  //   RESOURCE_EXHAUSTED (storage quota exceeded).
  rpc GetUploadUrl(GetUploadUrlRequest) returns (PresignedUrlResponse);

  // GetDownloadUrl generates a presigned GET URL for downloading a
  // previously uploaded media blob.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown media_id), PERMISSION_DENIED (not owner or
  //   recipient).
  rpc GetDownloadUrl(GetDownloadUrlRequest) returns (PresignedUrlResponse);

  // ConfirmUpload marks a media upload as complete. Must be called after
  // the client successfully PUTs the blob to the presigned URL. Until
  // confirmed, the media object is invisible to other RPCs and subject to
  // garbage collection.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown media_id), FAILED_PRECONDITION (size mismatch
  //   with GetUploadUrl).
  rpc ConfirmUpload(ConfirmUploadRequest) returns (ConfirmUploadResponse);
}

// MediaPurpose controls ACL and storage path for uploaded media.
enum MediaPurpose {
  // E2EE message attachment (private, presigned access).
  MEDIA_PURPOSE_ATTACHMENT = 0;
  // Profile avatar (public-read via CDN).
  MEDIA_PURPOSE_AVATAR = 1;
}

message GetUploadUrlRequest {
  // Size of the encrypted blob in bytes.
  int64 file_size = 1;
  // MIME type of the encrypted content (e.g., "image/jpeg", "video/mp4").
  string content_type = 2;
  // SHA-256 hash of the encrypted blob, hex-encoded. Used for server-side
  // deduplication.
  string sha256_hash = 3;
  // Controls ACL and storage path.
  MediaPurpose purpose = 4;
}

message GetDownloadUrlRequest {
```

### messaging
```protobuf
service MessagingService {
  // SendMessage delivers an end-to-end encrypted message to all devices in a
  // conversation. The client encrypts separately for each recipient device
  // using Signal Protocol sessions.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown conversation), INVALID_ARGUMENT (empty
  //   device_messages), PERMISSION_DENIED (not a conversation participant).
  rpc SendMessage(SendMessageRequest) returns (SendMessageResponse);

  // StartDirectConversation creates or returns the existing 1:1 conversation
  // with the specified recipient.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown recipient), PERMISSION_DENIED (blocked).
  rpc StartDirectConversation(StartDirectConversationRequest) returns (Conversation);

  // MessageStream is the primary bidirectional streaming RPC. The client
  // sends typing indicators and call event acks; the server pushes encrypted
  // messages, receipts, call events, reactions, and pre-key warnings.
  // The stream stays open for the lifetime of the client session.
  //
  // Auth: Bearer token required (validated once at stream open).
  // Errors: UNAUTHENTICATED (invalid token at connect time).
  rpc MessageStream(stream ClientEvent) returns (stream ServerEvent);

  // SyncMessages returns all unacknowledged encrypted envelopes queued since
  // the given timestamp. Used on reconnect or cold start.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (future timestamp).
  rpc SyncMessages(SyncRequest) returns (stream EncryptedEnvelope);

  // AckMessages acknowledges receipt of one or more messages so the server
  // can remove them from the delivery queue.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (empty list).
  rpc AckMessages(AckMessagesRequest) returns (AckMessagesResponse);

  // DeleteMessage removes a message from the server. The sender can delete
  // their own messages; recipients can delete for themselves only.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown message), PERMISSION_DENIED (not sender/participant).
  rpc DeleteMessage(DeleteMessageRequest) returns (DeleteMessageResponse);

  // EditMessage replaces the ciphertext of a previously sent message. Only
  // the original sender may edit. Generates a MessageEdited server event for
  // all other participants.
```

### notifications
```protobuf
service NotificationService {
  // RegisterPushToken registers or updates the device's push notification
  // token. Called on app startup and whenever the OS rotates the token.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (empty token or unsupported platform).
  rpc RegisterPushToken(RegisterPushTokenRequest) returns (RegisterPushTokenResponse);

  // UpdateNotificationPrefs updates the user's global notification
  // preferences (message, group, call toggles, sound, vibration, preview).
  //
  // Auth: Bearer token required.
  rpc UpdateNotificationPrefs(UpdateNotificationPrefsRequest) returns (UpdateNotificationPrefsResponse);

  // SetConversationNotificationPrefs mutes or unmutes push notifications
  // for a specific conversation.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown conversation_id).
  rpc SetConversationNotificationPrefs(SetConversationNotificationPrefsRequest) returns (SetConversationNotificationPrefsResponse);
}

message RegisterPushTokenRequest {
  // Platform-specific push token (APNs device token or FCM registration token).
  string token = 1;
  // Platform identifier: "ios" or "android".
  string platform = 2;
  // VoIP PushKit token (iOS only; empty on other platforms).
  string voip_token = 3;
}

message RegisterPushTokenResponse {}

// UpdateNotificationPrefsRequest sets global notification toggles.
message UpdateNotificationPrefsRequest {
  // Enable direct message notifications.
  bool message_notifications = 1;
  // Enable group message notifications.
  bool group_notifications = 2;
  // Enable incoming call notifications.
  bool call_notifications = 3;
  // Notification sound name (platform-specific).
  string notification_sound = 4;
  // Enable vibration on notification.
  bool vibrate = 5;
  // Show message preview in the notification banner.
  bool show_preview = 6;
}

message UpdateNotificationPrefsResponse {}
```

### sealed_sender
```protobuf
```

### settings
```protobuf
service SettingsService {
  // GetSettings returns the authenticated user's current preferences.
  //
  // Auth: Bearer token required.
  rpc GetSettings(GetSettingsRequest) returns (UserSettings);

  // UpdateSettings replaces the user's preferences with the provided values.
  // All fields in the UserSettings message are overwritten; omitted fields
  // revert to their proto default values.
  //
  // Auth: Bearer token required.
  rpc UpdateSettings(UpdateSettingsRequest) returns (UserSettings);

  // UpdateProfile updates the user's public-facing profile (display name,
  // avatar, status text) and encrypted profile fields.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (display_name empty or > 128 chars).
  rpc UpdateProfile(UpdateProfileRequest) returns (ProfileResponse);

  // ToggleSanchrMode enables or disables Sanchr privacy mode. When enabled,
  // additional privacy protections are applied (e.g., screenshot blocking,
  // hidden message previews).
  //
  // Auth: Bearer token required.
  rpc ToggleSanchrMode(ToggleSanchrModeRequest) returns (UserSettings);

  // GetStorageUsage returns a breakdown of the user's server-side storage
  // consumption by media type and the account's storage limit.
  //
  // Auth: Bearer token required.
  rpc GetStorageUsage(GetStorageUsageRequest) returns (StorageUsageResponse);

  // SetRegistrationLock enables or disables registration lock. When enabled,
  // re-registration on a new device requires a PIN in addition to OTP
  // verification.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (PIN too short when enabling).
  rpc SetRegistrationLock(SetRegistrationLockRequest) returns (SetRegistrationLockResponse);
}

message GetSettingsRequest {}

// UserSettings holds the full set of user preferences.
message UserSettings {
  // Whether read receipts are sent to other users.
  bool read_receipts = 1;
  // Whether online status is visible to contacts.
  bool online_status_visible = 2;
```

### vault
```protobuf
service VaultService {
  // CreateVaultItem registers a new vault entry backed by an already-uploaded
  // media object. The server stores only the encrypted metadata blob and a
  // reference to the media object; it never sees plaintext content.
  //
  // Auth: Bearer token required.
  // Errors: INVALID_ARGUMENT (encrypted_metadata > 64 KiB, missing media_id),
  //   NOT_FOUND (unknown media_id), PERMISSION_DENIED (media not owned by caller).
  rpc CreateVaultItem(CreateVaultItemRequest) returns (VaultItem);

  // GetVaultItems returns a paginated list of the authenticated user's vault
  // items, ordered by creation time (newest first).
  //
  // Auth: Bearer token required.
  rpc GetVaultItems(GetVaultItemsRequest) returns (GetVaultItemsResponse);

  // GetVaultItem returns a single vault item by its ID.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown vault_item_id), PERMISSION_DENIED (not owner).
  rpc GetVaultItem(GetVaultItemRequest) returns (VaultItem);

  // DeleteVaultItem permanently removes a vault item and its associated
  // media object from storage.
  //
  // Auth: Bearer token required.
  // Errors: NOT_FOUND (unknown vault_item_id), PERMISSION_DENIED (not owner).
  rpc DeleteVaultItem(DeleteVaultItemRequest) returns (DeleteVaultItemResponse);
}

message CreateVaultItemRequest {
  reserved 5, 6, 7, 8;
  reserved "media_type", "encrypted_url", "encrypted_key", "thumbnail_url",
           "file_name", "file_size", "sender_id", "ttl_seconds";

  // Client-generated UUIDv4 for idempotent crash recovery. Server uses this
  // as the primary key; retries with the same ID are a no-op that return
  // the existing row.
  string vault_item_id = 1;

  // UUID of an already-uploaded media object (via MediaService.GetUploadUrl +
  // ConfirmUpload). The caller MUST own this media_id or the request is rejected.
  string media_id = 2;

  // Opaque AES-GCM ciphertext of the metadata envelope, keyed client-side
  // with AccessK_vault. Contains name, mime type, size, thumbnail, sender
  // id, etc. Server treats this as an opaque byte string. Max 64 KiB;
  // exceeding this returns INVALID_ARGUMENT.
  bytes encrypted_metadata = 3;

```

