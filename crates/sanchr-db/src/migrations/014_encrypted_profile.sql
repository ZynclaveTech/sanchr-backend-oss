-- Migration 014: encrypted profile fields
--
-- Adds four nullable BYTEA columns to `users`.  The server stores these
-- as opaque blobs — it never decrypts them.  Clients that have not yet
-- upgraded simply leave all four columns NULL; the plaintext columns
-- (display_name, avatar_url, status_text) remain the authoritative
-- server-side fallback for backwards compatibility.
--
-- profile_key             : 32-byte AES-256-GCM master key (per user)
-- encrypted_display_name  : AES-GCM ciphertext of display_name
-- encrypted_bio           : AES-GCM ciphertext of status_text / bio
-- encrypted_avatar_url    : AES-GCM ciphertext of avatar_url

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS profile_key            BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_display_name BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_bio          BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_avatar_url   BYTEA;
