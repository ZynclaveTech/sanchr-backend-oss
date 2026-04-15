// Contacts, Settings, and Vault load tests
//
// Usage:
//   k6 run loadtests/contacts_settings_vault.js

import grpc from "k6/net/grpc";
import { check, sleep } from "k6";
import { Trend } from "k6/metrics";
import {
  GRPC_ADDR,
  newClient,
  invoke,
  authMeta,
  createAuthenticatedUser,
  randomStr,
  randomBytesB64,
  grpcErrors,
  grpcSuccess,
} from "./lib/helpers.js";

import crypto from "k6/crypto";

// ── Metrics ─────────────────────────────────────────────────────────────────
const syncContactsDuration = new Trend("contacts_sync_ms", true);
const getContactsDuration = new Trend("contacts_get_ms", true);
const blockDuration = new Trend("contacts_block_ms", true);
const getSettingsDuration = new Trend("settings_get_ms", true);
const updateSettingsDuration = new Trend("settings_update_ms", true);
const updateProfileDuration = new Trend("settings_profile_ms", true);
const sanchrModeDuration = new Trend("settings_sanchr_mode_ms", true);
const createVaultDuration = new Trend("vault_create_ms", true);
const getVaultDuration = new Trend("vault_get_ms", true);
const deleteVaultDuration = new Trend("vault_delete_ms", true);

// ── Options ─────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    contacts_settings_vault: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "15s", target: 10 },
        { duration: "45s", target: 30 },
        { duration: "30s", target: 50 },
        { duration: "15s", target: 0 },
      ],
    },
  },
  thresholds: {
    grpc_success_rate: ["rate>0.90"],
    contacts_sync_ms: ["p(95)<600"],
    settings_get_ms: ["p(95)<300"],
    vault_create_ms: ["p(95)<500"],
    vault_get_ms: ["p(95)<400"],
  },
};

// ── Init ────────────────────────────────────────────────────────────────────
const client = newClient();

export default function () {
  client.connect(GRPC_ADDR, { plaintext: true });

  // ── Auth ──────────────────────────────────────────────────────────────────
  const user = createAuthenticatedUser(client);
  if (!user) {
    client.close();
    return;
  }
  const meta = authMeta(user.accessToken);

  // Create a second user (contact target)
  const contact = createAuthenticatedUser(client);

  // ═══════════════════════════════════════════════════════════════════════════
  // CONTACTS
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Sync contacts (with SHA-256 phone hashes) ─────────────────────────────
  // k6 gRPC expects base64-encoded strings for protobuf `bytes` fields
  const phoneHash = crypto.sha256(user.phone, "base64");

  let t0 = Date.now();
  const syncResp = invoke(
    client,
    "sanchr.contacts.ContactService/SyncContacts",
    { phone_hashes: [phoneHash] },
    meta
  );
  syncContactsDuration.add(Date.now() - t0);
  check(syncResp, {
    "sync contacts: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Get contacts ──────────────────────────────────────────────────────────
  t0 = Date.now();
  const getResp = invoke(
    client,
    "sanchr.contacts.ContactService/GetContacts",
    {},
    meta
  );
  getContactsDuration.add(Date.now() - t0);
  check(getResp, {
    "get contacts: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Block + unblock (if contact exists) ───────────────────────────────────
  if (contact) {
    t0 = Date.now();
    const blockResp = invoke(
      client,
      "sanchr.contacts.ContactService/BlockContact",
      { contact_user_id: contact.userId },
      meta
    );
    blockDuration.add(Date.now() - t0);
    check(blockResp, {
      "block: status OK": (r) => r.status === grpc.StatusOK,
    });

    invoke(
      client,
      "sanchr.contacts.ContactService/UnblockContact",
      { contact_user_id: contact.userId },
      meta
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SETTINGS
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Get settings ──────────────────────────────────────────────────────────
  t0 = Date.now();
  const settingsResp = invoke(
    client,
    "sanchr.settings.SettingsService/GetSettings",
    {},
    meta
  );
  getSettingsDuration.add(Date.now() - t0);
  check(settingsResp, {
    "get settings: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Update settings ───────────────────────────────────────────────────────
  t0 = Date.now();
  const updateResp = invoke(
    client,
    "sanchr.settings.SettingsService/UpdateSettings",
    {
      settings: {
        read_receipts: true,
        online_status_visible: false,
        typing_indicator: true,
        theme: "dark",
        font_size: "medium",
      },
    },
    meta
  );
  updateSettingsDuration.add(Date.now() - t0);
  check(updateResp, {
    "update settings: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Update profile ────────────────────────────────────────────────────────
  t0 = Date.now();
  const profileResp = invoke(
    client,
    "sanchr.settings.SettingsService/UpdateProfile",
    {
      display_name: `user_${randomStr(8)}`,
      avatar_url: "",
      status_text: "load testing",
    },
    meta
  );
  updateProfileDuration.add(Date.now() - t0);
  check(profileResp, {
    "update profile: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Toggle Sanchr Mode ──────────────────────────────────────────────────────
  t0 = Date.now();
  const sanchrResp = invoke(
    client,
    "sanchr.settings.SettingsService/ToggleSanchrMode",
    { enabled: true },
    meta
  );
  sanchrModeDuration.add(Date.now() - t0);
  check(sanchrResp, {
    "sanchr mode: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // VAULT
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Create vault item ─────────────────────────────────────────────────────
  const fakeKey = randomBytesB64(32);

  t0 = Date.now();
  const createResp = invoke(
    client,
    "sanchr.vault.VaultService/CreateVaultItem",
    {
      media_type: "photo",
      encrypted_url: `https://s3.example.com/enc/${randomStr(16)}`,
      encrypted_key: fakeKey,
      thumbnail_url: "",
      file_name: `photo_${randomStr(6)}.enc`,
      file_size: 1024 * 512,
      sender_id: "",
      ttl_seconds: 86400,
    },
    meta
  );
  createVaultDuration.add(Date.now() - t0);
  check(createResp, {
    "vault create: status OK": (r) => r.status === grpc.StatusOK,
    "vault create: has item_id": (r) => r.message && r.message.itemId,
  });

  // ── Get vault items ───────────────────────────────────────────────────────
  t0 = Date.now();
  const vaultList = invoke(
    client,
    "sanchr.vault.VaultService/GetVaultItems",
    { filter: "all", limit: 50 },
    meta
  );
  getVaultDuration.add(Date.now() - t0);
  check(vaultList, {
    "vault get: status OK": (r) => r.status === grpc.StatusOK,
    "vault get: has items": (r) =>
      r.message && r.message.items && r.message.items.length > 0,
  });

  // ── Delete vault item ─────────────────────────────────────────────────────
  if (
    createResp.status === grpc.StatusOK &&
    createResp.message &&
    createResp.message.itemId
  ) {
    t0 = Date.now();
    const delResp = invoke(
      client,
      "sanchr.vault.VaultService/DeleteVaultItem",
      { item_id: createResp.message.itemId },
      meta
    );
    deleteVaultDuration.add(Date.now() - t0);
    check(delResp, {
      "vault delete: status OK": (r) => r.status === grpc.StatusOK,
    });
  }

  client.close();
  sleep(1);
}
