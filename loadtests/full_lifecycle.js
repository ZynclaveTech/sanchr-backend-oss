// Full user lifecycle load test — simulates a realistic user session:
//   Register → OTP → Upload keys → Update profile → Send messages →
//   Receipts → Vault upload → Settings → Logout
//
// This test exercises all services in a single flow, measuring end-to-end
// latency and throughput under realistic usage patterns.
//
// Usage:
//   k6 run loadtests/full_lifecycle.js
//   k6 run loadtests/full_lifecycle.js --vus 20 --duration 3m

import grpc from "k6/net/grpc";
import { check, sleep } from "k6";
import { Trend, Counter } from "k6/metrics";
import {
  GRPC_ADDR,
  newClient,
  invoke,
  authMeta,
  uniquePhone,
  randomStr,
  randomBytesB64,
  computeOtp,
  grpcErrors,
  grpcSuccess,
} from "./lib/helpers.js";

// ── Metrics ─────────────────────────────────────────────────────────────────
const lifecycleDuration = new Trend("lifecycle_total_ms", true);
const lifecycleComplete = new Counter("lifecycle_complete");
const lifecycleFailed = new Counter("lifecycle_failed");

// ── Options ─────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    // Soak test: steady load over time
    soak: {
      executor: "constant-arrival-rate",
      rate: 10, // 10 iterations/sec
      timeUnit: "1s",
      duration: "2m",
      preAllocatedVUs: 50,
      maxVUs: 200,
      tags: { scenario: "soak" },
    },
    // Spike test: sudden burst
    spike: {
      executor: "ramping-arrival-rate",
      startRate: 5,
      timeUnit: "1s",
      stages: [
        { duration: "10s", target: 5 },
        { duration: "10s", target: 50 }, // spike
        { duration: "30s", target: 50 },
        { duration: "10s", target: 5 }, // recover
      ],
      preAllocatedVUs: 100,
      maxVUs: 300,
      startTime: "2m30s",
      tags: { scenario: "spike" },
    },
  },
  thresholds: {
    grpc_success_rate: ["rate>0.85"],
    lifecycle_total_ms: ["p(95)<5000", "p(99)<8000"],
    lifecycle_complete: ["count>50"],
  },
};

// ── Init ────────────────────────────────────────────────────────────────────
const client = newClient();

// ── Helpers ─────────────────────────────────────────────────────────────────
function fakeKey32() {
  return randomBytesB64(32);
}

function fakeSig64() {
  return randomBytesB64(64);
}

// ── Default function ────────────────────────────────────────────────────────
export default function () {
  const t0 = Date.now();
  client.connect(GRPC_ADDR, { plaintext: true });

  const phone = uniquePhone();
  const password = "LoadTest1!pass";
  const name = `lifecycle_${randomStr(6)}`;

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. REGISTER
  // ═══════════════════════════════════════════════════════════════════════════
  const regResp = invoke(client, "sanchr.auth.AuthService/Register", {
    phone_number: phone,
    display_name: name,
    password: password,
    email: "",
  });
  if (regResp.status !== grpc.StatusOK) {
    lifecycleFailed.add(1);
    client.close();
    return;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. VERIFY OTP
  // ═══════════════════════════════════════════════════════════════════════════
  const nowSecs = Math.floor(Date.now() / 1000);
  const otpCode = computeOtp(phone, nowSecs);
  const otpResp = invoke(client, "sanchr.auth.AuthService/VerifyOTP", {
    phone_number: phone,
    otp_code: otpCode,
    device: { device_name: "k6-lifecycle", platform: "ios" },
  });
  if (otpResp.status !== grpc.StatusOK) {
    lifecycleFailed.add(1);
    client.close();
    return;
  }

  const accessToken = otpResp.message.accessToken;
  const refreshToken = otpResp.message.refreshToken;
  const userId = otpResp.message.user ? otpResp.message.user.id : "";
  const deviceId = otpResp.message.deviceId;
  const meta = authMeta(accessToken);

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. UPLOAD KEY BUNDLE (Signal protocol setup)
  // ═══════════════════════════════════════════════════════════════════════════
  const otpKeys = [];
  for (let i = 1; i <= 20; i++) {
    otpKeys.push({ key_id: i, public_key: fakeKey32() });
  }

  invoke(
    client,
    "sanchr.keys.KeyService/UploadKeyBundle",
    {
      identity_public_key: fakeKey32(),
      signed_pre_key: {
        key_id: 1,
        public_key: fakeKey32(),
        signature: fakeSig64(),
      },
      one_time_pre_keys: otpKeys,
    },
    meta
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. UPDATE PROFILE + SETTINGS
  // ═══════════════════════════════════════════════════════════════════════════
  invoke(
    client,
    "sanchr.settings.SettingsService/UpdateProfile",
    {
      display_name: `User ${randomStr(4)}`,
      avatar_url: "",
      status_text: "Just vibing",
    },
    meta
  );

  invoke(
    client,
    "sanchr.settings.SettingsService/UpdateSettings",
    {
      settings: {
        read_receipts: true,
        online_status_visible: true,
        typing_indicator: true,
        theme: "dark",
        font_size: "medium",
        message_notifications: true,
        call_notifications: true,
      },
    },
    meta
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. CREATE A SECOND USER + SEND MESSAGES
  // ═══════════════════════════════════════════════════════════════════════════
  const phone2 = uniquePhone();
  const regResp2 = invoke(client, "sanchr.auth.AuthService/Register", {
    phone_number: phone2,
    display_name: `peer_${randomStr(6)}`,
    password: password,
    email: "",
  });

  if (regResp2.status === grpc.StatusOK) {
    const otpCode2 = computeOtp(phone2, Math.floor(Date.now() / 1000));
    const otpResp2 = invoke(client, "sanchr.auth.AuthService/VerifyOTP", {
      phone_number: phone2,
      otp_code: otpCode2,
      device: { device_name: "k6-peer", platform: "android" },
    });

    if (otpResp2.status === grpc.StatusOK) {
      const peer = {
        accessToken: otpResp2.message.accessToken,
        userId: otpResp2.message.user ? otpResp2.message.user.id : "",
        deviceId: otpResp2.message.deviceId,
      };

      // Create conversation first
      const convResp = invoke(
        client,
        "sanchr.messaging.MessagingService/StartDirectConversation",
        { recipient_id: peer.userId },
        meta
      );
      const conversationId =
        convResp.status === grpc.StatusOK && convResp.message
          ? convResp.message.id
          : "";

      // Send 3 messages
      let lastMsgId = "";
      for (let i = 0; i < 3; i++) {
        const ciphertext = randomBytesB64(128);
        const sendResp = invoke(
          client,
          "sanchr.messaging.MessagingService/SendMessage",
          {
            conversation_id: conversationId,
            device_messages: [
              {
                recipient_id: peer.userId,
                device_id: peer.deviceId,
                ciphertext: ciphertext,
              },
            ],
            content_type: "text",
            expires_after_secs: 86400,
          },
          meta
        );
        if (sendResp.status === grpc.StatusOK) {
          lastMsgId = sendResp.message.messageId;
        }
      }

      // Peer sends receipt
      if (lastMsgId) {
        invoke(
          client,
          "sanchr.messaging.MessagingService/SendReceipt",
          {
            conversation_id: conversationId,
            message_id: lastMsgId,
            status: "read",
          },
          authMeta(peer.accessToken)
        );
      }

      // Get conversations
      invoke(
        client,
        "sanchr.messaging.MessagingService/GetConversations",
        {},
        meta
      );
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. VAULT — upload + list + delete
  // ═══════════════════════════════════════════════════════════════════════════
  const vaultResp = invoke(
    client,
    "sanchr.vault.VaultService/CreateVaultItem",
    {
      media_type: "photo",
      encrypted_url: `https://s3.example.com/${randomStr(20)}`,
      encrypted_key: fakeKey32(),
      thumbnail_url: "",
      file_name: `img_${randomStr(8)}.enc`,
      file_size: 2048000,
      sender_id: "",
      ttl_seconds: 86400 * 7,
    },
    meta
  );

  invoke(
    client,
    "sanchr.vault.VaultService/GetVaultItems",
    { filter: "all", limit: 20 },
    meta
  );

  if (vaultResp.status === grpc.StatusOK && vaultResp.message && vaultResp.message.itemId) {
    invoke(
      client,
      "sanchr.vault.VaultService/DeleteVaultItem",
      { item_id: vaultResp.message.itemId },
      meta
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. TOGGLE SANCHR MODE
  // ═══════════════════════════════════════════════════════════════════════════
  invoke(
    client,
    "sanchr.settings.SettingsService/ToggleSanchrMode",
    { enabled: true },
    meta
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. REFRESH TOKEN
  // ═══════════════════════════════════════════════════════════════════════════
  const refreshResp = invoke(client, "sanchr.auth.AuthService/RefreshToken", {
    refresh_token: refreshToken,
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. LOGOUT
  // ═══════════════════════════════════════════════════════════════════════════
  const finalRefresh =
    refreshResp.status === grpc.StatusOK
      ? refreshResp.message.refreshToken
      : refreshToken;

  invoke(client, "sanchr.auth.AuthService/Logout", {
    refresh_token: finalRefresh,
  });

  // ── Record lifecycle ──────────────────────────────────────────────────────
  const elapsed = Date.now() - t0;
  lifecycleDuration.add(elapsed);
  lifecycleComplete.add(1);

  client.close();
  sleep(0.5);
}
