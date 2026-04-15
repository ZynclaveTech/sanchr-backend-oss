// Key service load test — upload bundles, get prekeys, upload OTPs
//
// Usage:
//   k6 run loadtests/keys.js

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

// ── Metrics ─────────────────────────────────────────────────────────────────
const uploadBundleDuration = new Trend("keys_upload_bundle_ms", true);
const getPreKeyDuration = new Trend("keys_get_prekey_ms", true);
const uploadOtpKeysDuration = new Trend("keys_upload_otp_ms", true);
const getCountDuration = new Trend("keys_get_count_ms", true);
const getDevicesDuration = new Trend("keys_get_devices_ms", true);

// ── Options ─────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    keys_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "15s", target: 10 },
        { duration: "30s", target: 30 },
        { duration: "30s", target: 50 },
        { duration: "15s", target: 0 },
      ],
    },
  },
  thresholds: {
    grpc_success_rate: ["rate>0.90"],
    keys_upload_bundle_ms: ["p(95)<800"],
    keys_get_prekey_ms: ["p(95)<400"],
    keys_upload_otp_ms: ["p(95)<600"],
    keys_get_count_ms: ["p(95)<200"],
  },
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Generate a fake 32-byte public key as base64. */
function fakeKey32() {
  return randomBytesB64(32);
}

/** Generate a fake 64-byte signature as base64. */
function fakeSig64() {
  return randomBytesB64(64);
}

// ── Init ────────────────────────────────────────────────────────────────────
const client = newClient();

export default function () {
  client.connect(GRPC_ADDR, { plaintext: true });

  // ── Create user ───────────────────────────────────────────────────────────
  const user = createAuthenticatedUser(client);
  if (!user) {
    client.close();
    return;
  }
  const meta = authMeta(user.accessToken);

  // ── Upload key bundle (identity key + signed pre-key + 10 OTP keys) ──────
  const otpKeys = [];
  for (let i = 1; i <= 10; i++) {
    otpKeys.push({ key_id: i, public_key: fakeKey32() });
  }

  let t0 = Date.now();
  const bundleResp = invoke(
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
  uploadBundleDuration.add(Date.now() - t0);
  check(bundleResp, {
    "upload bundle: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Get pre-key count ─────────────────────────────────────────────────────
  t0 = Date.now();
  const countResp = invoke(
    client,
    "sanchr.keys.KeyService/GetPreKeyCount",
    {},
    meta
  );
  getCountDuration.add(Date.now() - t0);
  check(countResp, {
    "prekey count: status OK": (r) => r.status === grpc.StatusOK,
    "prekey count: has count": (r) => r.message && r.message.count >= 0,
  });

  // ── Upload more one-time pre-keys (20 more) ──────────────────────────────
  const moreKeys = [];
  for (let i = 11; i <= 30; i++) {
    moreKeys.push({ key_id: i, public_key: fakeKey32() });
  }

  t0 = Date.now();
  const otpResp = invoke(
    client,
    "sanchr.keys.KeyService/UploadOneTimePreKeys",
    { keys: moreKeys },
    meta
  );
  uploadOtpKeysDuration.add(Date.now() - t0);
  check(otpResp, {
    "upload OTP keys: status OK": (r) => r.status === grpc.StatusOK,
  });

  // ── Get pre-key bundle for this user (from another user's perspective) ───
  const user2 = createAuthenticatedUser(client);
  if (user2) {
    const meta2 = authMeta(user2.accessToken);

    t0 = Date.now();
    const pkResp = invoke(
      client,
      "sanchr.keys.KeyService/GetPreKeyBundle",
      { user_id: user.userId, device_id: user.deviceId },
      meta2
    );
    getPreKeyDuration.add(Date.now() - t0);
    check(pkResp, {
      "get prekey: status OK": (r) => r.status === grpc.StatusOK,
      "get prekey: has identity key": (r) =>
        r.message && r.message.identityPublicKey,
      "get prekey: has signed pre-key": (r) =>
        r.message && r.message.signedPreKey,
    });

    // ── Get user devices ────────────────────────────────────────────────────
    t0 = Date.now();
    const devResp = invoke(
      client,
      "sanchr.keys.KeyService/GetUserDevices",
      { user_id: user.userId },
      meta2
    );
    getDevicesDuration.add(Date.now() - t0);
    check(devResp, {
      "get devices: status OK": (r) => r.status === grpc.StatusOK,
    });
  }

  client.close();
  sleep(1);
}
