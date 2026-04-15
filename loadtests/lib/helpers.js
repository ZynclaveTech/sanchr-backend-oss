// Shared helpers for Sanchr k6 load tests

import { check } from "k6";
import grpc from "k6/net/grpc";
import { Counter, Rate, Trend } from "k6/metrics";
import crypto from "k6/crypto";

// ── Config ──────────────────────────────────────────────────────────────────
export const GRPC_ADDR = __ENV.GRPC_ADDR || "localhost:9090";
export const OTP_SECRET = __ENV.OTP_SECRET;
export const OTP_TTL = parseInt(__ENV.OTP_TTL || "300");

// ── Custom Metrics ──────────────────────────────────────────────────────────
export const grpcErrors = new Counter("grpc_errors");
export const grpcSuccess = new Rate("grpc_success_rate");
export const grpcDuration = new Trend("grpc_duration", true);

// ── gRPC Client Factory ────────────────────────────────────────────────────
// Each VU gets its own client via setup or init. Proto files are loaded once.
const PROTO_DIR = __ENV.PROTO_DIR || "../crates/sanchr-proto/proto";

export function newClient() {
  const client = new grpc.Client();
  client.load(
    [PROTO_DIR],
    "auth.proto",
    "messaging.proto",
    "keys.proto",
    "contacts.proto",
    "vault.proto",
    "settings.proto",
    "calling.proto",
    "notifications.proto",
    "media.proto"
  );
  return client;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Generate a unique phone number per VU + iteration. */
export function uniquePhone() {
  const vu = __VU || 0;
  const iter = __ITER || 0;
  const ts = Date.now() % 1_000_000;
  // +1555VVVIIIRRR — always unique across VUs and iterations
  return `+1555${String(vu).padStart(3, "0")}${String(iter).padStart(3, "0")}${String(ts).padStart(3, "0").slice(-3)}`;
}

/** Random alphanumeric string of given length. */
export function randomStr(len) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

/**
 * Generate random bytes as a base64 string (for protobuf `bytes` fields).
 * k6 gRPC serialises `bytes` from base64, NOT from Uint8Array.
 */
export function randomBytesB64(len) {
  const raw = randomStr(len);
  return _btoa(raw);
}

/** Simple btoa polyfill for k6 (ASCII-only). */
function _btoa(str) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < str.length; i += 3) {
    const a = str.charCodeAt(i);
    const b = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
    const c = i + 2 < str.length ? str.charCodeAt(i + 2) : 0;
    out += chars[(a >> 2) & 0x3f];
    out += chars[((a << 4) | (b >> 4)) & 0x3f];
    out +=
      i + 1 < str.length ? chars[((b << 2) | (c >> 6)) & 0x3f] : "=";
    out += i + 2 < str.length ? chars[c & 0x3f] : "=";
  }
  return out;
}

/** gRPC metadata with Bearer token. */
export function authMeta(token) {
  return {
    metadata: { authorization: `Bearer ${token}` },
  };
}

/**
 * Invoke a gRPC method and record custom metrics.
 * Returns the response object.
 */
export function invoke(client, method, payload, params) {
  const start = Date.now();
  const resp = client.invoke(method, payload, params || {});
  const elapsed = Date.now() - start;

  grpcDuration.add(elapsed);

  const ok = resp.status === grpc.StatusOK;
  grpcSuccess.add(ok ? 1 : 0);
  if (!ok) grpcErrors.add(1);

  return resp;
}

// ── OTP computation (mirrors crates/sanchr-server-crypto/src/otp.rs) ──────────

/**
 * Compute a 6-digit HMAC-SHA256 OTP identical to the server's algorithm.
 *
 * Algorithm:
 *   window  = floor(unix_seconds / ttl)
 *   message = phone + ":" + bigEndianI64(window)
 *   mac     = HMAC-SHA256(secret, message)
 *   offset  = mac[31] & 0x0f
 *   code    = (u32BE(mac[offset..offset+4]) & 0x7fffffff) % 1_000_000
 */
export function computeOtp(phone, unixSeconds) {
  if (!OTP_SECRET) {
    throw new Error(
      "OTP_SECRET must be provided explicitly for load tests; the OSS repo does not ship a default delivery secret"
    );
  }

  const window = Math.floor(unixSeconds / OTP_TTL);

  // Build the message: phone bytes + ":" + big-endian i64 of window
  // k6 crypto.hmac accepts string keys and ArrayBuffer data
  const phoneBytes = stringToBytes(phone);
  const colonBytes = stringToBytes(":");
  const windowBytes = i64ToBigEndian(window);

  const message = concatBuffers(phoneBytes, colonBytes, windowBytes);

  // HMAC-SHA256 → hex string → parse to bytes
  const hexMac = crypto.hmac("sha256", OTP_SECRET, message, "hex");
  const macBytes = hexToBytes(hexMac);

  // Dynamic truncation (RFC 4226 style)
  const offset = macBytes[macBytes.length - 1] & 0x0f;
  const code =
    (((macBytes[offset] & 0x7f) << 24) |
      ((macBytes[offset + 1] & 0xff) << 16) |
      ((macBytes[offset + 2] & 0xff) << 8) |
      (macBytes[offset + 3] & 0xff)) >>>
    0; // unsigned

  return String(code % 1_000_000).padStart(6, "0");
}

function stringToBytes(s) {
  const buf = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
  return buf.buffer;
}

function i64ToBigEndian(n) {
  // JavaScript can't natively handle i64, but our window values are small
  // enough to fit in 32 bits. Fill upper 4 bytes with 0 (or 0xFF if negative).
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  if (n >= 0) {
    view.setUint32(0, 0); // high 32 bits
    view.setUint32(4, n); // low 32 bits
  } else {
    view.setUint32(0, 0xffffffff);
    view.setUint32(4, n >>> 0);
  }
  return buf;
}

function concatBuffers(/* ...ArrayBuffers */) {
  let totalLen = 0;
  for (let i = 0; i < arguments.length; i++) totalLen += arguments[i].byteLength;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (let i = 0; i < arguments.length; i++) {
    result.set(new Uint8Array(arguments[i]), offset);
    offset += arguments[i].byteLength;
  }
  return result.buffer;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Register + verify OTP + login a test user.
 * Returns { accessToken, refreshToken, userId, deviceId, phone }.
 */
export function createAuthenticatedUser(client, phone) {
  const p = phone || uniquePhone();
  const password = "LoadTest1!pass";
  const name = `loaduser_${randomStr(6)}`;

  // 1. Register
  const regResp = invoke(client, "sanchr.auth.AuthService/Register", {
    phone_number: p,
    display_name: name,
    password: password,
    email: "",
  });
  check(regResp, { "register ok": (r) => r.status === grpc.StatusOK });

  // 2. Verify OTP — compute the same HMAC-SHA256 OTP the server generated
  const nowSecs = Math.floor(Date.now() / 1000);
  const otpCode = computeOtp(p, nowSecs);

  const otpResp = invoke(client, "sanchr.auth.AuthService/VerifyOTP", {
    phone_number: p,
    otp_code: otpCode,
    device: { device_name: "k6-loadtest", platform: "linux" },
  });
  check(otpResp, { "verify otp ok": (r) => r.status === grpc.StatusOK });

  if (otpResp.status !== grpc.StatusOK) {
    return null;
  }

  return {
    accessToken: otpResp.message.accessToken,
    refreshToken: otpResp.message.refreshToken,
    userId: otpResp.message.user ? otpResp.message.user.id : "",
    deviceId: otpResp.message.deviceId,
    phone: p,
    password: password,
  };
}
