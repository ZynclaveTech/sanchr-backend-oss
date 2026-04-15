// Auth service load test — register, OTP verify, login, refresh, logout
//
// Usage:
//   k6 run loadtests/auth.js
//   k6 run loadtests/auth.js --vus 50 --duration 60s

import grpc from "k6/net/grpc";
import { check, sleep } from "k6";
import { Trend } from "k6/metrics";
import {
  GRPC_ADDR,
  newClient,
  invoke,
  authMeta,
  uniquePhone,
  randomStr,
  computeOtp,
  grpcErrors,
  grpcSuccess,
} from "./lib/helpers.js";

// ── Metrics ─────────────────────────────────────────────────────────────────
const registerDuration = new Trend("auth_register_ms", true);
const verifyOtpDuration = new Trend("auth_verify_otp_ms", true);
const loginDuration = new Trend("auth_login_ms", true);
const refreshDuration = new Trend("auth_refresh_ms", true);
const logoutDuration = new Trend("auth_logout_ms", true);

// ── Options ─────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    // Smoke test: 5 VUs for 30s
    smoke: {
      executor: "constant-vus",
      vus: 5,
      duration: "30s",
      tags: { scenario: "smoke" },
    },
    // Ramp-up: 0 → 50 → 100 → 0 VUs
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 50 },
        { duration: "1m", target: 100 },
        { duration: "30s", target: 0 },
      ],
      startTime: "35s",
      tags: { scenario: "ramp" },
    },
  },
  thresholds: {
    grpc_success_rate: ["rate>0.95"],
    // Register and login are slow due to Argon2 password hashing (~1.5-2s).
    // This is the intended security tradeoff — not a performance bug.
    auth_register_ms: ["p(95)<5000"],
    auth_verify_otp_ms: ["p(95)<500"],
    auth_login_ms: ["p(95)<5000"],
    auth_refresh_ms: ["p(95)<200"],
    grpc_errors: ["count<100"],
  },
};

// ── Init ────────────────────────────────────────────────────────────────────
const client = newClient();

// ── Default function (per VU iteration) ─────────────────────────────────────
export default function () {
  client.connect(GRPC_ADDR, { plaintext: true });

  const phone = uniquePhone();
  const password = "LoadTest1!pass";
  const name = `load_${randomStr(6)}`;

  // ── Register ──────────────────────────────────────────────────────────────
  let t0 = Date.now();
  const regResp = invoke(client, "sanchr.auth.AuthService/Register", {
    phone_number: phone,
    display_name: name,
    password: password,
    email: "",
  });
  registerDuration.add(Date.now() - t0);
  check(regResp, {
    "register: status OK": (r) => r.status === grpc.StatusOK,
    "register: has user": (r) => r.message && r.message.user && r.message.user.id !== "",
  });

  if (regResp.status !== grpc.StatusOK) {
    client.close();
    return;
  }

  // ── Verify OTP ────────────────────────────────────────────────────────────
  const nowSecs = Math.floor(Date.now() / 1000);
  const otpCode = computeOtp(phone, nowSecs);

  t0 = Date.now();
  const otpResp = invoke(client, "sanchr.auth.AuthService/VerifyOTP", {
    phone_number: phone,
    otp_code: otpCode,
    device: { device_name: "k6-load", platform: "linux" },
  });
  verifyOtpDuration.add(Date.now() - t0);
  check(otpResp, {
    "verify_otp: status OK": (r) => r.status === grpc.StatusOK,
    "verify_otp: has access_token": (r) =>
      r.message && r.message.accessToken && r.message.accessToken.length > 0,
    "verify_otp: has refresh_token": (r) =>
      r.message && r.message.refreshToken && r.message.refreshToken.length > 0,
  });

  if (otpResp.status !== grpc.StatusOK) {
    client.close();
    return;
  }

  const accessToken = otpResp.message.accessToken;
  const refreshToken = otpResp.message.refreshToken;

  // ── Login (re-auth with password) ─────────────────────────────────────────
  t0 = Date.now();
  const loginResp = invoke(client, "sanchr.auth.AuthService/Login", {
    phone_number: phone,
    password: password,
    device: { device_name: "k6-load-2", platform: "linux" },
  });
  loginDuration.add(Date.now() - t0);
  check(loginResp, {
    "login: status OK": (r) => r.status === grpc.StatusOK,
    "login: has access_token": (r) =>
      r.message && r.message.accessToken && r.message.accessToken.length > 0,
  });

  // ── Refresh Token ─────────────────────────────────────────────────────────
  t0 = Date.now();
  const refreshResp = invoke(client, "sanchr.auth.AuthService/RefreshToken", {
    refresh_token: refreshToken,
  });
  refreshDuration.add(Date.now() - t0);
  check(refreshResp, {
    "refresh: status OK": (r) => r.status === grpc.StatusOK,
    "refresh: rotated token": (r) =>
      r.message && r.message.refreshToken && r.message.refreshToken !== refreshToken,
  });

  // ── Logout ────────────────────────────────────────────────────────────────
  const newRefresh =
    refreshResp.status === grpc.StatusOK
      ? refreshResp.message.refreshToken
      : refreshToken;

  t0 = Date.now();
  const logoutResp = invoke(client, "sanchr.auth.AuthService/Logout", {
    refresh_token: newRefresh,
  });
  logoutDuration.add(Date.now() - t0);
  check(logoutResp, {
    "logout: status OK": (r) => r.status === grpc.StatusOK,
  });

  client.close();
  sleep(0.5);
}
