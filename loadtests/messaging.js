// Messaging service load test — send messages, receipts, conversations
//
// Usage:
//   k6 run loadtests/messaging.js
//   k6 run loadtests/messaging.js --vus 30 --duration 2m

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
const sendMsgDuration = new Trend("msg_send_ms", true);
const receiptDuration = new Trend("msg_receipt_ms", true);
const conversationsDuration = new Trend("msg_conversations_ms", true);
const deleteMsgDuration = new Trend("msg_delete_ms", true);

// ── Options ─────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    messaging_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "20s", target: 20 },
        { duration: "1m", target: 50 },
        { duration: "30s", target: 100 },
        { duration: "20s", target: 0 },
      ],
      tags: { scenario: "messaging_load" },
    },
  },
  thresholds: {
    grpc_success_rate: ["rate>0.90"],
    msg_send_ms: ["p(95)<800"],
    msg_receipt_ms: ["p(95)<300"],
    msg_conversations_ms: ["p(95)<500"],
    grpc_errors: ["count<200"],
  },
};

// ── Init ────────────────────────────────────────────────────────────────────
const client = newClient();

export default function () {
  client.connect(GRPC_ADDR, { plaintext: true });

  // ── Create two authenticated users (sender + recipient) ───────────────────
  const sender = createAuthenticatedUser(client);
  if (!sender) {
    client.close();
    return;
  }

  const recipient = createAuthenticatedUser(client);
  if (!recipient) {
    client.close();
    return;
  }

  const meta = authMeta(sender.accessToken);

  // ── Start direct conversation ──────────────────────────────────────────────
  let t0 = Date.now();
  const startConvResp = invoke(
    client,
    "sanchr.messaging.MessagingService/StartDirectConversation",
    { recipient_id: recipient.userId },
    meta
  );
  conversationsDuration.add(Date.now() - t0);
  check(startConvResp, {
    "start conversation: status OK": (r) => r.status === grpc.StatusOK,
    "start conversation: has id": (r) => r.message && r.message.id,
  });

  if (startConvResp.status !== grpc.StatusOK) {
    client.close();
    return;
  }

  // ── Send messages (5 per iteration) ───────────────────────────────────────
  const conversationId = startConvResp.message.id;
  let lastMsgId = "";

  for (let i = 0; i < 5; i++) {
    const ciphertext = randomBytesB64(64);

    t0 = Date.now();
    const sendResp = invoke(
      client,
      "sanchr.messaging.MessagingService/SendMessage",
      {
        conversation_id: conversationId,
        device_messages: [
          {
            recipient_id: recipient.userId,
            device_id: recipient.deviceId,
            ciphertext: ciphertext,
          },
        ],
        content_type: "text",
        expires_after_secs: 86400,
      },
      meta
    );
    sendMsgDuration.add(Date.now() - t0);
    check(sendResp, {
      "send: status OK": (r) => r.status === grpc.StatusOK,
      "send: has message_id": (r) => r.message && r.message.messageId,
      "send: has timestamp": (r) =>
        r.message && r.message.serverTimestamp > 0,
    });

    if (sendResp.status === grpc.StatusOK) {
      lastMsgId = sendResp.message.messageId;
    }
  }

  // ── Send receipt (delivered) ──────────────────────────────────────────────
  if (lastMsgId) {
    const recipientMeta = authMeta(recipient.accessToken);

    t0 = Date.now();
    const rcptResp = invoke(
      client,
      "sanchr.messaging.MessagingService/SendReceipt",
      {
        conversation_id: conversationId,
        message_id: lastMsgId,
        status: "delivered",
      },
      recipientMeta
    );
    receiptDuration.add(Date.now() - t0);
    check(rcptResp, {
      "receipt: status OK": (r) => r.status === grpc.StatusOK,
    });

    // ── Delete message ──────────────────────────────────────────────────────
    t0 = Date.now();
    const delResp = invoke(
      client,
      "sanchr.messaging.MessagingService/DeleteMessage",
      {
        conversation_id: conversationId,
        message_id: lastMsgId,
      },
      meta
    );
    deleteMsgDuration.add(Date.now() - t0);
    check(delResp, {
      "delete: status OK": (r) => r.status === grpc.StatusOK,
    });
  }

  // ── Re-check conversations after messages ─────────────────────────────────
  t0 = Date.now();
  const convResp2 = invoke(
    client,
    "sanchr.messaging.MessagingService/GetConversations",
    {},
    meta
  );
  conversationsDuration.add(Date.now() - t0);
  check(convResp2, {
    "conversations after: status OK": (r) => r.status === grpc.StatusOK,
  });

  client.close();
  sleep(1);
}
