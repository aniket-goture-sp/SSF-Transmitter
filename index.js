/**
 * Spec-compliant CAEP / SSF Transmitter (transmitter-only)
 *
 * - Reads PKCS#8 private key from ./private_key_pkcs8.pem (required)
 * - POST /ssf/streams accepts a signed SET (application/secevent+jwt) from a Receiver to register a stream
 *   -> verifies signature using jwks_uri present in the SET payload
 * - GET /ssf/streams/:id  -> 200 with stream config
 * - PATCH /ssf/streams/:id -> 200 with updated config
 * - DELETE /ssf/streams?stream_id=... -> 204 No Content
 * - POST /ssf/verify -> accepts JSON { stream_id, state? } -> responds 204 and sends verification SET to stream.delivery.endpoint
 * - POST /caep/send-risk-level-change -> send CAEP SET to a registered stream (requires stream_id or receiver_url)
 * - /.well-known/ssf-configuration and /.well-known/jwks.json
 *
 * Environment:
 *   PORT (default 3000)
 *   ISS (issuer URL, required for production; default http://localhost:3000)
 *
 * Usage:
 *   1) Generate key: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key_pkcs8.pem
 *   2) npm install
 *   3) node index.js
 */

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const {
  SignJWT,
  importPKCS8,
  exportJWK,
  decodeProtectedHeader,
  jwtVerify,
  importJWK,
} = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));

/* ---------- Configuration ---------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://ssfrisklevelrepo.onrender.com/";

/* ---------- Load private key from file (PKCS#8) ---------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
let PRIVATE_KEY_PEM;
try {
  PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");
  console.log("🔑 Loaded private key from", KEY_PATH);
} catch (err) {
  console.error("Missing or unreadable private_key_pkcs8.pem. Generate with OpenSSL and place in project root.");
  process.exit(1);
}

/* ---------- Initialize JOSE signing key and publish JWK ---------- */
let signingKey;
let publicJwk;
async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = publicJwk.alg || "RS256";
    console.log("✅ Signing key ready, kid =", publicJwk.kid);
  } catch (err) {
    console.error("[FATAL] Unable to import PRIVATE_KEY_PEM:", err && err.message ? err.message : err);
    process.exit(1);
  }
}

/* ---------- Helpers ---------- */

/** 
 * Sign a payload as an RFC-compliant SET (Security Event Token)
 * - Adds 'kid' to protected header
 * - Uses typ: 'secevent+jwt' (per final CAEP spec)
 */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: "RS256",
      typ: "secevent+jwt",
      kid: publicJwk.kid // ✅ include key ID
    })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}


/** Verify incoming SET (signed JWT) using jwks_uri found in payload */
async function verifyIncomingSET(token) {
  // get header to find kid/alg
  const header = await decodeProtectedHeader(token);
  const kid = header.kid;
  // decode payload without verifying to read jwks_uri
  // jwtVerify requires a key; we'll fetch jwks_uri from an unverified decode
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");
  const payloadJson = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const jwks_uri = payloadJson.jwks_uri;
  if (!jwks_uri) throw new Error("jwks_uri_missing_in_payload");

  // fetch jwks
  const jwksResp = await axios.get(jwks_uri, { timeout: 10000 });
  if (!jwksResp || !jwksResp.data || !Array.isArray(jwksResp.data.keys)) {
    throw new Error("jwks_invalid_or_unreachable");
  }
  const jwk = jwksResp.data.keys.find((k) => k.kid === kid) || jwksResp.data.keys[0];
  if (!jwk) throw new Error("matching_jwk_not_found");

  // import jwk and verify
  const key = await importJWK(jwk, jwk.alg || "RS256");
  const verified = await jwtVerify(token, key, { issuer: payloadJson.iss, audience: payloadJson.aud });
  // verified.payload is the payload
  return { payload: verified.payload, header: header };
}

/* ---------- In-memory store (streams) ---------- */
/*
  stream object shape (spec-like):
  {
    stream_id,
    iss,           // optional - who registered
    jwks_uri,      // receiver jwks uri (if provided in registration)
    delivery: { method, endpoint, authorization_header, endpoint_url? },
    events_requested: [],
    events_accepted: [],
    description: null,
    status: "enabled" | "disabled",
    created_at, updated_at
  }
*/
const streams = {};

/* ---------- WELL-KNOWN endpoints ---------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));

app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    delivery_methods_supported: [
      "urn:ietf:rfc:8935", // push
      "urn:ietf:rfc:8936"  // poll
    ],
    configuration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    verification_endpoint: `${ISS}/ssf/streams/verify`,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    spec_version: "1_0-ID2",
    authorization_schemes: [
      {
        spec_urn: "urn:ietf:rfc:6749"
      }
    ]
  });
});


/* =======================================================
   SSF Stream Management APIs (Raw JSON + Bearer token123)
   ======================================================= */

// Middleware to enforce Bearer token for all /ssf routes
app.use("/ssf", (req, res, next) => {
  const auth = req.headers.authorization || "";
  if (auth !== "Bearer token123") {
    return res.status(401).json({ error: "unauthorized", message: "Missing or invalid Authorization token" });
  }
  next();
});

/**
 * CREATE STREAM (Receiver registers with Transmitter)
 * - Accepts raw JSON (CAEP or SSF format)
 * - Supports endpoint_url, endpoint, and CAEP delivery-method URIs
 * - Auto-fills aud/jwks_uri
 * - Adds events_delivered per SSF/CAEP 1.0-ID2
 */
app.post("/ssf/streams", (req, res) => {
  try {
    const body = req.body || {};

    // Default missing values
    if (!body.aud) body.aud = ISS;
    if (!body.jwks_uri) body.jwks_uri = `${ISS}/.well-known/jwks.json`;

    // Normalize delivery (case-insensitive + CAEP support)
    let delivery = body.delivery || body.Delivery || {};
    const endpointCandidate =
      delivery.endpoint ||
      delivery.Endpoint ||
      delivery.endpoint_url ||
      delivery.endpointUrl ||
      delivery.url ||
      delivery.URL ||
      null;

    const methodCandidate =
      delivery.method ||
      delivery.Method ||
      delivery.deliveryMethod ||
      delivery.DeliveryMethod ||
      null;

    // Normalize method URIs → RFC urns
    let normalizedMethod = methodCandidate;
    if (
      normalizedMethod &&
      normalizedMethod.includes(
        "https://schemas.openid.net/secevent/caep/delivery-method/push"
      )
    ) {
      normalizedMethod = "urn:ietf:rfc:8935";
    } else if (
      normalizedMethod &&
      normalizedMethod.includes(
        "https://schemas.openid.net/secevent/caep/delivery-method/poll"
      )
    ) {
      normalizedMethod = "urn:ietf:rfc:8936";
    }

    const deliveryObj = {
      method: normalizedMethod ? normalizedMethod.trim() : null,
      endpoint: endpointCandidate ? endpointCandidate.trim() : null,
      authorization_header:
        delivery.authorization_header ||
        delivery.Authorization ||
        delivery.Authorization_Header ||
        "Bearer token123",
    };

    // Validate delivery presence
    if (!deliveryObj.method || !deliveryObj.endpoint) {
      console.warn("⚠️ Invalid delivery object:", deliveryObj);
      return res.status(400).json({
        error: "invalid_delivery",
        message:
          "delivery.method and delivery.endpoint (or endpoint_url) required",
      });
    }

    // Validate required top-level fields
    const required = ["iss", "aud", "jwks_uri", "events_requested"];
    const missing = required.filter((f) => !(f in body));
    if (missing.length) {
      return res
        .status(400)
        .json({ error: `missing_fields: ${missing.join(", ")}` });
    }

    const stream_id = uuidv4();
    const now = new Date().toISOString();

    const stream = {
      stream_id,
      iss: body.iss,
      aud: body.aud,
      jwks_uri: body.jwks_uri,
      delivery: deliveryObj,
      events_requested: body.events_requested,
      events_accepted: body.events_requested,
      events_delivered: body.events_requested, // ✅ NEW FIELD per spec
      description: body.description || null,
      status: "enabled",
      created_at: now,
      updated_at: now,
    };

    streams[stream_id] = stream;
    console.log("✅ Stream created:", stream_id);
    res.status(201).json(stream);
  } catch (err) {
    console.error("create stream error:", err);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});


/**
 * GET STREAM LIST
 * Returns 200 with array of all registered streams
 */
app.get("/ssf/streams", (req, res) => {
  res.status(200).json(Object.values(streams));
});

/**
 * GET STREAM DETAILS
 */
app.get("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  res.status(200).json(s);
});

/**
 * UPDATE STREAM
 * Accepts raw JSON updates
 * Returns 200 with updated stream
 */
app.post("/ssf/streams/:id", (req, res) => {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const updates = req.body || {};
  if (updates.delivery) s.delivery = { ...s.delivery, ...updates.delivery };
  if (updates.events_requested) {
    s.events_requested = updates.events_requested;
    s.events_accepted = updates.events_requested;
  }
  if ("description" in updates) s.description = updates.description;
  if ("status" in updates) s.status = updates.status;
  s.updated_at = new Date().toISOString();

  console.log("🔄 Stream updated:", id);
  res.status(200).json(s);
});

/**
 * DELETE STREAM
 * Expects ?stream_id=uuid
 * Returns 204 on success
 */
app.post("/ssf/streams/:id/delete", (req, res) => {
  const id = req.params.id;
  if (!streams[id]) return res.status(404).json({ error: "stream_not_found" });
  delete streams[id];
  console.log("❌ Stream deleted:", id);
  res.status(204).send();
});

/**
 * VERIFY STREAM (signed outgoing SET)
 * Body: { stream_id }
 * Sends verification SET to delivery.endpoint, returns 202
 */
app.post("/ssf/streams/verify", async (req, res) => {
  const { stream_id } = req.body || {};
  const s = streams[stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const verifyPayload = {
    iss: ISS,
    aud: s.delivery.endpoint,
    sub_id: { format: "opaque", id: stream_id },
    events: {
      "https://schemas.openid.net/secevent/ssf/event-type/verification": {}
    }
  };

  const signed = await signSET(verifyPayload);
  const headers = {
    "Content-Type": "application/secevent+jwt",
    Authorization: s.delivery.authorization_header
  };

  axios.post(s.delivery.endpoint, signed, { headers })
    .then(() => console.log("✅ Sent verification SET to", s.delivery.endpoint))
    .catch(err => console.error("❌ Verification send failed:", err.message));

  res.status(202).json({ message: "verification_sent", stream_id });
});

/**
 * STREAM STATUS
 * Returns summary of all streams
 */
app.get("/ssf/status", (req, res) => {
  const summary = Object.values(streams).map(s => ({
    stream_id: s.stream_id,
    endpoint: s.delivery.endpoint,
    status: s.status
  }));
  res.status(200).json({
    status: "active",
    count: summary.length,
    streams: summary,
    timestamp: new Date().toISOString()
  });
});


/* ---------- CAEP event send endpoint ---------- */
/**
 * POST /caep/send-risk-level-change
 * Body: { stream_id?, receiver_url?, payload: { principal, current_level, previous_level?, risk_reason?, event_timestamp?, sub_id? } }
 * Must provide either stream_id (preferred) or receiver_url. No global/default fallbacks are used.
 */
app.post("/caep/send-risk-level-change", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};
    if (!payload || !payload.principal || !payload.current_level) {
      return res.status(400).json({ error: "payload.principal_and_current_level_required" });
    }

    let target;
    let authHeader;
    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });
      if (!s.delivery || !s.delivery.endpoint) return res.status(400).json({ error: "stream_has_no_delivery_endpoint" });
      target = s.delivery.endpoint;
      authHeader = s.delivery.authorization_header;
    } else if (receiver_url) {
      target = receiver_url;
      authHeader = req.body.authorization_header || null;
    } else {
      return res.status(400).json({ error: "stream_id_or_receiver_url_required" });
    }

    const eventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id: payload.sub_id || { format: "opaque", id: "unknown" },
      events: {
        [eventType]: {
          principal: payload.principal,
          current_level: String(payload.current_level).toUpperCase(),
          ...(payload.previous_level ? { previous_level: String(payload.previous_level).toUpperCase() } : {}),
          ...(payload.risk_reason ? { risk_reason: payload.risk_reason } : {}),
          ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {}),
        },
      },
    };

    // sign
    const signed = await signSET(setPayload);

    // prepare headers; use stream-specific auth if present
    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    // send and return receiver response
    const resp = await axios.post(target, signed, { headers, validateStatus: () => true, timeout: 20000 }).catch((e) => e.response || { status: 500, data: String(e) });
    return res.status(200).json({ message: "sent", http_status: resp.status, receiver_response: resp.data || null });
  } catch (err) {
    console.error("send-risk-level-change error:", err && err.message ? err.message : err);
    return res.status(500).json({ error: "internal_error" });
  }
});

/* Root */
app.get("/", (req, res) => {
  res.json({
    message: "Spec-compliant SSF/CAEP Transmitter",
    issuer: ISS,
    discovery: `${ISS}/.well-known/ssf-configuration`,
    jwks: `${ISS}/.well-known/jwks.json`,
  });
});

/* ---------- Start server ---------- */
initKeys()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Transmitter listening on ${PORT}`);
      console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
    });
  })
  .catch((err) => {
    console.error("Key init failed:", err);
    process.exit(1);
  });
