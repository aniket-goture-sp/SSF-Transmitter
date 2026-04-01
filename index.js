/**
 * Final index.js
 * - Added support for DELETE /ssf/streams?stream_id=<id>
 * 
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

/* --------------------------- CONFIG --------------------------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://ssfrisklevelrepo.onrender.com";

/* Default iss for iss_sub SubjectFormat (e.g. https://caep.dev/event) */
const DEFAULT_ISS_SUB_ISS = process.env.ISS_SUB_ISS || "https://caep.dev/event";

/* ------------------- PRIVATE KEY ------------------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
let PRIVATE_KEY_PEM;
try {
  PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");
  console.log("🔑 Loaded private key from", KEY_PATH);
} catch (err) {
  console.error("Missing private_key_pkcs8.pem");
  process.exit(1);
}

/* ------------------- INIT KEYS ------------------- */
let signingKey;
let publicJwk;

async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    console.log("✅ Signing key ready, kid =", publicJwk.kid);
  } catch (err) {
    console.error("Key import failed:", err.message);
    process.exit(1);
  }
}

/* ------------------- SIGN SET ------------------- */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: "RS256",
      typ: "secevent+jwt",
      kid: publicJwk.kid,
    })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/* ------------------- VERIFY INCOMING SET ------------------- */
async function verifyIncomingSET(token) {
  const header = await decodeProtectedHeader(token);
  const kid = header.kid;

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");

  const payloadJson = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const jwks_uri = payloadJson.jwks_uri;
  if (!jwks_uri) throw new Error("jwks_uri_missing");

  const jwksResp = await axios.get(jwks_uri);
  const jwk = jwksResp.data.keys.find((k) => k.kid === kid) || jwksResp.data.keys[0];

  if (!jwk) throw new Error("jwk_not_found");

  const key = await importJWK(jwk, jwk.alg || "RS256");

  const verified = await jwtVerify(token, key, {
    issuer: payloadJson.iss,
    audience: payloadJson.aud,
  });

  return { payload: verified.payload, header };
}

/* ------------------- BUILD SUB_ID (SubjectFormat) ------------------- */
/**
 * RFC 9493 iss_sub Subject Identifier uses JSON members "iss" and "sub" (not "issuer").
 * We always emit those exact names in the signed SET. Callers may send "issuer" as an alias
 * for "iss"; it is normalized to "iss" here. (jose SignJWT does not rename nested keys.)
 */
function canonicalIssSubSubId(sid) {
  const iss = sid.iss != null && sid.iss !== "" ? sid.iss : sid.issuer;
  if (!iss || sid.sub === undefined || sid.sub === null) {
    throw new Error(
      "sub_id with format 'iss_sub' requires both 'iss' (or alias 'issuer') and 'sub' fields"
    );
  }
  return { format: "iss_sub", iss: String(iss), sub: String(sid.sub) };
}

/**
 * Builds sub_id for SET payload.
 * Default is email-based. Choose per-event via payload.subject_format:
 *   - "email" (default): { format: "email", email: "..." } — uses payload.email or payload.principal
 *   - "iss_sub": { format: "iss_sub", iss: "https://caep.dev/event", sub: "<NativeIdentity>" }
 *     iss = issuer URL for the source; sub = NativeIdentity of the account in that source
 */
function buildSubId(payload, stream, defaultEmail = "unknown@unknown.local") {
  // Explicit sub_id takes precedence (caller provides full sub_id object)
  if (payload && payload.sub_id && typeof payload.sub_id === "object") {
    const sid = payload.sub_id;
    if (sid.format === "iss_sub") {
      return canonicalIssSubSubId(sid);
    }
    if (sid.format === "email") {
      const email = sid.email;
      if (email === undefined || email === null) {
        throw new Error("sub_id with format 'email' requires 'email' field");
      }
      return { format: "email", email: String(email) };
    }
    return sid;
  }

  // Per-event subject_format choice
  const format = payload?.subject_format || stream?.subject_format || "email";

  if (format === "iss_sub") {
    const cfg = stream?.subject_format?.iss_sub;
    const iss =
      payload?.iss_sub_iss ||
      cfg?.iss ||
      cfg?.issuer ||
      DEFAULT_ISS_SUB_ISS;
    const sub = payload?.sub || payload?.native_identity;
    if (sub === undefined || sub === null) {
      throw new Error("subject_format 'iss_sub' requires 'sub' or 'native_identity' in payload");
    }
    return { format: "iss_sub", iss: String(iss), sub: String(sub) };
  }

  // Default: email-based
  const email = payload?.email || payload?.principal || defaultEmail;
  return { format: "email", email: String(email) };
}

/**
 * Validates CAEP session-revoked "simple subject" (session + user + tenant).
 * Returns an error code string or null if valid.
 */
function validateSessionRevokedSubject(subject) {
  if (!subject || typeof subject !== "object") return "subject_required";
  const sess = subject.session;
  if (
    !sess ||
    sess.format !== "opaque" ||
    sess.id === undefined ||
    sess.id === null ||
    String(sess.id) === ""
  ) {
    return "subject.session_opaque_id_required";
  }
  const user = subject.user;
  if (!user || user.format !== "iss_sub") return "subject.user_iss_sub_required";
  const iss = user.iss != null && user.iss !== "" ? user.iss : user.issuer;
  if (!iss || user.sub === undefined || user.sub === null || String(user.sub) === "") {
    return "subject.user_iss_sub_required";
  }
  const tenant = subject.tenant;
  if (
    !tenant ||
    tenant.format !== "opaque" ||
    tenant.id === undefined ||
    tenant.id === null ||
    String(tenant.id) === ""
  ) {
    return "subject.tenant_opaque_id_required";
  }
  return null;
}

/** Normalize subject for signed SET (iss_sub user uses canonical iss, not issuer alias). */
function normalizeSessionRevokedSubject(subject) {
  const user = canonicalIssSubSubId({
    iss: subject.user.iss,
    issuer: subject.user.issuer,
    sub: subject.user.sub,
  });
  return {
    session: { format: "opaque", id: String(subject.session.id) },
    user,
    tenant: { format: "opaque", id: String(subject.tenant.id) },
  };
}

/** Top-level sub_id for session-revoked: explicit sub_id, else iss_sub from subject.user. */
function buildSubIdForSessionRevoked(payload, stream, defaultEmail) {
  if (payload.sub_id && typeof payload.sub_id === "object") {
    return buildSubId(payload, stream, defaultEmail);
  }
  const user = payload.subject?.user;
  if (user && user.format === "iss_sub") {
    try {
      return canonicalIssSubSubId({
        iss: user.iss,
        issuer: user.issuer,
        sub: user.sub,
      });
    } catch (_) {
      /* fall through */
    }
  }
  return buildSubId(payload, stream, defaultEmail);
}


/* ------------------- STREAM STORE ------------------- */
const streams = {};

/* ------------------- WELL-KNOWN ------------------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));

app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    delivery_methods_supported: ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
    configuration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    verification_endpoint: `${ISS}/ssf/streams/verify`,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    spec_version: "1_0-ID2",
    authorization_schemes: [{ spec_urn: "urn:ietf:rfc:6749" }],
  });
});

/* ------------------- AUTH MIDDLEWARE ------------------- */
/*
  Expect Authorization: Bearer <token>
  Token value is validated against process.env.SSF_AUTH_TOKEN || "token123"
*/
app.use("/ssf", (req, res, next) => {
  const auth = req.headers.authorization || "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "unauthorized", message: "missing_bearer_token" });
  }
  const token = auth.slice(7).trim();
  const expected = process.env.SSF_AUTH_TOKEN || "token123";
  if (!token || token !== expected) {
    return res.status(401).json({ error: "unauthorized", message: "invalid_token" });
  }
  next();
});

/* ------------------- CREATE STREAM ------------------- */
app.post("/ssf/streams", (req, res) => {
  try {
    const body = req.body || {};

    if (!body.aud) body.aud = ISS;
    if (!body.jwks_uri) body.jwks_uri = `${ISS}/.well-known/jwks.json`;

    let delivery = body.delivery || {};
    // Prefer delivery.endpoint_url (user requested canonical rename)
    const endpoint =
      delivery.endpoint_url ||
      delivery.endpoint ||
      delivery.URL ||
      delivery.url;

    const method = delivery.method;

    if (!endpoint || !method) {
      return res.status(400).json({
        error: "invalid_delivery",
        message: "delivery.method and delivery.endpoint_url required",
      });
    }

    const required = ["iss", "aud", "jwks_uri", "events_requested"];
    const missing = required.filter((f) => !(f in body));
    if (missing.length) {
      return res.status(400).json({ error: `missing_fields: ${missing.join(", ")}` });
    }

    const id = uuidv4();
    const now = new Date().toISOString();

    const stream = {
      stream_id: id,
      iss: body.iss,
      aud: body.aud,
      jwks_uri: body.jwks_uri,
      delivery: {
        method,
        endpoint_url: endpoint,
        authorization_header: delivery.authorization_header || "Bearer token123",
      },
      events_requested: body.events_requested,
      events_accepted: body.events_requested,
      events_delivered: body.events_requested,
      description: body.description || null,
      status: "enabled",
      created_at: now,
      updated_at: now,
      ...(body.subject_format ? { subject_format: body.subject_format } : {}),
    };

    streams[id] = stream;

    res.status(201).json(stream);
  } catch (err) {
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- GET STREAMS ------------------- */
app.get("/ssf/streams", (req, res) => {
  res.json(Object.values(streams));
});

/* ------------------- GET STREAM BY ID ------------------- */
app.get("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  res.json(s);
});

/* ------------------- UPDATE STREAM (POST - legacy) ------------------- */
app.post("/ssf/streams/:id", (req, res) => {
  return handleStreamUpdate(req, res);
});

/* ------------------- UPDATE STREAM (PATCH - preferred) ------------------- */
app.patch("/ssf/streams/:id", (req, res) => {
  return handleStreamUpdate(req, res);
});

/* centralised update logic used by both POST and PATCH */
function handleStreamUpdate(req, res) {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  try {
    const updates = req.body || {};

    // delivery merge: accept delivery.* fields and normalize endpoint_url
    if (updates.delivery) {
      const incoming = updates.delivery || {};
      const newDelivery = { ...s.delivery, ...incoming };

      const ep =
        (incoming.endpoint_url || incoming.endpoint || incoming.URL || incoming.url) ||
        newDelivery.endpoint_url;

      // Only overwrite endpoint_url if we have a non-empty value
      if (ep) newDelivery.endpoint_url = ep;

      // If incoming.method is provided and non-empty, update it
      if (incoming.method) newDelivery.method = incoming.method;

      // optional: allow update of authorization_header
      if (typeof incoming.authorization_header !== "undefined") {
        newDelivery.authorization_header = incoming.authorization_header;
      }

      s.delivery = newDelivery;
    }

    // events_requested update (replace)
    if (updates.events_requested) {
      s.events_requested = updates.events_requested;
      s.events_accepted = updates.events_requested;
      s.events_delivered = updates.events_requested;
    }

    // allow updating description, status, jwks_uri, and subject_format
    if ("description" in updates) s.description = updates.description;
    if ("status" in updates) s.status = updates.status;
    if ("jwks_uri" in updates) s.jwks_uri = updates.jwks_uri;
    if ("iss" in updates) s.iss = updates.iss;
    if ("aud" in updates) s.aud = updates.aud;
    if ("subject_format" in updates) s.subject_format = updates.subject_format;

    s.updated_at = new Date().toISOString();
    return res.json(s);
  } catch (err) {
    console.error("stream update error:", err.message);
    return res.status(500).json({ error: "internal_error", message: err.message });
  }
}

/* ------------------- DELETE STREAM (POST legacy) ------------------- */
app.post("/ssf/streams/:id/delete", (req, res) => {
  try {
    const id = req.params.id;
    if (!streams[id]) {
      return res.status(404).json({ error: "stream_not_found" });
    }
    delete streams[id];
    return res.status(204).send();
  } catch (err) {
    console.error("delete stream error:", err.message);
    return res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- DELETE STREAM (DELETE method) ------------------- */
app.delete("/ssf/streams/:id", (req, res) => {
  try {
    const id = req.params.id;
    if (!streams[id]) {
      return res.status(404).json({ error: "stream_not_found" });
    }
    delete streams[id];
    return res.status(204).send();
  } catch (err) {
    console.error("delete stream error:", err.message);
    return res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- DELETE STREAM (DELETE with query param) ------------------- */
app.delete("/ssf/streams", (req, res) => {
  try {
    const id = req.query.stream_id || req.query.id || null;
    if (!id) {
      return res.status(400).json({ error: "stream_id_query_required" });
    }
    if (!streams[id]) {
      return res.status(404).json({ error: "stream_not_found" });
    }
    delete streams[id];
    return res.status(204).send();
  } catch (err) {
    console.error("delete stream error:", err.message);
    return res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- BULK UPSERT STREAMS (PUT) ------------------- */
/*
  Accepts an array of stream objects (same shape as stored streams).
  For each item:
    - if stream_id exists and stream found => update (merge sensible fields)
    - if stream_id missing or not found => create new stream (use provided stream_id or generate one)
  Returns 200 with array of upserted streams.
*/
app.put("/ssf/streams", (req, res) => {
  try {
    const body = req.body;
    if (!Array.isArray(body)) {
      return res.status(400).json({ error: "expected_array_of_stream_objects" });
    }

    const results = body.map((item) => {
      // Defensive normalize
      const incoming = item || {};
      // Use provided id or generate
      const id = incoming.stream_id || uuidv4();

      // If exists, merge intelligently
      if (streams[id]) {
        const s = streams[id];

        // Update simple top-level props if provided
        if ("iss" in incoming) s.iss = incoming.iss;
        if ("aud" in incoming) s.aud = incoming.aud;
        if ("jwks_uri" in incoming) s.jwks_uri = incoming.jwks_uri;
        if ("description" in incoming) s.description = incoming.description;
        if ("status" in incoming) s.status = incoming.status;
        if ("subject_format" in incoming) s.subject_format = incoming.subject_format;

        // delivery merge (normalize endpoint keys)
        if (incoming.delivery) {
          const d = incoming.delivery;
          const ep = d.endpoint_url || d.endpoint || d.URL || d.url || s.delivery.endpoint_url;
          s.delivery.method = d.method || s.delivery.method;
          s.delivery.endpoint_url = ep || s.delivery.endpoint_url;
          if ("authorization_header" in d) s.delivery.authorization_header = d.authorization_header;
        }

        // events arrays - if provided replace
        if (incoming.events_requested) {
          s.events_requested = incoming.events_requested;
          s.events_accepted = incoming.events_requested;
          s.events_delivered = incoming.events_requested;
        }

        s.updated_at = incoming.updated_at || new Date().toISOString();
        streams[id] = s;
        return s;
      }

      // Create new stream object using provided shape (but ensure required fields and defaults)
      const now = new Date().toISOString();
      const delivery = incoming.delivery || {};
      const endpoint =
        delivery.endpoint_url ||
        delivery.endpoint ||
        delivery.URL ||
        delivery.url ||
        null;
      const method = delivery.method || "push";

      const newStream = {
        stream_id: id,
        iss: incoming.iss || ISS,
        aud: incoming.aud || (incoming.aud === "" ? "" : ISS),
        jwks_uri: incoming.jwks_uri || `${ISS}/.well-known/jwks.json`,
        delivery: {
          method,
          endpoint_url: endpoint,
          authorization_header: delivery.authorization_header || "Bearer token123"
        },
        events_requested: incoming.events_requested || incoming.events_accepted || incoming.events_delivered || [],
        events_accepted: incoming.events_accepted || incoming.events_requested || incoming.events_delivered || [],
        events_delivered: incoming.events_delivered || incoming.events_requested || incoming.events_accepted || [],
        description: typeof incoming.description !== "undefined" ? incoming.description : null,
        status: incoming.status || "enabled",
        ...(incoming.subject_format ? { subject_format: incoming.subject_format } : {}),
        created_at: incoming.created_at || now,
        updated_at: incoming.updated_at || now
      };

      streams[id] = newStream;
      return newStream;
    });

    return res.status(200).json(results);
  } catch (err) {
    console.error("PUT /ssf/streams error:", err);
    return res.status(500).json({ error: "internal_error", message: String(err) });
  }
});

/* ------------------- VERIFY STREAM ------------------- */
app.post("/ssf/streams/verify", async (req, res) => {
  try {
    const { stream_id } = req.body || {};
    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    const eventType = "https://schemas.openid.net/secevent/ssf/event-type/verification";

    // include jwks_uri so receiver can locate our public keys
    const verifyPayload = {
      iss: ISS,
      aud: s.delivery.endpoint_url,
      jwks_uri: `${ISS}/.well-known/jwks.json`,
      sub_id: { format: "opaque", id: stream_id },
      events: { [eventType]: {} }
    };

    const signed = await signSET(verifyPayload);

    const headers = {
      "Content-Type": "application/secevent+jwt",
      Authorization: s.delivery.authorization_header
    };

    // Await the receiver's response so we can return useful diagnostics
    const resp = await axios
      .post(s.delivery.endpoint_url, signed, { headers, validateStatus: () => true, timeout: 15000 })
      .catch(e => e.response || { status: 502, data: String(e) });

    if (resp.status >= 200 && resp.status < 300) {
      console.warn(`🔐 Verification SET sent → ${s.delivery.endpoint_url} (status ${resp.status})`);
      res.status(200).json({
        message: "verification_sent",
        stream_id,
        receiver_status: resp.status,
        receiver_response: resp.data || null
      });
    } else {
      console.warn(`❌ Verification failed → ${s.delivery.endpoint_url} (status ${resp.status})`);
      res.status(502).json({
        error: "verification_failed",
        stream_id,
        receiver_status: resp.status,
        receiver_response: resp.data || null
      });
    }
  } catch (err) {
    console.error("verify stream error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- STREAM STATUS (GET summary or single) ------------------- */
app.get("/ssf/status", (req, res) => {
  const streamId = req.query.stream_id || req.query.id || null;
  if (streamId) {
    const s = streams[streamId];
    if (!s) return res.status(404).json({ error: "stream_not_found" });
    return res.status(200).json({ status: s.status });
  }

  const summary = Object.values(streams).map(s => ({
    stream_id: s.stream_id,
    endpoint: s.delivery.endpoint_url,
    status: s.status
  }));

  res.status(200).json({
    status: "active",
    count: summary.length,
    streams: summary,
    timestamp: new Date().toISOString()
  });
});

/* ------------------- STREAM STATUS (POST update) ------------------- */
app.post("/ssf/status", (req, res) => {
  try {
    const { stream_id, status } = req.body || {};
    if (!stream_id) return res.status(400).json({ error: "stream_id_required" });
    if (!status) return res.status(400).json({ error: "status_required" });

    const allowed = ["enabled", "disabled", "verification_pending", "failed"];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: "invalid_status", message: `allowed: ${allowed.join(", ")}` });
    }

    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    s.status = status;
    s.updated_at = new Date().toISOString();

    res.status(200).json(s);
  } catch (err) {
    console.error("status update error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ============================================================
   SHARED METRICS (for all CAEP event send endpoints)
   ============================================================ */
if (!global.metrics) {
  global.metrics = {
    risk: { sent: 0, success: 0, failed: 0 },
    status: { sent: 0, success: 0, failed: 0 },
    device: { sent: 0, success: 0, failed: 0 },
    token_claim: { sent: 0, success: 0, failed: 0 }
  };
}

function logEvent(type, endpoint, resp) {
  const m = global.metrics[type];
  if (!m) {
    global.metrics[type] = { sent: 0, success: 0, failed: 0 };
  }
  const mm = global.metrics[type];
  mm.sent++;

  const ok = resp.status >= 200 && resp.status < 300;
  if (ok) mm.success++;
  else mm.failed++;

  console.warn(
    `${ok ? "✅" : "❌"} [${type.toUpperCase()} EVENT DELIVERY]\n` +
    `→ Target: ${endpoint}\n` +
    `→ HTTP: ${resp.status}\n` +
    `→ Body: ${JSON.stringify(resp.data)}\n` +
    `→ Stats: sent=${mm.sent}, success=${mm.success}, failed=${mm.failed}`
  );
}

/* ============================================================
   CAEP EVENT: RISK LEVEL CHANGE
   ============================================================ */
app.post("/caep/send-risk-level-change", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};

    if (!payload || !payload.principal || !payload.current_level) {
      return res.status(400).json({ error: "payload.principal_and_current_level_required" });
    }

    let target, authHeader;

    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });

      target = s.delivery.endpoint_url;
      authHeader = s.delivery.authorization_header;
    } else if (receiver_url) {
      target = receiver_url;
      authHeader = req.body.authorization_header || null;
    } else {
      return res.status(400).json({ error: "stream_id_or_receiver_url_required" });
    }

    const eventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";

    const streamObj = stream_id ? streams[stream_id] : null;
    const sub_id = buildSubId(payload, streamObj, "unknown@unknown.local");

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id,
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

    const signed = await signSET(setPayload);

    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    const resp = await axios
      .post(target, signed, { headers, validateStatus: () => true })
      .catch(e => e.response || { status: 500, data: String(e) });

    logEvent("risk", target, resp);

    res.status(200).json({
      message: "risk_level_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("risk-level-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ============================================================
   CAEP EVENT: STATUS CHANGE
   ============================================================ */
app.post("/caep/send-status-change", async (req, res) => {
  try {
    const { stream_id, payload } = req.body || {};

    if (!stream_id) return res.status(400).json({ error: "stream_id_required" });

    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    const eventType = "https://schemas.openid.net/secevent/caep/event-type/status-change";

    const sub_id = buildSubId(payload, s, "unknown@unknown.local");

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id,
      events: {
        [eventType]: {
          principal: payload.principal,
          current_status: payload.current_status,
          ...(payload.previous_status ? { previous_status: payload.previous_status } : {}),
          ...(payload.reason ? { reason: payload.reason } : {}),
          ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {})
        }
      }
    };

    const signed = await signSET(setPayload);

    const headers = {
      "Content-Type": "application/secevent+jwt",
      Authorization: s.delivery.authorization_header,
    };

    const resp = await axios
      .post(s.delivery.endpoint_url, signed, { headers, validateStatus: () => true })
      .catch(e => e.response || { status: 500, data: String(e) });

    logEvent("status", s.delivery.endpoint_url, resp);

    res.status(200).json({
      message: "status_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null
    });
  } catch (err) {
    console.error("status-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ============================================================
   CAEP EVENT: DEVICE COMPLIANCE CHANGE
   ============================================================ */
app.post("/caep/send-device-compliance-change", async (req, res) => {
  try {
    const { stream_id, payload } = req.body || {};

    if (!stream_id)
      return res.status(400).json({ error: "stream_id_required" });

    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    const eventType =
      "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

    const sub_id = buildSubId(payload, s, "unknown@unknown.local");

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id,
      events: {
        [eventType]: {
          current_status: payload.current_status,
          ...(payload.previous_status
            ? { previous_status: payload.previous_status }
            : {}),
          ...(payload.event_timestamp
            ? { event_timestamp: payload.event_timestamp }
            : {}),
        },
      },
    };

    const signed = await signSET(setPayload);

    const headers = {
      "Content-Type": "application/secevent+jwt",
      Authorization: s.delivery.authorization_header,
    };

    const resp = await axios
      .post(s.delivery.endpoint_url, signed, {
        headers,
        validateStatus: () => true,
        timeout: 20000,
      })
      .catch((e) => e.response || { status: 500, data: String(e) });

    logEvent("device", s.delivery.endpoint_url, resp);

    res.status(200).json({
      message: "device_compliance_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("send-device-compliance-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ============================================================
   CAEP EVENT: TOKEN CLAIM CHANGE (enhanced; claims object + complex sub_id)
   ============================================================ */
app.post("/caep/send-token-claim-change", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};

    // Accept either a claims object OR a single-claim (claim_name + current_value)
    if (!payload || ( !payload.claims && (!payload.claim_name || (typeof payload.current_value === "undefined" || payload.current_value === null)) )) {
      return res.status(400).json({ error: "payload.claims_or_claim_name_and_current_value_required" });
    }

    let target, authHeader;

    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });

      target = s.delivery.endpoint_url;
      authHeader = s.delivery.authorization_header;
    } else if (receiver_url) {
      target = receiver_url;
      authHeader = req.body.authorization_header || null;
    } else {
      return res.status(400).json({ error: "stream_id_or_receiver_url_required" });
    }

    // CAEP spec plural event type
    const eventType = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";

    // Build claims object (preserve provided structure)
    let claimsObj = {};
    if (payload.claims && typeof payload.claims === "object") {
      claimsObj = payload.claims;
    } else if (payload.claim_name) {
      claimsObj[payload.claim_name] = payload.current_value;
    }

    // Build event body including optional fields exactly as provided
    const eventBody = {
      ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {}),
      ...(payload.initiating_entity ? { initiating_entity: payload.initiating_entity } : {}),
      ...(payload.reason_admin ? { reason_admin: payload.reason_admin } : {}),
      ...(payload.reason_user ? { reason_user: payload.reason_user } : {}),
      claims: claimsObj
    };

    // include previous_value if single-claim previous_value provided
    if (!payload.claims && typeof payload.previous_value !== "undefined" && payload.previous_value !== null && payload.claim_name) {
      eventBody.previous_value = payload.previous_value;
    }

    const streamObj = stream_id ? streams[stream_id] : null;
    const sub_id = buildSubId(payload, streamObj, payload.principal || "unknown@unknown.local");

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      ...(payload.txn ? { txn: payload.txn } : {}), // preserve txn at top-level if provided
      sub_id,
      events: {
        [eventType]: eventBody
      }
    };

    const signed = await signSET(setPayload);

    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    const resp = await axios
      .post(target, signed, { headers, validateStatus: () => true, timeout: 20000 })
      .catch(e => e.response || { status: 500, data: String(e) });

    logEvent("token_claim", target, resp);

    res.status(200).json({
      message: "token_claim_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("token-claim-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ============================================================
   CAEP EVENT: SESSION REVOKED (simple subject: session + user + tenant)
   ============================================================ */
app.post("/caep/send-session-revoked", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};

    if (!payload || !payload.subject) {
      return res.status(400).json({ error: "payload.subject_required" });
    }

    const subjectErr = validateSessionRevokedSubject(payload.subject);
    if (subjectErr) {
      return res.status(400).json({ error: subjectErr });
    }

    let target, authHeader;

    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });

      target = s.delivery.endpoint_url;
      authHeader = s.delivery.authorization_header;
    } else if (receiver_url) {
      target = receiver_url;
      authHeader = req.body.authorization_header || null;
    } else {
      return res.status(400).json({ error: "stream_id_or_receiver_url_required" });
    }

    const eventType =
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    const eventBody = {
      subject: normalizeSessionRevokedSubject(payload.subject),
      ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {}),
      ...(payload.initiating_entity ? { initiating_entity: payload.initiating_entity } : {}),
      ...(payload.reason_admin ? { reason_admin: payload.reason_admin } : {}),
      ...(payload.reason_user ? { reason_user: payload.reason_user } : {}),
    };

    const streamObj = stream_id ? streams[stream_id] : null;
    const sub_id = buildSubIdForSessionRevoked(
      payload,
      streamObj,
      payload.principal || "unknown@unknown.local"
    );

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      ...(payload.txn ? { txn: payload.txn } : {}),
      sub_id,
      events: {
        [eventType]: eventBody,
      },
    };

    const signed = await signSET(setPayload);

    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    const resp = await axios
      .post(target, signed, { headers, validateStatus: () => true, timeout: 20000 })
      .catch((e) => e.response || { status: 500, data: String(e) });

    logEvent("session_revoked", target, resp);

    res.status(200).json({
      message: "session_revoked_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("session-revoked error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});


/* Root */
app.get("/", (req, res) => {
  res.json({
    message: "Spec-compliant SSF/CAEP Transmitter",
    issuer: ISS,
    discovery: `${ISS}/.well-known/ssf-configuration`,
    jwks: `${ISS}/.well-known/jwks.json`,
    metrics: global.metrics
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
