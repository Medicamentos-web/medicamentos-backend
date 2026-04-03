/**
 * Trazas en memoria del flujo Sign in with Apple (últimos N eventos).
 * Sirve para GET /api/debug/apple-oauth y para ver el último fallo sin buscar en logs de Render.
 */
const MAX_EVENTS = 30;

const events = [];

function redact(str) {
  if (str == null || typeof str !== "string") return "";
  let s = str;
  s = s.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "***@***");
  return s.slice(0, 500);
}

/**
 * @param {string} type - p.ej. authorize_start | callback_post | passport_error | verify_ok | verify_no_user
 * @param {string} [detail]
 */
function recordAppleOAuthEvent(type, detail) {
  const entry = {
    at: new Date().toISOString(),
    type,
    detail: detail ? redact(String(detail)) : "",
  };
  events.push(entry);
  if (events.length > MAX_EVENTS) events.shift();
  if (process.env.APPLE_OAUTH_DEBUG === "1" || process.env.APPLE_OAUTH_DEBUG === "true") {
    console.log("[AUTH APPLE trace]", type, entry.detail || "");
  }
}

function getAppleOAuthTraceDebug() {
  const failTypes =
    /passport_error|oauth_no_user|verify_no_|find_or_create_null|verify_exception/;
  const failures = events.filter((e) => failTypes.test(e.type));
  return {
    event_count: events.length,
    last_events: events.slice(-12),
    /** Último evento que suele indicar problema (no solo authorize/callback OK). */
    last_failure_hint: failures.length ? failures[failures.length - 1] : null,
  };
}

module.exports = { recordAppleOAuthEvent, getAppleOAuthTraceDebug };
