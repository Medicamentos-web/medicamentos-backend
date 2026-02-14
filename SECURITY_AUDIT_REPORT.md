# Security Audit Report — Medicamentos Backend (Medical SaaS)

**File analyzed:** `backend/src/index.js`  
**Application type:** Medical SaaS handling patient/family medication data  
**Date:** February 13, 2025  

---

## Executive Summary

The backend uses **parameterized SQL** consistently (no SQL injection found), **bcrypt** for passwords, and **httpOnly/secure/sameSite** cookies where configured. The main issues are **authorization (IDOR)** — any authenticated user can access other families’ data by sending `family_id` in query/body — **missing rate limiting**, **weak defaults (JWT secret, temp password, DB password)**, **overly permissive CORS**, and **no HTTPS enforcement**. For a medical app, **GDPR/data subject rights** (export, deletion, encryption at rest) are only partially addressed.

**Overall security score: 4.5 / 10** — Significant work required before production use with real patient data.

---

## 1. SQL Injection

**Status: ✅ No vulnerabilities found**

- All database access uses the `pg` library with **parameterized queries** (`$1`, `$2`, etc.). No string concatenation of user input into SQL was found.
- Dynamic `WHERE` clauses (e.g. `/admin/meds-list` around lines 2475–2494) build the clause with fixed strings and push values into a `params` array; placeholders use `$N` with that array. **Safe.**

**Recommendation:** Keep using parameterized queries only; avoid template literals or concatenation for any user-controlled input in SQL.

---

## 2. Authentication

### CRITICAL — Default JWT secret in code (Lines 50–51)

- **What:** `JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change"`
- **Where:** ~line 50
- **Risk:** If `JWT_SECRET` is not set in production, anyone who knows the default can forge tokens and impersonate any user.
- **Fix:** Require `JWT_SECRET` in production (e.g. fail startup if `NODE_ENV === 'production'` and `!process.env.JWT_SECRET`). Never ship a default secret.

### HIGH — Weak default temporary password (Lines 95–96)

- **What:** `DEFAULT_TEMP_PASSWORD = process.env.DEFAULT_TEMP_PASSWORD || "123456"`
- **Where:** ~line 95
- **Risk:** Predictable default; if env is unset, new users get a trivial password.
- **Fix:** Require a strong default from env in production, or generate a random temporary password and send it securely (e.g. email); force change on first login (you already have `must_change_password`).

### MEDIUM — JWT in cookie and Authorization header (Lines 942–954)

- **What:** Token accepted from cookie or `Authorization: Bearer`; cookie has `httpOnly`, `secure`, `sameSite` when behind HTTPS.
- **Where:** `authMiddleware` ~942–956; `cookieOpts(req)` ~98–106
- **Risk:** Sending token in URL or in non-secure contexts can lead to leakage. No explicit check that token is not logged.
- **Fix:** Ensure tokens are never logged; consider short-lived access tokens and refresh tokens for sensitive operations.

### LOW — Password reset token in URL (Lines 1527–1528)

- **What:** Reset link: `${req.protocol}://${req.get("host")}/reset?token=${token}`
- **Where:** ~1527
- **Risk:** Tokens in URLs can appear in logs, Referer, browser history. Reset tokens are single-use and time-limited, which mitigates.
- **Fix:** Prefer POST with token in body for the reset step; if keeping GET, ensure reverse proxy logs do not log query strings and that link is only sent over HTTPS email.

**Password hashing:** bcrypt with cost 10 is used consistently (e.g. ~1418, 1570, 1608). **Good.**

---

## 3. Authorization (Family Data Isolation)

### CRITICAL — IDOR via `family_id` from request (Multiple routes)

- **What:** `getFamilyId(req)` (lines 915–925) takes `family_id` from `req.query`, `req.headers["x-family-id"]`, or `req.body`. Many **requireAuth** routes use `getFamilyId(req)` instead of `req.user.family_id`. Any authenticated user can pass another family’s ID and read or write that family’s data.
- **Where (examples):**
  - `GET/POST/PUT/DELETE /api/medicines` — 2954, 2978, 3008, 3039, 3083
  - `GET /api/schedules` — 3116
  - `GET/POST /api/dose-logs` — 3237, 3264
  - `GET /api/alerts`, `POST /api/alerts/read` — 3620, 3643
  - `GET /api/doctor` — 3658
  - `POST /api/push/subscribe`, `/api/push/test` — 3729, 3745
  - `POST /api/daily-checkout` — 3758
  - And other routes that use `getFamilyId(req)` under `requireAuth` or admin
- **Risk:** One family’s patient/medication/schedule/alert data can be accessed or modified by a user from another family. **Unacceptable for medical data.**
- **Fix:**
  - For **requireAuth** (non-admin) routes: do **not** trust query/body/header for `family_id`. Use only `familyId = req.user.family_id` (and optionally validate `user_id` belongs to that family where relevant).
  - For **requireRole(["admin", "superuser"])** routes: use `resolveFamilyScope(req)` so admins are restricted to their own family and only superusers can pass another `family_id`. Replace `getFamilyId(req)` with `resolveFamilyScope(req)` on admin routes that currently use `getFamilyId`.
  - Remove or strictly restrict the `x-family-id` header and do not allow body/query `family_id` to override the authenticated user’s family for non-superuser roles.

### MEDIUM — Admin can target another family on POST /api/medicines (Line 3008)

- **What:** `POST /api/medicines` uses `getFamilyId(req)`, so an admin of family A can send `family_id: B` and create medicines for family B.
- **Fix:** Use `resolveFamilyScope(req)` here and on all other admin CRUD routes that are family-scoped (medicines, schedules, users, etc.).

---

## 4. Input Validation

### HIGH — No password strength or length checks

- **Where:** Registration, login, change-password, reset, admin user create (e.g. 1405, 1546, 1586, 2051, 2835).
- **Risk:** Users can set very weak or short passwords; increases risk of account takeover.
- **Fix:** Enforce minimum length (e.g. 8–12), and optionally complexity (uppercase, lowercase, digit, symbol). Reject weak passwords with a clear message.

### MEDIUM — No email format validation

- **Where:** All endpoints that accept `email` (register, login, forgot, user create/edit).
- **Risk:** Invalid emails, possible abuse of password reset or user enumeration.
- **Fix:** Validate format (e.g. regex or a small library) and normalize (trim, lowercase). Consider not revealing “user not found” on forgot-password (you already return generic `{ ok: true }` when user is missing — good).

### MEDIUM — No maximum length / sanitization on text inputs

- **Where:** Names, dosage, notes, message fields (e.g. body in alerts, names in medicines/users).
- **Risk:** Extremely long strings can cause performance or DoS; stored XSS if rendered without escaping.
- **Fix:** Enforce max lengths (e.g. 200 for names, 500 for notes) and trim. You already use `escapeHtml` for HTML output; keep using it everywhere user content is rendered.

### LOW — `user_id` / `family_id` type validation

- **What:** Many places use `Number(id)` or `Number(family_id)`; non-numeric input becomes `NaN` and is often caught by `!Number.isFinite(id)`.
- **Fix:** Explicitly reject non-integer or out-of-range values and return 400 with a clear message.

---

## 5. CORS Configuration

### HIGH — All origins allowed in practice (Lines 36–47)

- **What:** The CORS callback checks `allowedOrigins` and logs blocked origins but **always** calls `callback(null, true)`, so every origin is allowed.
- **Where:** ~36–47
- **Risk:** Any website can send credentialed requests to your API and read/write data if the user is logged in.
- **Fix:** When origin is present and does not match any allowed pattern, call `callback(new Error("Not allowed by CORS"), false)` (or return 403) instead of `callback(null, true)`. Only allow your real frontend origins and necessary dev URLs.

### MEDIUM — `credentials: true` with broad origin (Line 46)

- **What:** `credentials: true` is set, which is needed for cookies, but combined with the above it allows any site to use cookies.
- **Fix:** After fixing the origin check, keep `credentials: true` only for trusted origins.

---

## 6. Cookie Security

### MEDIUM — Logout clears cookie with `secure: false` (Lines 1491–1496)

- **What:** `res.clearCookie(TOKEN_NAME, { httpOnly: true, sameSite: "lax", secure: false })`
- **Where:** ~1491–1496
- **Risk:** In production (HTTPS), the cookie may have been set with `secure: true`; clearing with `secure: false` might not clear it in some browsers.
- **Fix:** Use the same options as when setting the cookie (e.g. `cookieOpts(req)` or a function that matches the same `secure`/`sameSite` logic) when clearing.

### LOW — sameSite and secure (Lines 98–106, 99–105)

- **What:** `cookieOpts(req)` sets `httpOnly: true`, `secure: isSecure` (from `x-forwarded-proto` or `req.secure`), `sameSite: isSecure ? "none" : "lax"`.
- **Risk:** If the app is not behind a trusted proxy, `x-forwarded-proto` can be spoofed. In that case, enforce HTTPS at the reverse proxy and ensure `app.set("trust proxy", 1)` (or equivalent) so `req.secure` is correct.
- **Fix:** Call `app.set("trust proxy", 1)` (or 2 if behind two proxies) when behind a reverse proxy. Rely on proxy for HTTPS termination and correct headers.

---

## 7. Rate Limiting

### CRITICAL — No rate limiting

- **What:** There is no rate limiting on login, registration, password reset, or API endpoints.
- **Where:** Entire app; no `express-rate-limit` or similar.
- **Risk:** Brute-force on passwords, abuse of password reset, user enumeration, and general API abuse/DoS.
- **Fix:** Add rate limiting (e.g. `express-rate-limit`) for:
  - Auth: `/auth/login`, `/auth/register`, `/auth/forgot`, `/auth/reset`, `/admin/login` (stricter limits, e.g. 5–10 req/min per IP).
  - General API: e.g. 100–200 req/15 min per IP (or per user when identified).
  - Optionally, stricter limits on sensitive actions (e.g. delete user, export data).

---

## 8. HTTPS Enforcement

### HIGH — No HTTPS redirect or enforcement

- **What:** There is no middleware that redirects HTTP to HTTPS or sets security headers (e.g. Strict-Transport-Security).
- **Where:** N/A; not implemented.
- **Risk:** If the app is ever exposed directly (or misconfigured), traffic could be sent over HTTP and tokens/cookies could be intercepted.
- **Fix:** When running behind a reverse proxy (e.g. Render, Nginx): (1) Rely on the proxy to redirect HTTP→HTTPS and terminate SSL. (2) Set `app.set("trust proxy", 1)` so `req.secure` and `x-forwarded-proto` are trusted. (3) Optionally add Helmet and set `Strict-Transport-Security` in production. Do not implement TLS in Node if the proxy already does it.

---

## 9. Sensitive Data Exposure

### HIGH — Diagnostic endpoint exposes configuration (Lines 1347–1362)

- **What:** `GET /diag` returns `HAS_JWT_SECRET`, `HAS_DATABASE_URL`, `NODE_ENV`, `PORT`, cookie names, `hasUser`.
- **Where:** ~1347–1362
- **Risk:** Information disclosure; confirms whether JWT secret is set and helps attackers prioritize targets.
- **Fix:** Remove `/diag` in production, or restrict it (e.g. allow only from localhost or internal IP, or require a secret query param only in dev).

### MEDIUM — Login attempt logging (Line 1673)

- **What:** `console.log("[AUTH] Intentando login admin:", email, "family:", family_id);`
- **Where:** ~1673
- **Risk:** Email and family_id in logs can be sensitive and may be retained in log aggregation; helps attackers if logs are leaked.
- **Fix:** Log only “login attempt” and outcome (success/fail) without email or family_id, or redact (e.g. hash or truncate).

### LOW — DEV_SHOW_RESET_TOKEN (Lines 53, 1538)

- **What:** When `DEV_SHOW_RESET_TOKEN === "true"`, reset response includes the token in JSON.
- **Risk:** If enabled in production, reset tokens are exposed in the API response.
- **Fix:** Ensure this is never set in production; consider removing or gating behind `NODE_ENV !== 'production'`.

---

## 10. GDPR / Data Protection

### HIGH — No data export (right to portability)

- **What:** There is no endpoint for a user or data subject to export their personal data in a machine-readable form.
- **Where:** N/A
- **Risk:** Non-compliance with GDPR Art. 20 and similar rights; poor transparency.
- **Fix:** Add an authenticated endpoint (e.g. `GET /api/me/export` or `/api/gdpr/export`) that returns all data linked to the user (and optionally their family, with appropriate consent/role) as JSON. Restrict to `req.user.family_id` (and same user or admin) and rate-limit.

### HIGH — No explicit “delete my account/data” for data subject

- **What:** Admins can delete users; there is no self-service “delete my account” or “delete all my data” flow for the data subject.
- **Where:** User deletion exists (e.g. DELETE /api/users/:id) but is admin-only.
- **Risk:** GDPR Art. 17 (right to erasure) and similar laws require that the data subject can request deletion; having a clear self-service path is best practice.
- **Fix:** Add an endpoint (e.g. `POST /api/me/delete-account` or `DELETE /api/me`) that deletes the authenticated user and all associated data (or marks for deletion and runs a job). Require re-authentication (e.g. password) and optionally a cooling-off period. Log the deletion for audit.

### MEDIUM — Encryption at rest not implemented in app

- **What:** The app does not implement application-level encryption of sensitive fields (e.g. medical notes, names). Encryption at rest depends on the database and hosting (e.g. PostgreSQL TDE, disk encryption).
- **Risk:** If the DB or backups are compromised, data is readable. For health data, regulators often expect encryption at rest.
- **Fix:** Prefer database/host-level encryption (e.g. encrypted volume, PostgreSQL options). If you need field-level encryption, encrypt sensitive columns (e.g. notes) with a key managed in a secret manager and never log keys.

### MEDIUM — Password reset token expiry (Lines 1518–1522)

- **What:** Reset tokens expire (e.g. 30 minutes); good. Ensure token is single-use (you mark `used_at` — good).
- **Fix:** Keep expiry short; consider 15 minutes. Ensure old reset tokens are purged periodically.

### LOW — Audit trail

- **What:** `medicine_audits` and `deletion_logs` exist; good for accountability.
- **Fix:** Ensure all destructive or sensitive actions (user delete, family delete, export) are logged with who, when, and what. Avoid logging full PII in plain text; use IDs and action type.

---

## Summary Table

| Severity  | Count | Topics |
|-----------|-------|--------|
| CRITICAL  | 3     | JWT default secret; no rate limiting; IDOR via family_id |
| HIGH      | 6     | Default temp password; CORS allows all origins; no HTTPS enforcement; /diag info disclosure; no GDPR export; no self-service deletion |
| MEDIUM    | 8     | Logout cookie options; trust proxy; no password/email validation; text length/sanitization; admin family_id on POST medicines; credentials + CORS; encryption at rest; reset token lifecycle |
| LOW       | 5     | Reset token in URL; sameSite/secure/trust proxy; DEV_SHOW_RESET_TOKEN; user_id/family_id validation; audit logging |

---

## Recommended Priority Order

1. **Immediate:** Fix IDOR by using `req.user.family_id` (or `resolveFamilyScope` for admin) everywhere family-scoped data is accessed; never trust client-supplied `family_id` for non-superuser.
2. **Immediate:** Require `JWT_SECRET` in production; remove or restrict `/diag`; fix CORS to reject unknown origins.
3. **Short term:** Add rate limiting on auth and sensitive endpoints; enforce HTTPS at proxy and set `trust proxy`; fix logout `clearCookie` options; add password strength and email validation.
4. **Medium term:** Add GDPR export and self-service account deletion; document encryption at rest (DB/host); tighten logging (no passwords/tokens, minimal PII).

---

## Overall Security Score: **4.5 / 10**

- **Strengths:** Parameterized SQL, bcrypt, httpOnly/secure/sameSite when configured, single-use/time-limited reset tokens, some audit tables.
- **Weaknesses:** Critical authorization flaw (family_id), no rate limiting, weak defaults, permissive CORS, no HTTPS enforcement, limited input validation, and incomplete GDPR controls for a medical app.

After addressing CRITICAL and HIGH items and reinforcing validation and CORS, a reasonable target is **7–8/10** for a production medical backend.
