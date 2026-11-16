// Design Hustler / portfolio2 Worker
// Static site is served by the ASSETS binding. This Worker handles /api/*, /admin and /studio.

const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers allows at most 100000
const SESSION_DAYS = 7;
const COOKIE = "dh_session";
const MAX_BODY = 20000;
const enc = new TextEncoder();

/* ---------- small helpers ---------- */
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const nowSql = (ms = Date.now()) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");

export async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashPassword(password, saltB64) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return b64(bits);
}

export function newSalt() {
  return b64(crypto.getRandomValues(new Uint8Array(16)));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000",
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SEC_HEADERS, ...extra },
  });
}
const err = (status, code, extra = {}) => json({ ok: false, error: code }, status, extra);

async function readJson(request) {
  const ct = request.headers.get("Content-Type") || "";
  if (!ct.includes("application/json")) throw new HttpError(415, "json_required");
  if (Number(request.headers.get("Content-Length") || 0) > MAX_BODY) throw new HttpError(413, "too_large");
  const text = await request.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "too_large");
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v;
  } catch {
    throw new HttpError(400, "bad_json");
  }
}

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function clean(v, max) {
  if (typeof v !== "string") return "";
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max);
}

function getCookie(request, name) {
  const h = request.headers.get("Cookie") || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "0.0.0.0";
}

// Never store raw IPs. The tag changes every UTC day, is scoped per feature, and is salted
// with the optional IP_SALT secret (falls back to a fixed string if the secret is not set).
async function ipTag(env, request, scope) {
  const day = new Date().toISOString().slice(0, 10);
  return (await sha256hex(`${env.IP_SALT || "dh"}|${scope}|${day}|${clientIp(request)}`)).slice(0, 32);
}

/* ---------- housekeeping (daily cron) ---------- */
export async function housekeeping(env) {
  await env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?1").bind(Math.floor(Date.now() / 1000) - 86400).run();
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  // privacy: forget the (hashed) IP tag of old reviews
  await env.DB.prepare("UPDATE reviews SET ip_hash = NULL WHERE ip_hash IS NOT NULL AND created_at < datetime('now','-30 days')").run();
}

/* ---------- rate limiting (D1) ---------- */
// Returns true if the request is allowed. Counts this attempt.
async function allow(env, key, limit, windowSec) {
  const win = Math.floor(Date.now() / 1000 / windowSec) * windowSec;
  const row = await env.DB.prepare(
    "INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1 RETURNING count"
  )
    .bind(key, win)
    .first();
  if (Math.random() < 0.02) {
    // occasional cleanup of old windows
    await env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?1").bind(Math.floor(Date.now() / 1000) - 86400).run();
  }
  return row.count <= limit;
}

/* ---------- auth ---------- */
async function createSession(env, adminId) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const id = await sha256hex(token);
  const expires = nowSql(Date.now() + SESSION_DAYS * 86400000);
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  await env.DB.prepare("INSERT INTO sessions (id, admin_id, expires_at) VALUES (?1, ?2, ?3)").bind(id, adminId, expires).run();
  return token;
}

function sessionCookie(token, maxAge) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function currentAdmin(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || token.length < 20 || token.length > 100) return null;
  const id = await sha256hex(token);
  return await env.DB.prepare(
    "SELECT a.id, a.email, a.must_change, s.id AS sid FROM sessions s JOIN admin_users a ON a.id = s.admin_id WHERE s.id = ?1 AND s.expires_at > datetime('now')"
  )
    .bind(id)
    .first();
}

async function requireAdmin(request, env, { allowMustChange = false } = {}) {
  const admin = await currentAdmin(request, env);
  if (!admin) throw new HttpError(401, "unauthorized");
  if (admin.must_change && !allowMustChange) throw new HttpError(403, "password_change_required");
  return admin;
}

/* ---------- handlers: public ---------- */
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

async function submitReview(request, env) {
  const b = await readJson(request);

  // Honeypot or too-fast submission: pretend success, store nothing.
  // `el` = milliseconds the form was open, measured on the client (immune to clock skew).
  const tooFast = typeof b.el === "number" && b.el < 3000;
  if ((typeof b.website === "string" && b.website.trim() !== "") || tooFast) return json({ ok: true });

  // Only these fields are ever read from the request. status/featured/consent-style
  // fields sent by a client are ignored: every review starts as 'pending'.
  const name = clean(b.name, 80);
  const brand = clean(b.brand, 120);
  const email = clean(b.email, 254);
  const service = clean(b.service, 80);
  const text = clean(b.text, 1500);
  const rating = Number(b.rating);
  const fields = {};
  if (name.length < 2) fields.name = "Please enter your name.";
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) fields.rating = "Please choose a rating from 1 to 5.";
  if (text.length < 10) fields.text = "Please write at least a few words (10 characters).";
  if (email && !EMAIL_RE.test(email)) fields.email = "That email does not look right.";
  if (Object.keys(fields).length) return json({ ok: false, error: "validation", fields }, 422);

  // Rate limits are charged only for well-formed submissions, so a typo never locks a real client out.
  const ipHash = await ipTag(env, request, "review");
  if (!(await allow(env, "review:" + ipHash, 3, 3600))) return err(429, "rate_limited", { "Retry-After": "3600" });
  if (!(await allow(env, "review:all", 300, 86400))) return err(429, "rate_limited", { "Retry-After": "3600" });

  const dup = await env.DB.prepare(
    "SELECT id FROM reviews WHERE ip_hash = ?1 AND original_text = ?2 AND created_at > datetime('now','-1 day')"
  )
    .bind(ipHash, text)
    .first();
  if (dup) return json({ ok: true });

  await env.DB.prepare(
    "INSERT INTO reviews (name, brand, email, service, rating, review_text, original_text, consent, status, ip_hash) VALUES (?1,?2,?3,?4,?5,?6,?6,?7,'pending',?8)"
  )
    .bind(name, brand || null, email || null, service || null, rating, text, b.consent === true ? 1 : 0, ipHash)
    .run();
  return json({ ok: true }, 201);
}

async function publicReviews(env) {
  const { results } = await env.DB.prepare(
    "SELECT name, brand, rating, review_text AS text, featured FROM reviews WHERE status = 'published' AND consent = 1 ORDER BY featured DESC, published_at DESC, id DESC LIMIT 50"
  ).all();
  return json({ ok: true, reviews: results }, 200, { "Cache-Control": "public, max-age=30" });
}

/* ---------- handlers: admin ---------- */
async function login(request, env) {
  const b = await readJson(request);
  const email = clean(b.email, 254).toLowerCase();
  const password = typeof b.password === "string" ? b.password.slice(0, 200) : "";
  // Three limits: per IP, per IP+email pair (5 tries), and a high per-email ceiling.
  // The low limit is per pair, so a stranger guessing from their own IP cannot lock the owner out.
  const tag = await ipTag(env, request, "login");
  const eh = (await sha256hex(email)).slice(0, 24);
  const okIp = await allow(env, "login:ip:" + tag, 20, 900);
  const okPair = await allow(env, `login:pair:${eh}:${tag}`, 5, 900);
  const okEmail = await allow(env, "login:email:" + eh, 60, 900);
  if (!okIp || !okPair || !okEmail) return err(429, "too_many_attempts", { "Retry-After": "900" });

  const user = await env.DB.prepare("SELECT id, password_hash, salt, must_change FROM admin_users WHERE email = ?1").bind(email).first();
  // Always run PBKDF2 so response time does not reveal whether the email exists.
  const salt = user ? user.salt : "AAAAAAAAAAAAAAAAAAAAAA==";
  const hash = await hashPassword(password, salt);
  if (!user || !safeEqual(hash, user.password_hash)) return err(401, "invalid_credentials");

  const token = await createSession(env, user.id);
  return json({ ok: true, mustChange: !!user.must_change }, 200, { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 86400) });
}

async function logout(request, env) {
  const token = getCookie(request, COOKIE);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE id = ?1").bind(await sha256hex(token)).run();
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
}

async function changePassword(request, env) {
  const admin = await requireAdmin(request, env, { allowMustChange: true });
  const b = await readJson(request);
  const cur = typeof b.current === "string" ? b.current : "";
  const next = typeof b.next === "string" ? b.next : "";
  if (next.length < 12 || next.length > 200) return json({ ok: false, error: "weak_password", message: "Use at least 12 characters." }, 422);
  const user = await env.DB.prepare("SELECT password_hash, salt FROM admin_users WHERE id = ?1").bind(admin.id).first();
  if (!safeEqual(await hashPassword(cur, user.salt), user.password_hash)) return err(401, "invalid_credentials");
  if (next === cur) return json({ ok: false, error: "same_password", message: "Choose a different password." }, 422);
  const salt = newSalt();
  await env.DB.prepare("UPDATE admin_users SET password_hash = ?1, salt = ?2, must_change = 0 WHERE id = ?3")
    .bind(await hashPassword(next, salt), salt, admin.id)
    .run();
  // sign out every other session
  await env.DB.prepare("DELETE FROM sessions WHERE admin_id = ?1 AND id != ?2").bind(admin.id, admin.sid).run();
  return json({ ok: true });
}

async function listReviews(request, env) {
  await requireAdmin(request, env);
  const url = new URL(request.url);
  const status = url.searchParams.get("status") || "";
  const rating = Number(url.searchParams.get("rating") || 0);
  const where = [];
  const args = [];
  if (["pending", "approved", "rejected", "published"].includes(status)) {
    args.push(status);
    where.push("status = ?" + args.length);
  }
  if (rating >= 1 && rating <= 5) {
    args.push(rating);
    where.push("rating = ?" + args.length);
  }
  const sql =
    "SELECT id, name, brand, email, service, rating, review_text, original_text, consent, status, featured, created_at, updated_at, published_at FROM reviews" +
    (where.length ? " WHERE " + where.join(" AND ") : "") +
    " ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, id DESC LIMIT 300";
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  const counts = { pending: 0, approved: 0, rejected: 0, published: 0 };
  const c = await env.DB.prepare("SELECT status, COUNT(*) AS n FROM reviews GROUP BY status").all();
  for (const r of c.results) counts[r.status] = r.n;
  return json({ ok: true, reviews: results, counts });
}

async function logAction(env, reviewId, action, oldV, newV, adminId) {
  await env.DB.prepare("INSERT INTO review_moderation_log (review_id, action, old_value, new_value, admin_id) VALUES (?1,?2,?3,?4,?5)")
    .bind(reviewId, action, oldV == null ? null : String(oldV), newV == null ? null : String(newV), adminId)
    .run();
}

async function reviewAction(request, env, id) {
  const admin = await requireAdmin(request, env);
  const b = await readJson(request);
  const r = await env.DB.prepare("SELECT * FROM reviews WHERE id = ?1").bind(id).first();
  if (!r) return err(404, "not_found");
  const a = String(b.action || "");
  const ts = nowSql();
  const set = (sql, ...args) => env.DB.prepare(sql).bind(...args).run();

  if (a === "approve") {
    if (!["pending", "rejected"].includes(r.status)) return err(409, "bad_state");
    await set("UPDATE reviews SET status='approved', updated_at=?1 WHERE id=?2", ts, id);
    await logAction(env, id, "approve", r.status, "approved", admin.id);
  } else if (a === "publish") {
    if (!["pending", "approved"].includes(r.status)) return err(409, "bad_state");
    if (!r.consent) return err(409, "no_consent");
    await set("UPDATE reviews SET status='published', published_at=?1, updated_at=?1 WHERE id=?2", ts, id);
    await logAction(env, id, "publish", r.status, "published", admin.id);
  } else if (a === "unpublish") {
    if (r.status !== "published") return err(409, "bad_state");
    await set("UPDATE reviews SET status='approved', featured=0, updated_at=?1 WHERE id=?2", ts, id);
    await logAction(env, id, "unpublish", "published", "approved", admin.id);
  } else if (a === "reject") {
    if (r.status === "rejected") return err(409, "bad_state");
    await set("UPDATE reviews SET status='rejected', featured=0, updated_at=?1 WHERE id=?2", ts, id);
    await logAction(env, id, "reject", r.status, "rejected", admin.id);
  } else if (a === "feature" || a === "unfeature") {
    if (a === "feature" && r.status !== "published") return err(409, "bad_state");
    await set("UPDATE reviews SET featured=?1, updated_at=?2 WHERE id=?3", a === "feature" ? 1 : 0, ts, id);
    await logAction(env, id, a, r.featured, a === "feature" ? 1 : 0, admin.id);
  } else if (a === "edit") {
    const text = clean(b.text, 1500);
    if (text.length < 10) return json({ ok: false, error: "validation", fields: { text: "Too short." } }, 422);
    await set("UPDATE reviews SET review_text=?1, updated_at=?2 WHERE id=?3", text, ts, id);
    await logAction(env, id, "edit", r.review_text, text, admin.id);
  } else {
    return err(400, "unknown_action");
  }
  const fresh = await env.DB.prepare("SELECT id, status, featured, review_text, published_at FROM reviews WHERE id = ?1").bind(id).first();
  return json({ ok: true, review: fresh });
}

async function deleteReview(request, env, id) {
  const admin = await requireAdmin(request, env);
  const r = await env.DB.prepare("SELECT * FROM reviews WHERE id = ?1").bind(id).first();
  if (!r) return err(404, "not_found");
  // keep a snapshot in the moderation log before removing
  await logAction(env, id, "delete", JSON.stringify(r), null, admin.id);
  await env.DB.prepare("DELETE FROM reviews WHERE id = ?1").bind(id).run();
  return json({ ok: true });
}

async function reviewLog(request, env, id) {
  await requireAdmin(request, env);
  const { results } = await env.DB.prepare(
    "SELECT action, old_value, new_value, admin_id, created_at FROM review_moderation_log WHERE review_id = ?1 AND action != 'delete' ORDER BY id DESC LIMIT 50"
  )
    .bind(id)
    .all();
  return json({ ok: true, log: results });
}

/* ---------- pages ---------- */
async function servePage(request, env, assetPath, { dashboard = false } = {}) {
  const url = new URL(request.url);
  const res = await env.ASSETS.fetch(new Request(url.origin + assetPath, { headers: request.headers }));
  if (!dashboard || !res.ok) return res;
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const html = (await res.text()).replaceAll("__NONCE__", nonce);
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      "X-Robots-Tag": "noindex, nofollow",
      ...SEC_HEADERS,
    },
  });
}

/* ---------- router ---------- */
export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(housekeeping(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path === "/admin" || path === "/admin/") return await servePage(request, env, "/dashboard", { dashboard: true });
      if (path === "/admin.html") return Response.redirect(url.origin + "/studio", 302);
      if (path === "/studio" || path === "/studio/") return await servePage(request, env, "/admin");
      if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

      // CSRF guard for state-changing requests: browsers always send Origin on cross-site POSTs.
      if (method !== "GET" && method !== "HEAD") {
        const origin = request.headers.get("Origin");
        if (origin && origin !== url.origin) return err(403, "bad_origin");
        const site = request.headers.get("Sec-Fetch-Site");
        if (site && !["same-origin", "none"].includes(site)) return err(403, "bad_origin");
      }

      if (path === "/api/reviews" && method === "POST") return await submitReview(request, env);
      if (path === "/api/reviews/public" && method === "GET") return await publicReviews(env);

      if (path === "/api/admin/login" && method === "POST") return await login(request, env);
      if (path === "/api/admin/logout" && method === "POST") return await logout(request, env);
      if (path === "/api/admin/password" && method === "POST") return await changePassword(request, env);
      if (path === "/api/admin/me" && method === "GET") {
        const a = await currentAdmin(request, env);
        return a ? json({ ok: true, email: a.email, mustChange: !!a.must_change }) : err(401, "unauthorized");
      }
      if (path === "/api/admin/reviews" && method === "GET") return await listReviews(request, env);

      const m = path.match(/^\/api\/admin\/reviews\/(\d+)(?:\/(action|log))?$/);
      if (m) {
        const id = Number(m[1]);
        if (m[2] === "action" && method === "POST") return await reviewAction(request, env, id);
        if (m[2] === "log" && method === "GET") return await reviewLog(request, env, id);
        if (!m[2] && method === "DELETE") return await deleteReview(request, env, id);
      }
      return err(404, "not_found");
    } catch (e) {
      if (e instanceof HttpError) return err(e.status, e.code);
      console.error("unhandled", e && e.message);
      return err(500, "server_error");
    }
  },
};
