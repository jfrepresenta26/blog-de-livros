export const SESSION_COOKIE = "blog_session";
export const SESSION_SECONDS = 60 * 60 * 24 * 7;

export function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}

export function dbUnavailable(env) {
  return !env?.DB
    ? json({ error: "O banco do blog ainda não está conectado no Cloudflare." }, 503)
    : null;
}

export function validEmail(email) {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function validPassword(password) {
  return typeof password === "string" && password.length >= 12 && password.length <= 128;
}

export function randomHex(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return [...data].map((n) => n.toString(16).padStart(2, "0")).join("");
}

export async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, "0")).join("");
}

export async function hashPassword(password, salt = randomHex(16)) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 310000, hash: "SHA-256" },
    key,
    256,
  );
  return { salt, hash: [...new Uint8Array(bits)].map((n) => n.toString(16).padStart(2, "0")).join("") };
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

export async function verifyPassword(password, salt, expected) {
  const actual = await hashPassword(password, salt);
  return constantTimeEqual(actual.hash, expected);
}

export function cookieValue(request, name = SESSION_COOKIE) {
  const all = request.headers.get("Cookie") || "";
  const entry = all.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : "";
}

export function setSessionCookie(token) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export async function currentUser(request, env) {
  if (!env?.DB) return null;
  const token = cookieValue(request);
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT u.id, u.email, u.blog_id, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? LIMIT 1",
  ).bind(tokenHash, now).first();
  return row || null;
}

export function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !!origin && origin === new URL(request.url).origin;
}

export function blogUrl(blogId) {
  return blogId === "debora" ? "https://blog-da-debora.pages.dev/" : "https://blog-de-livros.pages.dev/";
}
