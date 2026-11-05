import { dbUnavailable, json, validEmail, sha256, verifyPassword, randomHex, setSessionCookie, SESSION_SECONDS, sameOrigin, blogUrl } from "../../_shared/auth.js";

export async function onRequestPost({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  if (!sameOrigin(request)) return json({ error: "Origem da solicitação inválida." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Confira os dados informados." }, 400); }
  const email = String(body?.email || "").trim().toLowerCase();
  const password = body?.password;
  if (!validEmail(email) || typeof password !== "string" || password.length > 128) {
    return json({ error: "E-mail ou senha incorretos." }, 401);
  }

  const now = Math.floor(Date.now() / 1000);
  const limit = await env.DB.prepare("SELECT window_started, attempts, locked_until FROM login_limits WHERE email=?").bind(email).first();
  if (limit?.locked_until > now) return json({ error: "Muitas tentativas. Aguarde alguns minutos e tente novamente." }, 429);

  const user = await env.DB.prepare("SELECT id, email, blog_id, role, password_salt, password_hash FROM users WHERE email=? LIMIT 1").bind(email).first();
  const ok = !!user && await verifyPassword(password, user.password_salt, user.password_hash);
  if (!ok) {
    const windowStart = limit && now - limit.window_started < 900 ? limit.window_started : now;
    const attempts = (limit && windowStart === limit.window_started ? limit.attempts : 0) + 1;
    const lockedUntil = attempts >= 8 ? now + 900 : 0;
    await env.DB.prepare(
      "INSERT INTO login_limits(email,window_started,attempts,locked_until) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET window_started=excluded.window_started, attempts=excluded.attempts, locked_until=excluded.locked_until",
    ).bind(email, windowStart, attempts, lockedUntil).run();
    return json({ error: "E-mail ou senha incorretos." }, 401);
  }

  await env.DB.prepare("DELETE FROM login_limits WHERE email=?").bind(email).run();
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = now + SESSION_SECONDS;
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(tokenHash, user.id, expiresAt, now).run();
  return json({ user: { email: user.email, blogId: user.blog_id, role: user.role }, redirect: blogUrl(user.blog_id) }, 200, { "Set-Cookie": setSessionCookie(token) });
}
