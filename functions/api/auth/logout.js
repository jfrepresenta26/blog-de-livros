import { clearSessionCookie, cookieValue, dbUnavailable, json, sha256, sameOrigin } from "../../_shared/auth.js";

export async function onRequestPost({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  if (!sameOrigin(request)) return json({ error: "Origem da solicitação inválida." }, 403);
  const token = cookieValue(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
}
