import { dbUnavailable, json, validEmail, validPassword, hashPassword, randomHex, sameOrigin, setSessionCookie, SESSION_SECONDS, sha256 } from "../../_shared/auth.js";

export async function onRequestPost({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  if (!sameOrigin(request)) return json({ error: "Origem da solicitação inválida." }, 403);
  if (!env.BOOTSTRAP_CODE) return json({ error: "A configuração inicial ainda não foi habilitada no Cloudflare." }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Confira os dados informados." }, 400); }
  const email = String(body?.email || "").trim().toLowerCase();
  const password = body?.password;
  if (body?.code !== env.BOOTSTRAP_CODE) return json({ error: "Código inicial incorreto." }, 403);
  if (!validEmail(email) || !validPassword(password)) return json({ error: "Use um e-mail válido e uma senha com pelo menos 12 caracteres." }, 400);
  const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
  if (Number(count?.total || 0) !== 0) return json({ error: "A conta inicial já foi criada. Use a tela de entrada." }, 409);
  const { salt, hash } = await hashPassword(password);
  const id = randomHex(16);
  const now = Math.floor(Date.now() / 1000);
  const created = await env.DB.prepare(
    "INSERT INTO users(id,email,password_salt,password_hash,blog_id,role,created_at) SELECT ?,?,?,?,'gabriel','owner',? WHERE NOT EXISTS (SELECT 1 FROM users)",
  ).bind(id, email, salt, hash, now).run();
  if (!created.meta?.changes) return json({ error: "A configuração inicial já foi concluída." }, 409);
  const token = randomHex(32);
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha256(token), id, now + SESSION_SECONDS, now).run();
  return json({ user: { email, blogId: "gabriel", role: "owner" }, redirect: "https://blog-de-livros.pages.dev/" }, 201, { "Set-Cookie": setSessionCookie(token) });
}
